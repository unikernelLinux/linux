// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Upcall event handler implementaion for UKL
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/errno.h>
#include <linux/poll.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/rbtree.h>
#include <linux/wait.h>
#include <linux/eventpoll.h>
#include <linux/bitops.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <linux/atomic.h>
#include <linux/compat.h>
#include <linux/rculist.h>
#include <net/busy_poll.h>
#include <asm/mmu_context.h>
#include <linux/percpu-defs.h>
#include <linux/cpumask.h>
#include <linux/upcall.h>

#include <linux/tsc_logger.h>

#include <linux/sched.h>
#include <uapi/linux/sched/types.h>

struct upcall_filefd {
	struct file *file;
	__poll_t events;
	int fd;
} __packed;

/* Hold all the poll table infrastructure for a subscription */
struct sub_poll {
        wait_queue_entry_t wait;
        wait_queue_head_t *whead;
	/* Used to attach to work item queues when waiting for an execution context */
        struct list_head anchor;
	struct subscription *parent;
	poll_table pt;
};

struct subscription
{
	union {
		/* Used to organize all the subscriptions for a process in subscription_manager */
		struct rb_node rbn;
		/* In case we need to rely in RCU to free, this may be removed */
		struct rcu_head rcu;
	};

	/* The file descriptor and struct file * that this subscription is attached to */
	struct upcall_filefd fileinfo;

	/* The mananager that is responsible for this subscription */
	struct subscription_manager *mgr;

	/* We will start this at 1 and reclaim when the count reaches 0. To decrement to 0, we will
	 * insert a synthetic event that only decrements the ref count so that the last outstanding
	 * event will release the subscription.
	 */
	struct kref ref_count;

	/* The structure containing the work to be done in response to an event */
	struct work_item work;

	/* Hold all the wait table and poll info for this subscription */
	struct sub_poll *tables;
};

struct subscription_manager
{
	/*
	 * This lock is intended to serialize alterations to the collection of
	 * subscriptions. Insertions and deletions of subscriptions should be done
	 * holding it.
	 */
	struct mutex sub_mtx;

	/* RB Tree root for holding per file subscriptions */
	struct rb_root_cached rbr;
};

struct sub_event
{
	struct list_head work_item_head;
	struct subscription *sub;
};

struct event_handler
{
	struct list_head		tasks;
	spinlock_t			tasks_lock;
	struct list_head		work_item_head;
	spinlock_t			work_lock;
};

struct pcpu_handler
{
	struct event_handler *handler;
};

static DEFINE_PER_CPU(struct pcpu_handler, pcpu_upcall);

/* We should probably stash this in a file descriptor like epoll does but I
 * don't want to support nesting the way epoll does so we may need another option
 */
struct subscription_manager *ukl_subs;

/* Subscription cache */
static struct kmem_cache *sub_cache __read_mostly;

/* Poll table cache */
static struct kmem_cache *table_cache __read_mostly;

/* List head cache for file link */
static struct kmem_cache *uplist_cache __read_mostly;

/* Per event structure cache */
static struct kmem_cache *event_cache __read_mostly;

void ukl_worker_sleep(void)
{
	unsigned long flags;
	struct event_handler *handler;
	struct pcpu_handler *container;

	// This function is intended to be called from a user space thread that
	// was created to handle events. AFAICT this is the most efficient way
	// for a task to "sleep".

	//ukl_state_u2k();
	enter_ukl_kernel();

	local_irq_save(flags);
	container = this_cpu_ptr(&pcpu_upcall);
	handler = container->handler;

	// There are no events to handle at the moment, mark ourselves
	// idle and go to sleep

	spin_lock(&handler->tasks_lock);

	// However, we may have raced with the event notifications so double check
	// before we go to sleep
	spin_lock(&handler->work_lock);
	if (!list_empty(&handler->work_item_head)) {
		// We did race, let's go do the work
		spin_unlock(&handler->work_lock);
		spin_unlock(&handler->tasks_lock);
		local_irq_restore(flags);
		goto out;
	}

	spin_unlock(&handler->work_lock);

	// Okay, we really need to sleep.
	list_add_tail(&current->event_handlers, &handler->tasks);
	set_current_state(TASK_IDLE);
	// This barrier is paired with the one in upcall_handler() which will execute in
	// softIRQ context and attempt to wake a worker.
	smp_mb();
	spin_unlock(&handler->tasks_lock);
	local_irq_restore(flags);

	schedule();
out:
	enter_ukl_user();

	//ukl_state_k2u();
}

static struct event_handler *create_handler(void)
{
	struct event_handler *handler = kmalloc(sizeof(struct event_handler), GFP_ATOMIC);
	INIT_LIST_HEAD(&handler->tasks);
	INIT_LIST_HEAD(&handler->work_item_head);
	spin_lock_init(&handler->tasks_lock);
	spin_lock_init(&handler->work_lock);
	return handler;
}

#define UPCALL_PCPU	0
#define UPCALL_PCACHE	1
#define UPCALL_SINGLE	2
/*
 * Initialize the percpu event handler structures and prepare for execution
 * contexts to be registered.
 */
int init_upcall_handler(int concurrency_model)
{
	int i;
	int j;
	struct pcpu_handler *container;
	struct event_handler *mine;
	unsigned long flags;
	int queue_cnt = 0;

	ukl_subs = kzalloc(sizeof(struct subscription_manager), GFP_KERNEL);
	mutex_init(&ukl_subs->sub_mtx);

	switch(concurrency_model) {
	case UPCALL_PCPU:
		local_irq_save(flags);
		for_each_online_cpu(i) {
			container = per_cpu_ptr(&pcpu_upcall, i);
			container->handler = create_handler();
			queue_cnt++;
		}
		local_irq_restore(flags);
		break;
	case UPCALL_PCACHE:
		local_irq_save(flags);
		for_each_online_cpu(i) {
			container = per_cpu_ptr(&pcpu_upcall, i);
			if (container->handler) // We already have one set
				continue;
			mine = create_handler();
			queue_cnt++;
			container->handler = mine;
			for_each_cpu(j, topology_cluster_cpumask(i)) {
				if (i == j)
					continue;
				container = per_cpu_ptr(&pcpu_upcall, j);
				container->handler = mine;
			}
		}
		local_irq_restore(flags);
		break;
	case UPCALL_SINGLE:
		mine = create_handler();
		queue_cnt++;
		local_irq_save(flags);
		for_each_online_cpu(i) {
			container = per_cpu_ptr(&pcpu_upcall, i);
			container->handler = mine;
		}
		local_irq_restore(flags);
		break;
	}
	return queue_cnt;
}

/*
 * Take the calling task (which should be a thread for the application using
 * upcalls) and make it the event handler for the specified CPU. We will pin
 * it to the specified CPU in user space (the API for pinning is simpler there)
 */
void register_ukl_handler_task(void)
{
	enter_ukl_kernel();

	// Unfortunately, there really isn't a better place to do this. Finding a better
	// location would allow us to delete this function.
	INIT_LIST_HEAD(&current->event_handlers);

	enter_ukl_user();
}

static void cleanup_file(struct subscription *sub)
{
	struct file *file = NULL;
	struct list_head *to_free = NULL;
	struct list_head *head;

	/* Unhook from the file, if we are still connected */
	if ((file = smp_load_acquire(&sub->fileinfo.file))) {
		spin_lock(&file->f_lock);
		head = file->f_upcall;
		if (head->next == &sub->tables->anchor && sub->tables->anchor.next == head) {
			to_free = head;
			file->f_upcall = NULL;
		}
		list_del_rcu(&sub->tables->anchor);
		smp_store_release(&sub->fileinfo.file, NULL);
		spin_unlock(&file->f_lock);
	}

	if (to_free) {
		kmem_cache_free(uplist_cache, to_free);
	}
}

static void unhook_waiters(struct sub_poll *tables)
{
	wait_queue_head_t *whead;

	rcu_read_lock();
	whead = smp_load_acquire(&tables->whead);
	if (whead) {
		remove_wait_queue(whead, &tables->wait);
		smp_store_release(&tables->whead, NULL);
	}
	rcu_read_unlock();
}

static void sub_rcu_free(struct rcu_head *rcu)
{
	struct subscription *sub = container_of(rcu, struct subscription, rcu);
	struct sub_poll *tables = sub->tables;

	kmem_cache_free(table_cache, tables);
	kmem_cache_free(sub_cache, sub);
}

/* Cleanup a subscription structure when there are no outstanding references. */
static void subscription_release(struct kref *ref)
{
	struct subscription *sub = container_of(ref, struct subscription, ref_count);
	struct subscription_manager *mgr = sub->mgr;
	struct sub_poll *tables = sub->tables;

	/* Remove us from the overall RB tree */
	mutex_lock(&mgr->sub_mtx);
	rb_erase_cached(&sub->rbn, &mgr->rbr);

	unhook_waiters(tables);
	cleanup_file(sub);
	mutex_unlock(&mgr->sub_mtx);

	/* Now tell RCU to free everything when we are sure it's safe */
	call_rcu(&sub->rcu, sub_rcu_free);
}


void event_work_done(struct work_item *work)
{
	struct subscription *sub = container_of(work, struct subscription, work);
	kref_put(&sub->ref_count, subscription_release);
}

// Return the opaque pointer supplied when this event was registered and re-enable
// the event waiter
struct work_item* workitem_queue_consume_event(void)
{
	struct work_item *ret = NULL;
	unsigned long flags;
	struct sub_event *event;
	struct pcpu_handler *container;
	struct event_handler *handler;

	enter_ukl_kernel();

	local_irq_save(flags);
	container = this_cpu_ptr(&pcpu_upcall);
	handler = container->handler;
	spin_lock(&handler->work_lock);
	// This barrier is paired with one in workitem_queue_add_event(), this barrier ensures
	// the worker thread sees the new work items.
	smp_mb();
	event = list_first_entry_or_null(&handler->work_item_head, struct sub_event,
			work_item_head);
	if (event) {
		list_del_init(&event->work_item_head);
		ret = &event->sub->work;
	}

	spin_unlock_irqrestore(&handler->work_lock, flags);

	if (event) {
		kmem_cache_free(event_cache, event);
	}

	enter_ukl_user();
	return ret;
}

/* Caller is expected to have disabled interrupts */
static void workitem_queue_add_event(struct event_handler *handler, struct sub_event *event)
{
	spin_lock(&handler->work_lock);
	list_add_tail(&event->work_item_head, &handler->work_item_head);
	spin_unlock(&handler->work_lock);
	// This barrier is paired with the one in workitem_queue_consume_event()
	smp_mb();
}

void enqueue_event(struct subscription *sub)
{
	unsigned long flags;
	struct event_handler *handler;
	struct pcpu_handler *container;
	struct sub_event *event;
	struct task_struct *thread = NULL;

	event = kmem_cache_zalloc(event_cache, GFP_ATOMIC);
	if (!event) {
		pr_err("Can't allocate event structure, dropping event\n");
		return;
	}

	INIT_LIST_HEAD(&event->work_item_head);

	local_irq_save(flags);
	container = this_cpu_ptr(&pcpu_upcall);
	handler = container->handler;

	if (!handler) {
		pr_err("Can't read pcpu handler pointer\n");
		kmem_cache_free(event_cache, event);
		local_irq_restore(flags);
		return;
	}

	kref_get(&sub->ref_count);
	event->sub = sub;

	workitem_queue_add_event(handler, event);

	spin_lock(&handler->tasks_lock);
	// This barrier is paired with the one in the worker_sleep() function
	smp_mb();

	thread = list_first_entry_or_null(&handler->tasks, struct task_struct,
			event_handlers);
	if (thread) {
		list_del_init(&thread->event_handlers);
		wake_up_process(thread);
	}

	spin_unlock_irqrestore(&handler->tasks_lock, flags);
}

int handle_event_source(struct wait_queue_entry *wq_entry, unsigned mode,
			int flags, void *key)
{
	struct sub_poll *tables = container_of(wq_entry, struct sub_poll, wait);
	__poll_t pollflags = key_to_poll(key);

	/* Check if we got events in key and if we are watching for them */
	if (pollflags && !(pollflags & tables->parent->fileinfo.events)) {
		return 0;
	}

	/*
	 * We have an event that we care about, we need to increment the subscription
	 * reference count and then enqueue the work function for a worker thread.
	 * If we can disarm the event and have the worker rearm it after handling,
	 * do that too.
	 */
        enqueue_event(tables->parent);

        return 0;
}

static inline void setup_filefd(struct upcall_filefd *ffd, struct file *file, int fd, __poll_t events)
{
	ffd->file = file;
	ffd->events = events;
	ffd->fd = fd;
}

/* Used for RB tree management */
static inline int upcall_cmp(struct upcall_filefd *l, struct upcall_filefd *r)
{
	if (l->file > r->file)
		return +1;
	if (l->file < r->file)
		return -1;
	if (l->fd != r->fd)
		return l->fd - r->fd;
	return l->events - r->events;
}

/*
 * Retrieve the subscription structure from the RB tree given a fd and file*.
 * Callers must hold mgr->sub_mtx.
 * Note: we do not alter the refcount_t value here so the caller must do that before releasing
 * the mutex to ensure that the pointer remains valid.
 */
static inline struct subscription *lookup_sub(struct subscription_manager *mgr, int fd, struct file *file, __poll_t events)
{
	int cmp;
	struct rb_node *rbp;
	struct subscription *node, *ret = NULL;
	struct upcall_filefd ffd;

	// Ensure we account for EPOLLERR
	events |= EPOLLERR;

	setup_filefd(&ffd, file, fd, events);
	for (rbp = mgr->rbr.rb_root.rb_node; rbp; ) {
		node = rb_entry(rbp, struct subscription, rbn);
		cmp = upcall_cmp(&ffd, &node->fileinfo);
		if (cmp > 0)
			rbp = rbp->rb_right;
		else if (cmp < 0)
			rbp = rbp->rb_left;
		else {
			ret = node;
			break;
		}
	}

	return ret;
}

static void sub_rbtree_insert(struct subscription_manager *mgr, struct subscription *sub)
{
	int cmp;
	struct rb_node **p = &mgr->rbr.rb_root.rb_node, *parent = NULL;
	struct subscription *node;
	bool leftmost = true;

	while (*p) {
		parent = *p;
		node = rb_entry(parent, struct subscription, rbn);
		cmp = upcall_cmp(&sub->fileinfo, &node->fileinfo);
		if (cmp > 0) {
			p = &parent->rb_right;
			leftmost = false;
		} else
			p = &parent->rb_left;
	}
	rb_link_node(&sub->rbn, parent, p);
	rb_insert_color_cached(&sub->rbn, &mgr->rbr, leftmost);
}

static void upcall_ptable_queue_proc(struct file *file, wait_queue_head_t *whead, poll_table *pt)
{
	struct sub_poll *table = container_of(pt, struct sub_poll, pt);

	init_waitqueue_func_entry(&table->wait, handle_event_source);
	table->whead = whead;
	add_wait_queue(whead, &table->wait);
}

static __poll_t upcall_item_poll(struct subscription *sub)
{
	struct file *file = sub->fileinfo.file;
	poll_table *pt = &sub->tables->pt;
	__poll_t res;

	pt->_key = sub->fileinfo.events;
	res = vfs_poll(file, pt);

	return res & sub->fileinfo.events;
}

static int create_subscription(struct subscription_manager *mgr, int fd, struct file *file, __poll_t events,
				void(work_fn)(void*), void *arg)
{
	struct subscription *sub;
	struct list_head *to_free = NULL;

	lockdep_assert_irqs_enabled();

	if (!(sub = kmem_cache_zalloc(sub_cache, GFP_KERNEL)))
		return -ENOMEM;

	if (!(sub->tables = kmem_cache_zalloc(table_cache, GFP_KERNEL))) {
		kmem_cache_free(sub_cache, sub);
		return -ENOMEM;
	}

	/* We add EPOLLERR to all events */
	events |= EPOLLERR;
	sub->work.work_fn = work_fn;
	sub->work.arg = arg;
	setup_filefd(&sub->fileinfo, file, fd, events);
	sub->mgr = mgr;
	kref_init(&sub->ref_count);

	// Init tables
	INIT_LIST_HEAD(&sub->tables->anchor);
	sub->tables->parent = sub;

	if (!READ_ONCE(file->f_upcall)) {
		if (!(to_free = kmem_cache_zalloc(uplist_cache, GFP_KERNEL))) {
			kmem_cache_free(table_cache, sub->tables);
			kmem_cache_free(sub_cache, sub);
			return -ENOMEM;
		}
		INIT_LIST_HEAD(to_free);
	}

	spin_lock(&file->f_lock);
	if (!file->f_upcall) {
		file->f_upcall = to_free;
		to_free = NULL;
	}
	list_add_rcu(&sub->tables->anchor, file->f_upcall);
	spin_unlock(&file->f_lock);

	if (to_free) {
		kmem_cache_free(uplist_cache, to_free);
	}

	sub_rbtree_insert(mgr, sub);

	// Setup the poll table waiters
	init_poll_funcptr(&sub->tables->pt, upcall_ptable_queue_proc);

	if(upcall_item_poll(sub)) {
		// There were events present already, enqueue them
		enqueue_event(sub);
	}

	return 0;
}

int register_subscription(struct subscription_manager *mgr, int fd, __poll_t events,
			void(work_fn)(void*), void *arg)
{
	int err;
	struct fd desc;
	struct subscription *sub;

	enter_ukl_kernel();

	desc = fdget(fd);
	if (!desc.file) {
		err = -EBADF;
		goto err_ret;
	}

	if (!file_can_poll(desc.file)) {
		err = -EPERM;
		goto desc_put;
	}

	mutex_lock(&mgr->sub_mtx);

	sub = lookup_sub(mgr, fd, desc.file, events);

	if (sub) {
		err = -EEXIST;
		goto unlock_out;
	}

	err = create_subscription(mgr, fd, desc.file, events, work_fn, arg);

unlock_out:
	mutex_unlock(&mgr->sub_mtx);
desc_put:
	fdput(desc);
err_ret:
	enter_ukl_user();
	return err;
}

int remove_subscription(struct subscription_manager *mgr, int fd, __poll_t events)
{
	int err;
	struct fd desc;
	struct subscription *sub;

	enter_ukl_kernel();

	desc = fdget(fd);
	if (!desc.file) {
		err = -EBADF;
		goto err_ret;
	}

	mutex_lock(&mgr->sub_mtx);

	sub = lookup_sub(mgr, fd, desc.file, events | EPOLLERR);

	if (!sub) {
		err = -EEXIST;
		goto out_put_unlock;
	}

	if ((sub->fileinfo.events & (events | EPOLLERR)) != (events | EPOLLERR)) {
		err = -EEXIST;
		goto out_put_unlock;
	}

	/*
	 * When removing a subscription from an existing file, we only want to
	 * remove the ability to trigger new events without removing information
	 * needed to handle the existing events. If this is the last outstanding
	 * reference to the subscription, the file bits will be cleaned when we
	 * release the reference below.
	 */
	unhook_waiters(sub->tables);
	cleanup_file(sub);

	mutex_unlock(&mgr->sub_mtx);
	fdput(desc);

	kref_put(&sub->ref_count, subscription_release);
	
	enter_ukl_user();
	return 0;

out_put_unlock:
	mutex_unlock(&mgr->sub_mtx);
	fdput(desc);
err_ret:
	enter_ukl_user();
	return err;
}

void upcall_release_file(struct file *file)
{
	struct subscription *sub;
	struct sub_poll *tables, *n;

	if (unlikely(!file->f_upcall))
		return;

	list_for_each_entry_safe(tables, n, file->f_upcall, anchor) {
		unhook_waiters(tables);
		sub = tables->parent;
		kref_put(&sub->ref_count, subscription_release);
	}
}

static int __init upcall_init(void)
{
	sub_cache = kmem_cache_create("upcall_sub", sizeof(struct subscription),
			0, SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);
	table_cache = kmem_cache_create("upcall_work", sizeof(struct sub_poll),
			0, SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);
	uplist_cache = kmem_cache_create("upcall_head", sizeof(struct list_head),
			0, SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);
	event_cache = kmem_cache_create("upcall_event", sizeof(struct sub_event),
			0, SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);
	return 0;
}
fs_initcall(upcall_init);


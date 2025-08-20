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
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <linux/atomic.h>
#include <linux/compat.h>
#include <linux/rculist.h>
#include <net/busy_poll.h>
#include <asm/mmu_context.h>
#include <linux/percpu-defs.h>
#include <linux/cpumask.h>
#include <linux/anon_inodes.h>
#include <linux/upcall.h>

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

struct sub_event
{
	struct list_head work_item_head;
	struct subscription *sub;
};

/* The event_handler structure now needs to be attached to the subscription_manager
 * which, in turn, will be attached to the inode info that is indexed by our file
 * descriptor
 */
struct event_handler
{
	struct list_head		tasks;
	spinlock_t			tasks_lock;
	struct list_head		work_item_head;
	spinlock_t			work_lock;
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

	struct kref ref_count;

	struct file *file;

	/* The number of work queues created when initializing this manager */
	uint64_t queue_cnt;

	/* Per CPU event queues */
	struct event_handler * handlers[NR_CPUS];
};

/* Subscription cache */
static struct kmem_cache *sub_cache __read_mostly;

/* Poll table cache */
static struct kmem_cache *table_cache __read_mostly;

/* List head cache for file link */
static struct kmem_cache *uplist_cache __read_mostly;

/* Per event structure cache */
static struct kmem_cache *event_cache __read_mostly;

static const struct file_operations upcall_fops;

static inline int is_file_upcall(struct file *f)
{
	return f->f_op == &upcall_fops;
}

static void upcall_worker_sleep(struct subscription_manager *mgr)
{
	unsigned long flags;
	struct event_handler *handler;

	// This function is intended to be called from the upcall_wait syscall.
	// AFAICT this is the most efficient way for a task to "sleep".

	local_irq_save(flags);
	handler = mgr->handlers[smp_processor_id()];

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
	return;
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

/*
 * Initialize the percpu event handler structures and prepare for execution
 * contexts to be registered.
 */
static struct subscription_manager *create_upcall_handler(int flags)
{
	int i;
	int j;
	struct event_handler *mine;
	unsigned long itr_flags;
	struct subscription_manager *mgr = NULL;
	int concurrency_model = flags & UPCALL_MODEL_MASK;

	mgr = kzalloc(sizeof(struct subscription_manager), GFP_KERNEL);
	if (!mgr) {
		return mgr;
	}
	mutex_init(&mgr->sub_mtx);


	local_irq_save(itr_flags);
	switch(concurrency_model) {
	case UPCALL_PCPU:
		for_each_online_cpu(i) {
			mgr->handlers[i] = create_handler();
			mgr->queue_cnt++;
		}
		break;
	case UPCALL_PCACHE:
		for_each_online_cpu(i) {
			if (mgr->handlers[i]) // We already have one set
				continue;
			mine = create_handler();
			mgr->queue_cnt++;
			mgr->handlers[i] = mine;
			for_each_cpu(j, topology_cluster_cpumask(i)) {
				if (i == j)
					continue;
				mgr->handlers[i] = mine;
			}
		}
		break;
	case UPCALL_SINGLE:
		mine = create_handler();
		mgr->queue_cnt++;
		for_each_online_cpu(i) {
			mgr->handlers[i] = mine;
		}
		break;
	}

	local_irq_restore(itr_flags);
	return mgr;
}

/*
 * Take the calling task (which should be a thread for the application using
 * upcalls) and make it the event handler for the specified CPU. We will pin
 * it to the specified CPU in user space (the API for pinning is simpler there)
 */
static void register_upcall_handler_task(void)
{
	// Unfortunately, there really isn't a better place to do this. Finding a better
	// location would allow us to delete this function.
	INIT_LIST_HEAD(&current->event_handlers);
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

// Return the opaque pointer supplied when this event was registered and re-enable
// the event waiter
static struct subscription* workitem_queue_consume_event(struct subscription_manager *mgr)
{
	struct subscription *ret = NULL;
	unsigned long flags;
	struct sub_event *event;
	struct event_handler *handler;

	local_irq_save(flags);
	handler = mgr->handlers[smp_processor_id()];
	spin_lock(&handler->work_lock);
	// This barrier is paired with one in workitem_queue_add_event(), this barrier ensures
	// the worker thread sees the new work items.
	smp_mb();
	event = list_first_entry_or_null(&handler->work_item_head, struct sub_event,
			work_item_head);
	if (event) {
		list_del_init(&event->work_item_head);
		ret = event->sub;
	}

	spin_unlock_irqrestore(&handler->work_lock, flags);

	if (event) {
		kmem_cache_free(event_cache, event);
	}

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

static void enqueue_event(struct subscription *sub)
{
	unsigned long flags;
	struct event_handler *handler;
	struct sub_event *event;
	struct task_struct *thread = NULL;
	struct subscription_manager *mgr = sub->mgr;

	event = kmem_cache_zalloc(event_cache, GFP_ATOMIC);
	if (!event) {
		pr_err("Can't allocate event structure, dropping event.\n");
		return;
	}

	INIT_LIST_HEAD(&event->work_item_head);

	local_irq_save(flags);
	handler = mgr->handlers[smp_processor_id()];

	if (!handler) {
		pr_err("Trying to use unintialized event queue, dropping event.\n");
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

static int handle_event_source(struct wait_queue_entry *wq_entry, unsigned mode,
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

	// Ensure we account for UPCALLERR
	events |= UPCALLERR;

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

	/* We add UPCALLERR to all events */
	events |= UPCALLERR;
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

static int register_subscription(struct subscription_manager *mgr, int fd, struct file *file,
				__poll_t events, void(work_fn)(void*), void *arg)
{
	int err;
	struct subscription *sub;

	mutex_lock(&mgr->sub_mtx);

	sub = lookup_sub(mgr, fd, file, events);

	if (sub) {
		err = -EEXIST;
		goto unlock_out;
	}

	err = create_subscription(mgr, fd, file, events, work_fn, arg);

unlock_out:
	mutex_unlock(&mgr->sub_mtx);
	return err;
}

static int remove_subscription(struct subscription_manager *mgr, int fd,
				struct file *file, __poll_t events)
{
	int err;
	struct subscription *sub;

	mutex_lock(&mgr->sub_mtx);

	sub = lookup_sub(mgr, fd, file, events | UPCALLERR);

	if (!sub) {
		err = -EEXIST;
		goto out_unlock;
	}

	if ((sub->fileinfo.events & (events | UPCALLERR)) != (events | UPCALLERR)) {
		err = -EEXIST;
		goto out_unlock;
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

	kref_put(&sub->ref_count, subscription_release);
	
	return 0;

out_unlock:
	mutex_unlock(&mgr->sub_mtx);
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

static void free_manager(struct subscription_manager *mgr)
{
	uint64_t i;
	/* When we get here we have no remaining subscriptions and no outstanding
	   events so we can safely delete our queues */
	mutex_lock(&mgr->sub_mtx);
	for (i = 0; i < NR_CPUS; i++) {
		if (mgr->handlers[i]) {
			kfree(mgr->handlers[i]);
			mgr->handlers[i] = NULL;
		}
	}
	mutex_unlock(&mgr->sub_mtx);
	kfree(mgr);
}

static void free_manager_kref(struct kref *kref)
{
	struct subscription_manager *mgr = container_of(kref, struct subscription_manager, ref_count);
	free_manager(mgr);
}

static int upcall_tear_down(struct inode *indoe, struct file *file)
{
	struct subscription_manager *mgr = file->private_data;

	if (mgr) {
		// TODO, clearout and unhook any live subscriptions
		kref_put(&mgr->ref_count, free_manager_kref);
	}
	return 0;
}


#ifdef CONFIG_PROC_FS
static void upcall_show_fdinfo(struct seq_file *m, struct file *f)
{
	struct subscription_manager *mgr = f->private_data;
	struct rb_node *rbp;

	mutex_lock(&mgr->sub_mtx);
	for (rbp = rb_first_cached(&mgr->rbr); rbp; rbp = rb_next(rbp)) {
		struct subscription *sub = rb_entry(rbp, struct subscription, rbn);
		struct inode *inode = file_inode(sub->fileinfo.file);
		seq_printf(m, "tfd: %8d events: %8x pos: %16llx ino: %lx sdev: %x\n",
				sub->fileinfo.fd, sub->fileinfo.events,
				sub->fileinfo.file->f_pos, inode->i_ino,
				inode->i_sb->s_dev);
		if (seq_has_overflowed(m))
			break;
	}
	mutex_unlock(&mgr->sub_mtx);
}
#endif

static long upcall_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct subscription_manager *mgr = file->private_data;
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case UPIOGQCNT:
		if (copy_to_user(uarg, &mgr->queue_cnt, sizeof(uint64_t)))
			return -EFAULT;
		return 0;
	case UPIOSTSK:
		register_upcall_handler_task();
		return 0;
	default:
		return -ENOIOCTLCMD;
	}
}

static const struct file_operations upcall_fops = {
#ifdef CONFIG_PROC_FS
	.show_fdinfo		= upcall_show_fdinfo,
#endif
	.release		= upcall_tear_down,
	.llseek			= noop_llseek,
	.unlocked_ioctl		= upcall_ioctl,
};

SYSCALL_DEFINE2(upcall_wait, int, upfd, struct work_item __user *, item)
{
	struct subscription *sub = NULL;
	struct subscription_manager *mgr;

	CLASS(fd, f)(upfd);
	if (fd_empty(f))
		return -EBADF;

	if(!is_file_upcall(fd_file(f)))
		return -EBADF;

	mgr = fd_file(f)->private_data;

	while (NULL == (sub = workitem_queue_consume_event(mgr))) {
		upcall_worker_sleep(mgr);
	}

	if (copy_to_user(item, &sub->work, sizeof(struct work_item)))
		return -EFAULT;
	kref_put(&sub->ref_count, subscription_release);

	return 0;
}

SYSCALL_DEFINE5(upcall_ctl, int, upfd, int, op, int, fd,
		__poll_t, events, struct work_item __user *, action)
{
	int ret = -EINVAL;
	struct subscription_manager *mgr;
	struct work_item work;

	CLASS(fd, f)(upfd);
	if (fd_empty(f))
		return -EBADF;

	CLASS(fd, tf)(fd);
	if (fd_empty(tf))
		return -EBADF;

	if (is_file_upcall(fd_file(tf)))
		return -EINVAL;

	if(!is_file_upcall(fd_file(f)))
		return -EINVAL;

	mgr = fd_file(f)->private_data;

	if (op == UPCALL_ADD) {
		if (!file_can_poll(fd_file(tf)))
			return -EPERM;

		if (copy_from_user(&work, action, sizeof(struct work_item)))
			return -EFAULT;
		ret = register_subscription(mgr, fd, fd_file(tf), events, work.work_fn, work.arg);
	} else if (op == UPCALL_DEL) {
		ret = remove_subscription(mgr, fd, fd_file(tf), events);
	}

	return ret;
}

SYSCALL_DEFINE1(upcall_create, int, flags)
{
	int fd, error = 0;
	struct subscription_manager *manager;
	struct file *file;

	if (flags & ~UPCALL_MASK)
		return -EINVAL;

	manager = create_upcall_handler(flags);
	if (!manager)
		return -ENOMEM;

	fd = get_unused_fd_flags(O_RDWR | (flags & O_CLOEXEC));
	if (fd < 0) {
		error = fd;
		goto out_free;
	}

	file = anon_inode_getfile("[upcall]", &upcall_fops, manager,
			O_RDWR | (flags & O_CLOEXEC));
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		goto out_put_fd;
	}

	manager->file = file;
	fd_install(fd, file);
	return fd;

out_put_fd:
	put_unused_fd(fd);
out_free:
	free_manager(manager);
	return error;
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


// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Upcall event handler implementaion
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/errno.h>
#include <linux/poll.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/rbtree.h>
#include <linux/wait.h>
#include <linux/kref.h>
#include <linux/eventpoll.h>
#include <linux/bitops.h>
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/rculist.h>
#include <linux/percpu-defs.h>
#include <linux/cpumask.h>
#include <linux/anon_inodes.h>
#include <linux/upcall.h>

#include <linux/sched.h>

struct event_channel {
	struct list_head	wakeups;
	spinlock_t		wakeup_lock;
	struct list_head	sleeping_workers;
	spinlock_t		worker_lock;
};

struct event_manager {
	struct file		*file;
	struct kref ref_count;
	/* Number of channels created during initialization */
	uint64_t		queue_cnt;
	/* Per CPU event channels */
	struct event_channel	*channels[NR_CPUS];
};

struct event_anchor {
	struct list_head	anchor;
	struct up_event		*event;
	struct event_manager	*mgr;
	wait_queue_entry_t	wait;
	wait_queue_head_t	*whead;
	poll_table		pt;
	__poll_t		events;
	atomic_t		armed;
};

/* up_event cache */
static struct kmem_cache *event_cache __read_mostly;

/* Anchor cache */
static struct kmem_cache *anchor_cache __read_mostly;

static void free_manager_kref(struct kref *kref);

static inline void put_mgr(struct event_manager *mgr)
{
	kref_put(&mgr->ref_count, free_manager_kref);
}

/* Callers are expected to have disabled IRQs */
static inline struct event_channel *get_event_channel(struct event_manager *mgr)
{
	return mgr->channels[smp_processor_id()];
}

static void post_event(struct event_anchor *anchor)
{
	unsigned long flags;
	struct task_struct *thread;
	struct event_channel *channel;

	/* Now, we add this to the wakeup list for this CPU and potentially wake a
	   waiting thread to process */
	local_irq_save(flags);
	channel = get_event_channel(anchor->mgr);
	INIT_LIST_HEAD(&anchor->anchor);
	scoped_guard(spinlock, &channel->wakeup_lock) {
		list_add_tail(&anchor->anchor, &channel->wakeups);
	}

	scoped_guard(spinlock, &channel->worker_lock) {
		thread = list_first_entry_or_null(&channel->sleeping_workers,
				struct task_struct, event_handlers);
		if (thread) {
			list_del_init(&thread->event_handlers);
			wake_up_state(thread, TASK_NORMAL | TASK_IDLE);
		}
	}

	local_irq_restore(flags);
}

static int handle_poll_event(struct wait_queue_entry *wq_entry, unsigned mode,
		int flags, void *key)
{
	struct event_anchor *anchor = container_of(wq_entry, struct event_anchor, wait);
	__poll_t pollflags = key_to_poll(key);
	int armed;
	
	/* Check if this is an event we are waiting for */
	if (pollflags && !(pollflags & anchor->events))
		return 0;

	/* Take ownership of this anchor */
	armed = atomic_dec_return(&anchor->armed);
	if (armed) {
		/* We raced with another wake up, and they won */
		return 0;
	}

	post_event(anchor);
	return 0;
}


static void upcall_poll_init(struct file *file, wait_queue_head_t *whead, poll_table *pt)
{
	struct event_anchor *anchor = container_of(pt, struct event_anchor, pt);
	init_waitqueue_func_entry(&anchor->wait, handle_poll_event);
	anchor->whead = whead;
	add_wait_queue(whead, &anchor->wait);
}

static inline int try_read(struct up_event *evt)
{
	struct file *file;
	struct kiocb kiocb;
	struct iov_iter iter;
	int ret;
	CLASS(fd_pos, f)(evt->fd);

	if (fd_empty(f)) {
		evt->result = -EBADF;
		return 1;
	}

	file = fd_file(f);
	init_sync_kiocb(&kiocb, file);

	iov_iter_ubuf(&iter, ITER_DEST, evt->buf, evt->len);

	ret = file->f_op->read_iter(&kiocb, &iter);

	if (ret == -EAGAIN || ret == -EWOULDBLOCK)
		return 0;

	evt->result = ret;
	return 1;
}

static __poll_t upcall_item_poll(struct event_anchor *anchor, __poll_t events)
{
	struct file *file = fget(anchor->event->fd);
	poll_table *pt = &anchor->pt;
	__poll_t res;

	anchor->events = pt->_key = events;
	res = vfs_poll(file, pt);

	fput(file);

	return res & events;
}

static struct event_anchor *get_next_wakeup(struct event_manager *mgr)
{
	unsigned long flags;
	struct event_channel *channel;
	struct event_anchor *anchor;

	local_irq_save(flags);
	channel = get_event_channel(mgr);
	scoped_guard(spinlock, &channel->wakeup_lock) {
		anchor = list_first_entry_or_null(&channel->wakeups, struct event_anchor, anchor);
		if (!anchor)
			goto out;
		list_del_init(&anchor->anchor);
	}
out:
	local_irq_restore(flags);
	return anchor;
}

static void worker_sleep(struct event_manager *mgr)
{
	unsigned long flags;
	struct event_channel *channel;

	local_irq_save(flags);
	channel = get_event_channel(mgr);
	// There are no events to handle at the moment, mark ourselves
	// idle and go to sleep
	
	spin_lock(&channel->worker_lock);
	// However, we may have raced with the event notifications so double check
	// before we go to sleep
	spin_lock(&channel->wakeup_lock);
	if (!list_empty(&channel->wakeups)) {
		// We did race, go do the work
		spin_unlock(&channel->wakeup_lock);
		spin_unlock(&channel->worker_lock);
		local_irq_restore(flags);
		goto out;
	}
	spin_unlock(&channel->wakeup_lock);

	// Okay, we really need to sleep.
	list_add(&current->event_handlers, &channel->sleeping_workers);
	set_current_state(TASK_IDLE);
	spin_unlock(&channel->worker_lock);
	local_irq_restore(flags);

	schedule();
out:
	return;
}

static int do_upcall_submit(struct event_manager *mgr, int in_cnt, struct up_event **in, int out_cnt, struct up_event **out)
{
	int out_idx = 0;
	struct event_anchor *anchor;
	int armed;
	struct wait_queue_head *head;

	INIT_LIST_HEAD(&current->event_handlers);

	// Try all the submissions for I/O now
	for (int i = 0; i < in_cnt; i++) {
		// If we don't have a results buffer, this is either a poll notification or
		// something like accept, we will use the vfs_poll interface later to check
		// readability before returning.
		if (in[i]->buf != NULL && in[i]->len != 0 &&
				out_idx < out_cnt && try_read(in[i])) {
			out[out_idx] = in[i];
			out_idx++;
		} else {
			anchor = kmem_cache_alloc(anchor_cache, GFP_KERNEL);
			if (!anchor) {
				// Not sure what to do here, needs thinking
				return -ENOMEM;
			}
			anchor->event = in[i];
			INIT_LIST_HEAD(&anchor->anchor);
			INIT_LIST_HEAD(&anchor->wait.entry);
			anchor->mgr = mgr;
			kref_get(&mgr->ref_count);
			atomic_set(&anchor->armed, 1);
			init_poll_funcptr(&anchor->pt, upcall_poll_init);
			if (upcall_item_poll(anchor, EPOLLIN | EPOLLERR | EPOLLHUP)) {
				/* There was data waiting, check if we are still armed
				and remove the poll linkage if we are */
				armed = atomic_dec_return(&anchor->armed);
				if (!armed) {
					post_event(anchor);
				}
			}
		}
		in[i] = NULL;
	}

	if (out_idx == out_cnt)
		goto out;
	cond_resched();

again:
	// Now we need to check wakeups
	while (out_idx < out_cnt) {
		anchor = get_next_wakeup(mgr);
		if (!anchor)
			break;

		/* We found one we care about, unhook the waiter */
		rcu_read_lock();
		head = smp_load_acquire(&anchor->whead);
		if (head) {
			remove_wait_queue(head, &anchor->wait);
		}
		rcu_read_unlock();

		if (anchor->event->buf != NULL && anchor->event->len != 0) {
			try_read(anchor->event);
		}
		out[out_idx] = anchor->event;
		out_idx++;
		put_mgr(mgr);
		kmem_cache_free(anchor_cache, anchor);
	}

	// Finally, if we have no active wakeups and no output, we need to sleep here and try again.
	if (!out_idx) {
		worker_sleep(mgr);
		goto again;
	}

out:
	return out_idx;
}

static long upcall_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct event_manager *mgr = file->private_data;
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case UPIOGQCNT:
		if (copy_to_user(uarg, &mgr->queue_cnt, sizeof(uint64_t)))
			return -EFAULT;
		return 0;
	default:
		return -ENOIOCTLCMD;
	}
}

static void free_manager(struct event_manager *mgr)
{
	struct event_channel *chan;
	for (uint64_t i = 0; i < NR_CPUS; i++) {
		chan = mgr->channels[i];
		mgr->channels[i] = NULL;
		if (!chan)
			continue;
		for (uint64_t j = i + 1; j < NR_CPUS; j++)
			if (mgr->channels[j] == chan)
				mgr->channels[j] = NULL;
		kfree(chan);
	}
	kfree(mgr);
}

static void free_manager_kref(struct kref *kref)
{
	struct event_manager *mgr = container_of(kref, struct event_manager, ref_count);
	free_manager(mgr);
}

static int upcall_tear_down(struct inode *inode, struct file *file)
{
	struct event_manager *mgr = file->private_data;
	if (mgr)
		kref_put(&mgr->ref_count, free_manager_kref);	
	return 0;
}

static const struct file_operations upcall_fops = {
	.release		= upcall_tear_down,
	.llseek			= noop_llseek,
	.unlocked_ioctl		= upcall_ioctl,
};

static inline int is_file_upcall(struct file *f)
{
	return f->f_op == &upcall_fops;
}

static inline void clean_kitems(int count, struct up_event **kitems)
{
	for (int j = 0; j < count; j++) {
		kmem_cache_free(event_cache, kitems[j]);
	}
}

SYSCALL_DEFINE5(upcall_submit, int, upfd, int, in_cnt, struct up_event __user *, in,
		int, out_cnt, struct up_event __user *, out)
{
	struct event_manager *mgr = NULL;
	struct up_event **kitems = NULL;
	struct up_event **koutput = NULL;
	int ret = -EINVAL;
	int cnt;

	if (in == NULL && in_cnt > 0)
		goto out;
	if (out_cnt <= 0 || out == NULL)
		goto out;

	ret = -EBADF;
	CLASS(fd, f)(upfd);
	if (fd_empty(f))
		goto out;

	if (!is_file_upcall(fd_file(f)))
		goto out;

	ret = -ENOMEM;

	kitems = kzalloc(sizeof(struct up_event *) * in_cnt, GFP_KERNEL);
	if (!kitems)
		goto out;
	koutput = kzalloc(sizeof(struct up_event *) * out_cnt, GFP_KERNEL);
	if (!koutput)
		goto out_free;

	for (int i = 0; i < in_cnt; i++) {
		struct up_event *item = kmem_cache_zalloc(event_cache, GFP_KERNEL);
		if (!item) {
			clean_kitems(i, kitems);
			goto out_free;
		}
		item->fd = -1;

		kitems[i] = item;
			
		if (copy_from_user(item, &in[i], sizeof(*item))) {
			clean_kitems(i + 1, kitems);
			ret = -EFAULT;
			goto out_free;
		}

		if (item->fd < 0 || item->work_fn == NULL) {
			pr_err("Corrupted submission at %d of %d\n", i, in_cnt);
			if (item->fd < 0)
				pr_err("Bad fd\n");
			else
				pr_err("Missing continuation\n");
			clean_kitems(i + 1, kitems);
			ret = -EINVAL;
			goto out_free;
		}
	}

	mgr = (struct event_manager *)fd_file(f)->private_data;

	cnt = do_upcall_submit(mgr, in_cnt, kitems, out_cnt, koutput);

	for (int i = 0; i < out_cnt && i < cnt; i++) {
		if (copy_to_user(&out[i], koutput[i], sizeof(struct up_event))) {
			ret = -EFAULT;
			goto out_clean;
		}
	}


	ret = cnt;
out_clean:
	clean_kitems(cnt, koutput);
out_free:
	kfree(kitems);
	kfree(koutput);
out:
	return ret;
}

static struct event_channel *create_channel(void)
{
	struct event_channel *ret = kzalloc(sizeof(struct event_channel), GFP_KERNEL);
	if (!ret)
		return ret;

	INIT_LIST_HEAD(&ret->wakeups);
	INIT_LIST_HEAD(&ret->sleeping_workers);
	spin_lock_init(&ret->wakeup_lock);
	spin_lock_init(&ret->worker_lock);

	return ret;
}

static struct event_manager *create_manager(int flags)
{
	int i, j;
	struct event_channel *mine;
	struct event_manager *mgr;
	int concurrency_model = flags & UPCALL_MODEL_MASK;

	mgr = kzalloc(sizeof(struct event_manager), GFP_KERNEL);
	if (!mgr)
		return mgr;

	switch(concurrency_model) {
	default:
	case UPCALL_PCPU:
		for_each_online_cpu(i) {
			mgr->channels[i] = create_channel();
			if (!mgr->channels[i])
				goto out_free;
		}
			mgr->queue_cnt++;
			break;

	case UPCALL_PCACHE:
		for_each_online_cpu(i) {
			if (mgr->channels[i]) // We already have one
				continue;
			mine = create_channel();
			if (!mine)
				goto out_free;
			mgr->queue_cnt++;
			mgr->channels[i] = mine;
			for_each_cpu(j, topology_cluster_cpumask(i)) {
				if (i == j)
					continue;
				mgr->channels[j] = mine;
			}
		}
		break;

	case UPCALL_SINGLE:
		mine = create_channel();
		if (!mine)
			goto out_free;
		mgr->queue_cnt++;
		for_each_online_cpu(i) {
			mgr->channels[i] = mine;
		}
		break;
	}

	kref_init(&mgr->ref_count);

	return mgr;

out_free:
	for_each_online_cpu(i) {
		kfree(mgr->channels[i]);
	}
	kfree(mgr);
	return NULL;
}

SYSCALL_DEFINE1(upcall_create, int, flags)
{
	int fd, error = 0;
	struct event_manager *mgr;
	struct file *file;

	mgr = create_manager(flags);
	if (!mgr)
		return -ENOMEM;

	fd = get_unused_fd_flags(O_RDWR | (flags & O_CLOEXEC));
	if (fd < 0) {
		error = fd;
		goto out_free;
	}

	file = anon_inode_getfile("[upcall]", &upcall_fops, mgr,
			O_RDWR | (flags & O_CLOEXEC));
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		goto out_put_fd;
	}

	mgr->file = file;
	fd_install(fd, file);
	return fd;

out_put_fd:
	put_unused_fd(fd);
out_free:
	kfree(mgr);
	return error;
}

static int __init upcall_init(void)
{
	event_cache = kmem_cache_create("upcall_event", sizeof(struct up_event),
			0, SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);
	if (!event_cache)
		return -ENOMEM;
	anchor_cache = kmem_cache_create("upcall_anchor", sizeof(struct event_anchor),
			0, SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);
	if (!anchor_cache)
		return -ENOMEM;
	return 0;
}

__initcall(upcall_init);


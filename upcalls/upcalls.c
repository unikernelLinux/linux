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
#include <linux/net.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/rculist.h>
#include <linux/percpu-defs.h>
#include <linux/cpumask.h>
#include <linux/anon_inodes.h>
#include <linux/upcall.h>
#include <linux/socket.h>

#include <linux/sched.h>

struct event_channel {
	spinlock_t		wakeup_lock;
	spinlock_t		worker_lock;
	struct list_head	wakeups;
	struct list_head	sleeping_workers;
	size_t			event_count;
	uint8_t			pad[8]; // Pad to a cacheline
};

struct event_manager {
	struct file		*file;
	struct kref ref_count;
	/* Number of channels created during initialization */
	uint64_t		queue_cnt;
	/* Each CPU has its own pointer to an event_channel but they
	 * are not necessarily unique. In the case of per LLC channels,
	 * all CPUs that share an LLC will also share an event_channel
	 */
	struct event_channel	*channels[NR_CPUS];
	struct worker_context	*pcpu_workers[NR_CPUS];
	struct event_channel	*channel_list[NR_CPUS];
};

struct event_anchor {
	struct list_head	anchor;
	struct up_event		*event;
	struct event_manager	*mgr;
	atomic_t		armed;
	wait_queue_entry_t	wait;
	wait_queue_head_t	*whead;
	poll_table		pt;
	__poll_t		events;
};

struct event_buffer {
	struct iovec		iovec;
	struct list_head	anchor;
};

struct worker_context {
	struct task_struct	*worker;
	struct list_head	buffers;
	struct list_head	anchor;
	uint64_t		spurious_count;
};

/* up_event cache */
static struct kmem_cache *event_cache __read_mostly;

/* Anchor cache */
static struct kmem_cache *anchor_cache __read_mostly;

/* Buffer cache */
static struct kmem_cache *buffer_cache __read_mostly;

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

static inline struct worker_context *get_local_worker(struct event_manager *mgr)
{
	return mgr->pcpu_workers[smp_processor_id()];
}

static void post_event(struct event_anchor *anchor)
{
	unsigned long flags;
	struct worker_context *ctx;
	struct event_channel *channel;

	/* Now, we add this to the wakeup list for this CPU and potentially wake a
	   waiting thread to process */
	local_irq_save(flags);
	channel = anchor->mgr->channels[smp_processor_id()];
	INIT_LIST_HEAD(&anchor->anchor);
	scoped_guard(spinlock, &channel->wakeup_lock) {
		list_add_tail(&anchor->anchor, &channel->wakeups);
		channel->event_count++;
	}

	// Start by checking if the local worker is sleeping and wake it only.
	scoped_guard(spinlock, &channel->worker_lock) {
		ctx = anchor->mgr->pcpu_workers[smp_processor_id()];
		if (ctx && !list_empty(&ctx->anchor)) {
			list_del_init(&ctx->anchor);
			wake_up_process(ctx->worker);
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

	/* Called from __wake_up_common with wq_head->lock held; use list_del_init
	 * directly rather than remove_wait_queue, which would deadlock trying to
	 * re-acquire the same lock. */
	list_del_init(&anchor->wait.entry);

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

static void get_buffer(struct iovec *iov)
{
	struct event_buffer *buf;

	buf = list_first_entry_or_null(&(current->worker_context->buffers), struct event_buffer, anchor);
	if (!buf) {
		iov->iov_base = NULL;
		return;
	}

	list_del(&buf->anchor);

	iov->iov_base = buf->iovec.iov_base;
	iov->iov_len = buf->iovec.iov_len;
	kmem_cache_free(buffer_cache, buf);
}


static void try_read(struct up_event *evt)
{
	struct file *file;
	struct kiocb kiocb;
	struct iov_iter iter;
	struct iovec iov;
	size_t cursor = 0;
	int ret;
	CLASS(fd_pos, f)(evt->fd);

	if (fd_empty(f)) {
		evt->result = -EBADF;
		return;
	}

	get_buffer(&iov);
	if (iov.iov_base == NULL) {
		evt->result = -ENOMEM;
		return;
	}

	evt->buf = iov.iov_base;
	evt->len = iov.iov_len;

	file = fd_file(f);
	init_sync_kiocb(&kiocb, file);

	while (cursor < iov.iov_len) {

		iov_iter_ubuf(&iter, ITER_DEST, iov.iov_base + cursor, iov.iov_len - cursor);

		ret = file->f_op->read_iter(&kiocb, &iter);

		if (ret <= 0) {
			evt->result = cursor > 0 ? cursor : ret;
			return;
		}
		cursor += ret;
	}

	evt->result = cursor;
}

static void try_write(struct up_event *evt)
{
	struct file *file;
	struct kiocb kiocb;
	struct iov_iter iter;
	struct iovec iov;
	size_t cursor = 0;
	int ret;
	CLASS(fd_pos, f)(evt->fd);

	if (fd_empty(f)) {
		evt->result = -EBADF;
		return;
	}

	iov.iov_base = evt->buf;
	iov.iov_len = evt->len;

	file = fd_file(f);
	init_sync_kiocb(&kiocb, file);

	while (cursor < iov.iov_len) {

		iov_iter_ubuf(&iter, ITER_SOURCE, iov.iov_base + cursor, iov.iov_len - cursor);

		ret = file->f_op->write_iter(&kiocb, &iter);

		if (ret <= 0) {
			evt->result = cursor > 0 ? cursor : ret;
			return;
		}
		cursor += ret;
	}

	evt->result = cursor;
}

static void try_accept(struct up_event *evt)
{
	 evt->result = __sys_accept4(evt->fd, NULL, 0, SOCK_NONBLOCK);
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
		channel->event_count--;
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
	if (channel->event_count > 0) {
		// We did race, go do the work
		spin_unlock(&channel->wakeup_lock);
		spin_unlock(&channel->worker_lock);
		local_irq_restore(flags);
		goto out;
	}
	spin_unlock(&channel->wakeup_lock);

	// Okay, we really need to sleep.
	list_add(&current->worker_context->anchor, &channel->sleeping_workers);
	set_current_state(TASK_INTERRUPTIBLE);
	spin_unlock(&channel->worker_lock);
	local_irq_restore(flags);
again:
	schedule();

	// schedule() can return without us having called ttwp, check if we are still on
	// the worker list
	local_irq_save(flags);
	spin_lock(&channel->worker_lock);
	if (!list_empty(&current->worker_context->anchor)) {
		current->worker_context->spurious_count++;
		set_current_state(TASK_INTERRUPTIBLE);
		spin_unlock(&channel->worker_lock);
		local_irq_restore(flags);
		goto again;
	}
	spin_unlock(&channel->worker_lock);
	local_irq_restore(flags);
out:
	return;
}

static struct event_anchor *build_anchor(struct event_manager *mgr, struct up_event *evt)
{
	struct event_anchor *anchor;

	anchor = kmem_cache_alloc(anchor_cache, GFP_KERNEL);
	if (!anchor) {
		// Not sure what to do here, needs thinking
		return NULL;
	}
	anchor->event = evt;
	INIT_LIST_HEAD(&anchor->anchor);
	INIT_LIST_HEAD(&anchor->wait.entry);
	anchor->mgr = mgr;
	kref_get(&mgr->ref_count);
	atomic_set(&anchor->armed, 1);
	return anchor;
}

static void attach_buffers(uint64_t cnt, struct iovec __user *bufs)
{
	struct worker_context *ctx = current->worker_context;
	struct event_buffer *buf;

	for (uint64_t i = 0; i < cnt; i++) {
		buf = kmem_cache_alloc(buffer_cache, GFP_KERNEL);
		INIT_LIST_HEAD(&buf->anchor);
		if (copy_from_user(&buf->iovec, &bufs[i], sizeof(struct iovec)))
			return;
		list_add(&buf->anchor, &ctx->buffers);
	}
}

static int attach_poll(struct event_manager *mgr, struct up_event *evt, __poll_t rdw) 
{
	struct event_anchor *anchor;
	int armed;

	anchor = build_anchor(mgr, evt);
	if (!anchor) {
		return -ENOMEM;
	}

	init_poll_funcptr(&anchor->pt, upcall_poll_init);
	if (upcall_item_poll(anchor, rdw | EPOLLERR | EPOLLHUP | EPOLLPRI)) {
		/* There was data waiting. Only remove the wait queue entry and
		 * post the event if we still own the anchor.
		 */
		armed = atomic_dec_return(&anchor->armed);
		if (!armed) {
			remove_wait_queue(anchor->whead, &anchor->wait);
			post_event(anchor);
		}
	}

	return 0;
}

static int do_upcall_submit(struct event_manager *mgr, int in_cnt,
		struct up_event **in, int out_cnt, struct up_event **out)
{
	int out_idx = 0;
	int ret = 0;
	struct event_anchor *anchor;

	// Handle all the incoming submissions
	for (int i = 0; i < in_cnt; i++) {
		switch (in[i]->type) {
		case UP_VEC:
			attach_buffers(in[i]->len, (struct iovec*)in[i]->buf);
			kmem_cache_free(event_cache, in[i]);
			break;

		case UP_ACCEPT:
			ret = attach_poll(mgr, in[i], EPOLLIN | POLLRDNORM);
			break;

		case UP_READ:
			ret = attach_poll(mgr, in[i], EPOLLIN | POLLRDNORM);
			break;

		case UP_WRITE:
			ret = attach_poll(mgr, in[i], EPOLLOUT | POLLWRNORM);
			break;

		default:
			return -EINVAL;
		};
		in[i] = NULL;

	}

again:
	// Now we need to check wakeups
	while (out_idx < out_cnt) {
		anchor = get_next_wakeup(mgr);
		if (!anchor)
			break;

		switch (anchor->event->type) {
		case UP_READ:
			try_read(anchor->event);
			break;
		case UP_WRITE:
			try_write(anchor->event);
			break;
		case UP_ACCEPT:
			try_accept(anchor->event);
			break;
		default:
			return -EINVAL;
		}
		out[out_idx] = anchor->event;
		out_idx++;
		put_mgr(mgr);
		kmem_cache_free(anchor_cache, anchor);
	}

	// Finally, if we have no active wakeups and no output, we need to sleep here and try again.
	if (!out_idx && out_cnt > 0) {
		worker_sleep(mgr);
		goto again;
	}

	return out_idx;
}

static struct worker_context *build_context(void)
{
	struct worker_context *ctx;
	ctx = kzalloc(sizeof(struct worker_context), GFP_KERNEL);
	if (!ctx)
		return NULL;
	INIT_LIST_HEAD(&ctx->anchor);
	INIT_LIST_HEAD(&ctx->buffers);

	return ctx;
}

static long upcall_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct event_manager *mgr = file->private_data;
	void __user *uarg = (void __user *)arg;
	struct worker_context *ctx;
	struct event_channel *channel;
	struct list_head *pos;
	uint64_t out = 0;

	switch (cmd) {
	case UPIOGQCNT:
		for (uint64_t i = 0; i < mgr->queue_cnt; i++) {
			channel = mgr->channel_list[i];
			list_for_each(pos, &(channel->sleeping_workers)) {
				ctx = container_of(pos, struct worker_context, anchor);
				out += ctx->spurious_count;
			}
		}
		if (copy_to_user(uarg, &out, sizeof(uint64_t)))
			return -EFAULT;
		return 0;
	case UPWRKINIT:
		ctx = build_context();
		if (!ctx)
			return -ENOMEM;
		ctx->worker = current;
		current->worker_context = ctx;
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
		int, out_cnt, struct up_event __user *, output)
{
	struct event_manager *mgr = NULL;
	struct up_event **kitems = NULL;
	struct up_event **koutput = NULL;
	int ret = -EINVAL;
	int cnt;
	struct worker_context *ctx;
	unsigned long flags;

	if (in == NULL && in_cnt > 0)
		goto out;
	if (out_cnt != 0 && output == NULL)
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

	mgr = (struct event_manager *)fd_file(f)->private_data;

	if (current->worker_context == NULL) {
		ctx = build_context();
		if (!ctx)
			goto out;
		ctx->worker = current;
		current->worker_context = ctx;
		local_irq_save(flags);
		if (mgr->pcpu_workers[smp_processor_id()] == NULL) {
			mgr->pcpu_workers[smp_processor_id()] = ctx;
		}
		local_irq_restore(flags);

	}

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

		// Check if we have an fd, UP_VEC doesn't need one
		if (item->fd < 0 && item->type != UP_VEC) {
			pr_err("Corrupted submission at %d of %d, bad fd\n", i, in_cnt);
			clean_kitems(i + 1, kitems);
			ret = -EINVAL;
			goto out_free;
		}

		// Check if we have a continuation, UP_VEC doesn't need one
		if (item->work_fn == NULL && item->type != UP_VEC) {
			pr_err("Corrupted submission at %d of %d, missing continuation\n", i, in_cnt);
			clean_kitems(i + 1, kitems);
			ret = -EINVAL;
			goto out_free;
		}
	}

	cnt = do_upcall_submit(mgr, in_cnt, kitems, out_cnt, koutput);

	for (int i = 0; i < out_cnt && i < cnt; i++) {
		if (copy_to_user(&output[i], koutput[i], sizeof(struct up_event))) {
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
			mgr->channel_list[mgr->queue_cnt] = mgr->channels[i];
			mgr->queue_cnt++;
		}
			break;

	case UPCALL_PCACHE:
		for_each_online_cpu(i) {
			if (mgr->channels[i]) // We already have one
				continue;
			mine = create_channel();
			if (!mine)
				goto out_free;
			mgr->channel_list[mgr->queue_cnt] = mine;
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
		mgr->channel_list[mgr->queue_cnt] = mine;
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

	buffer_cache = kmem_cache_create("upcall_buffer", sizeof(struct event_buffer),
			0, SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);
	if (!buffer_cache)
		return -ENOMEM;

	return 0;
}

__initcall(upcall_init);


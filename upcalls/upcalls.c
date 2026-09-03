// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Upcall event handler implementaion
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/vmalloc.h>
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
#include <linux/percpu.h>
#include <linux/cpumask.h>
#include <linux/anon_inodes.h>
#include <linux/upcall.h>
#include <linux/socket.h>
#include <net/busy_poll.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include <linux/sched.h>

struct event_channel {
	spinlock_t		wakeup_lock;
	spinlock_t		worker_lock;
	struct list_head	wakeups;
	struct list_head	sleeping_workers;
	size_t			event_count;
	int			cpu;
	uint8_t			pad[4];
};

struct event_manager {
	struct file		*file;
	struct kref ref_count;
	struct event_channel	*channels[NR_CPUS];
	struct worker_context	*pcpu_workers[NR_CPUS];
	/* owned_mask mirrors core_pool.owner[] for lock-free reads on the
	 * delivery path; a stolen owner[] flip is serialised against
	 * post_event() by the owning channel's wakeup_lock. guaranteed_mask
	 * (subset of owned_mask, ~1 core per LLC domain) is never released. */
	struct cpumask		owned_mask;
	struct cpumask		guaranteed_mask;
	struct cpumask		guaranteed_electing;	/* per-domain create-once token */
	atomic_t		owned_count;
	size_t		batch_size;
	/* Kept separate from batch_size -- coupling scale-up to the placement
	 * threshold caused a regression before. */
	size_t		spread_threshold;
	/* Below this completion count, do one NAPI poll budget before returning. */
	size_t		napi_poll_threshold;
	int			id;		/* small stable id for observability */
	/* fd -> struct file* cache; entries only clear via UP_CLOSE, which is
	 * the only path that closes an fd this manager touches. */
	struct file		**fd_cache;
	unsigned int		fd_cache_size;
};

/*
 * Machine-global core pool: the only cross-manager structure. A core is
 * owned by at most one manager at any instant. Hot paths are lock-free
 * (test_and_clear/cmpxchg on the masks); core_pool.lock is only taken for a
 * genuine cross-app steal and free_manager() teardown, which serialise
 * against each other.
 */
struct upcall_core_pool {
	spinlock_t		lock;
	struct event_manager	*owner[NR_CPUS];
	struct cpumask		free_mask;	/* tier 1: never-owned / returned on exit */
	struct cpumask		stealable_mask;	/* tier 2: owned but worker parked idle */
};

static struct upcall_core_pool core_pool;

/* Monotonic id source + debugfs handle for observability. */
static  atomic_t upcall_mgr_ids = ATOMIC_INIT(0);
static struct dentry *upcall_debugfs_dir;

struct event_anchor {
	struct list_head	anchor;
	struct up_event		*event;
	struct event_manager	*mgr;
	atomic_t		armed;	/* arbiter: who completes/posts the event */
	struct kref		refs;	/* lifetime: recycled when this hits 0 */
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

/*
 * Per-CPU recycle pool for event_anchor objects; build_anchor()/attach_poll()
 * reinitialize every field on reuse. Only touched from task context (the
 * softirq-reachable drop_anchor() path frees straight to the slab instead),
 * so preempt-disable (get_cpu_var/put_cpu_var) is enough without irq-off.
 */
#define ANCHOR_POOL_CAP 64
struct anchor_pool {
	int			count;
	struct event_anchor	*free[ANCHOR_POOL_CAP];
};
static DEFINE_PER_CPU(struct anchor_pool, anchor_pool);

/* fd -> struct file* cache size; see fdcache_get() near try_read(). */
#define FD_CACHE_SIZE 65536

/* Buffer cache */
static struct kmem_cache *buffer_cache __read_mostly;

static void free_manager_kref(struct kref *kref);

/* anchor->refs release callbacks: recycle to the per-CPU pool (task context)
 * or free straight to the slab (drop_anchor, which is softirq-reachable and
 * must not touch the pool). */
static void anchor_release_pool(struct kref *kref);
static void anchor_release_slab(struct kref *kref);

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

/*
 * Finest CPU grouping that still has more than one CPU: LLC, then socket,
 * then whole machine. The fallbacks matter on topologies (e.g. QEMU) that
 * report each CPU as its own singleton domain, which would otherwise make
 * spreading/elastic claim silently unable to find a sibling.
 */
static const struct cpumask *upcall_domain_mask(int cpu)
{
	const struct cpumask *m = cpu_llc_shared_mask(cpu);

	if (m && cpumask_weight(m) > 1)
		return m;
	m = topology_core_cpumask(cpu);
	if (m && cpumask_weight(m) > 1)
		return m;
	return cpu_online_mask;
}

/*
 * Acquire a core for mgr within `domain`. Lock-free except for a genuine
 * cross-app steal (tier 2), which takes core_pool.lock so the victim can't
 * be freed under us, then gates on the victim being idle (event_count == 0)
 * under its own channel wakeup_lock and flips owner[cpu] with cmpxchg -- the
 * same lock post_event() uses to re-validate ownership, so no event strands.
 * Returns the cpu acquired (now in mgr->owned_mask) or -1.
 */
static int acquire_core(struct event_manager *mgr, const struct cpumask *domain)
{
	unsigned long flags;
	int cpu;

	/* Tier 1: a truly free core (lock-free). */
	for_each_cpu_and(cpu, domain, &core_pool.free_mask) {
		if (!cpumask_test_and_clear_cpu(cpu, &core_pool.free_mask))
			continue;	/* lost the race for this core */
		WRITE_ONCE(core_pool.owner[cpu], mgr);
		cpumask_set_cpu(cpu, &mgr->owned_mask);
		atomic_inc(&mgr->owned_count);
		return cpu;
	}

	/* Tier 2: steal an idle core from another app. */
	for_each_cpu_and(cpu, domain, &core_pool.stealable_mask) {
		struct event_manager *victim;
		struct event_channel *vchan;

		if (!cpumask_test_and_clear_cpu(cpu, &core_pool.stealable_mask))
			continue;	/* another CPU grabbed the mark */
		victim = READ_ONCE(core_pool.owner[cpu]);
		if (!victim || victim == mgr)
			continue;	/* free or our own — skip, lock-free */

		/* Re-read owner in case it moved while we were lock-free. */
		spin_lock_irqsave(&core_pool.lock, flags);
		victim = READ_ONCE(core_pool.owner[cpu]);
		if (victim && victim != mgr) {
			vchan = victim->channels[cpu];
			spin_lock(&vchan->wakeup_lock);
			if (vchan->event_count == 0 &&
			    cmpxchg(&core_pool.owner[cpu], victim, mgr) == victim) {
				cpumask_clear_cpu(cpu, &victim->owned_mask);
				cpumask_set_cpu(cpu, &mgr->owned_mask);
				atomic_dec(&victim->owned_count);
				atomic_inc(&mgr->owned_count);
				spin_unlock(&vchan->wakeup_lock);
				spin_unlock_irqrestore(&core_pool.lock, flags);
				return cpu;
			}
			spin_unlock(&vchan->wakeup_lock);
		}
		spin_unlock_irqrestore(&core_pool.lock, flags);
		/* victim reclaimed it or ownership moved; mark already cleared */
	}
	return -1;
}

/*
 * Ensure mgr owns a guaranteed (never-released) core in cpu's domain. To
 * elect exactly one claimer per domain without a lock, test_and_set on
 * guaranteed_electing is keyed on the domain's first CPU as a stable token;
 * the winner acquires (possibly stealing an idle core), everyone else skips.
 * Backstop: if the domain yields nothing and mgr still owns zero cores,
 * acquire machine-wide so it can never strand coreless.
 */
static void claim_guaranteed_core(struct event_manager *mgr, int cpu)
{
	const struct cpumask *domain = upcall_domain_mask(cpu);
	int c;

	if (cpumask_test_and_set_cpu(cpumask_first(domain), &mgr->guaranteed_electing))
		return;
	c = acquire_core(mgr, domain);
	if (c < 0 && atomic_read(&mgr->owned_count) == 0)
		c = acquire_core(mgr, cpu_online_mask);
	if (c >= 0)
		cpumask_set_cpu(c, &mgr->guaranteed_mask);
}

/*
 * Scale-down without releasing: mark an idle non-guaranteed core stealable
 * instead of freeing it, so mgr keeps ownership (post_event reclaims it
 * instantly if work arrives) but another app can steal it under pressure.
 */
static void mark_stealable(struct event_manager *mgr, int cpu)
{
	struct event_channel *chan = mgr->channels[cpu];
	unsigned long flags;

	if (cpumask_test_cpu(cpu, &mgr->guaranteed_mask))
		return;

	spin_lock_irqsave(&chan->wakeup_lock, flags);
	if (chan->event_count == 0 && READ_ONCE(core_pool.owner[cpu]) == mgr)
		cpumask_set_cpu(cpu, &core_pool.stealable_mask);
	spin_unlock_irqrestore(&chan->wakeup_lock, flags);
}

/* Wake the manager's worker on cpu if it is parked.  Caller has IRQs off. */
static void wake_owned_worker(struct event_manager *mgr, int cpu)
{
	struct event_channel *chan = mgr->channels[cpu];
	struct worker_context *ctx;

	spin_lock(&chan->worker_lock);
	ctx = mgr->pcpu_workers[cpu];
	if (ctx && !list_empty(&ctx->anchor)) {
		list_del_init(&ctx->anchor);
		wake_up_process(ctx->worker);
	}
	spin_unlock(&chan->worker_lock);
}

/*
 * Choose an owned channel for mgr to receive an event that arrived on my_cpu.
 * Fast path: the local core, as long as it is owned and its queue depth is
 * below mgr->batch_sz.  Past that, spreads to the least-loaded core
 * mgr owns within my_cpu's cache domain; if the domain has no owned core,
 * falls back to a guaranteed core (never released, always a valid target).
 * Reads owned/guaranteed masks lock-free — hint quality; post_event
 * re-validates the chosen core's ownership under its wakeup_lock.  Returns NULL
 * only if the manager owns no cores at all (pathological, fully-allocated
 * machine).
 */

static struct event_channel *pick_target(struct event_manager *mgr, int my_cpu)
{
	const struct cpumask *domain = upcall_domain_mask(my_cpu);
	struct event_channel *best = NULL;
	size_t best_count = (size_t)-1;
	int cpu;

	if (cpumask_test_cpu(my_cpu, &mgr->owned_mask)) {
		struct event_channel *local = mgr->channels[my_cpu];

		/*
		 * We don't want to spread to a new core until our local queueu is
		 * larger than the application configured batch size 
		 */
		if (local && READ_ONCE(local->event_count) < mgr->batch_size)
			return local;
	}

	for_each_cpu_and(cpu, domain, &mgr->owned_mask) {
		struct event_channel *chan = mgr->channels[cpu];
		size_t count;

		if (!chan)
			continue;
		count = READ_ONCE(chan->event_count);
		if (count < best_count) {
			best_count = count;
			best = chan;
			if (count == 0)
				break;
		}
	}
	if (best)
		return best;

	cpu = cpumask_first(&mgr->guaranteed_mask);
	if (cpu < nr_cpu_ids)
		return mgr->channels[cpu];

	return NULL;
}

/* Only reachable when mgr owns no cores at all (fully-allocated machine). */
static void drop_anchor(struct event_anchor *anchor)
{
	pr_warn_once("upcall: manager owns no cores, dropping event\n");
	kmem_cache_free(event_cache, anchor->event);
	put_mgr(anchor->mgr);
	/* Drop the event reference. anchor_release_slab frees straight to the slab
	 * (this path is softirq-reachable and must not touch the pool); if the
	 * arming path still holds its reference it frees the anchor itself later. */
	kref_put(&anchor->refs, anchor_release_slab);
}

/* Runs with IRQs disabled (placement context). */
static void upcall_scale_up(struct event_manager *mgr, int cpu)
{
	int claimed;

	if (cpumask_empty(&core_pool.free_mask) &&
	    cpumask_empty(&core_pool.stealable_mask))
		return;
	claimed = acquire_core(mgr, upcall_domain_mask(cpu));
	if (claimed >= 0)
		wake_owned_worker(mgr, claimed);
}

static void post_event(struct event_anchor *anchor)
{
	unsigned long flags;
	struct event_manager *mgr = anchor->mgr;
	struct event_channel *target;
	bool enqueued = false;
	bool congested = false;
	int my_cpu, gcpu;

	local_irq_save(flags);
	my_cpu = smp_processor_id();

	/* Softirq may run on a CPU this manager doesn't own. */
	target = pick_target(mgr, my_cpu);
	if (!target) {
		local_irq_restore(flags);
		drop_anchor(anchor);
		return;
	}

	INIT_LIST_HEAD(&anchor->anchor);

	/* If mgr released the core since pick_target(), owner[] no longer
	 * points at mgr; fall back to a guaranteed core instead of enqueuing
	 * onto a channel nothing will ever drain. */
	spin_lock(&target->wakeup_lock);
	if (READ_ONCE(core_pool.owner[target->cpu]) == mgr) {
		congested = target->event_count > mgr->spread_threshold;
		list_add_tail(&anchor->anchor, &target->wakeups);
		target->event_count++;
		enqueued = true;
	}
	spin_unlock(&target->wakeup_lock);

	if (!enqueued) {
		gcpu = cpumask_first(&mgr->guaranteed_mask);
		if (gcpu >= nr_cpu_ids) {
			local_irq_restore(flags);
			drop_anchor(anchor);
			return;
		}
		target = mgr->channels[gcpu];
		spin_lock(&target->wakeup_lock);
		congested = target->event_count > mgr->spread_threshold;
		list_add_tail(&anchor->anchor, &target->wakeups);
		target->event_count++;
		spin_unlock(&target->wakeup_lock);
	}

	wake_owned_worker(mgr, target->cpu);

	if (congested)
		upcall_scale_up(mgr, my_cpu);

	local_irq_restore(flags);
}

static int handle_poll_event(struct wait_queue_entry *wq_entry, unsigned mode,
		int flags, void *key)
{
	struct event_anchor *anchor = container_of(wq_entry, struct event_anchor, wait);
	__poll_t pollflags = key_to_poll(key);
	int armed;

	if (pollflags && !(pollflags & anchor->events))
		return 0;

	armed = atomic_dec_return(&anchor->armed);
	if (armed)
		return 0;	/* raced with another wakeup path; they won */

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

/*
 * Returns a reference borrowed from the cache -- callers must never fput()
 * it. fdcache_invalidate() runs before close_fd() actually closes the fd, so
 * a lookup never observes a stale pointer.
 */
static struct file *fdcache_get(struct event_manager *mgr, int fd)
{
	struct file *file, *raced;

	if (fd < 0 || (unsigned int)fd >= mgr->fd_cache_size)
		return NULL;

	file = READ_ONCE(mgr->fd_cache[fd]);
	if (file)
		return file;

	file = fget(fd);
	if (!file)
		return NULL;

	raced = cmpxchg(&mgr->fd_cache[fd], NULL, file);
	if (raced) {
		/* Someone else published first; use theirs, drop our extra ref. */
		fput(file);
		return raced;
	}
	return file;
}

/* Called before close_fd() so no lookup can observe a stale cached file. */
static void fdcache_invalidate(struct event_manager *mgr, int fd)
{
	struct file *file;

	if (fd < 0 || (unsigned int)fd >= mgr->fd_cache_size)
		return;

	file = xchg(&mgr->fd_cache[fd], NULL);
	if (file)
		fput(file);
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


static void try_read(struct event_manager *mgr, struct up_event *evt)
{
	struct file *file;
	struct kiocb kiocb;
	struct iov_iter iter;
	struct iovec iov;
	size_t cursor = 0;
	int ret;

	file = fdcache_get(mgr, evt->fd);
	if (!file) {
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

static void try_write(struct event_manager *mgr, struct up_event *evt)
{
	struct file *file;
	struct kiocb kiocb;
	struct iov_iter iter;
	struct iovec iov;
	size_t cursor = 0;
	int ret;

	file = fdcache_get(mgr, evt->fd);
	if (!file) {
		evt->result = -EBADF;
		return;
	}

	iov.iov_base = evt->buf;
	iov.iov_len = evt->len;

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
	struct file *file = fdcache_get(anchor->mgr, anchor->event->fd);
	poll_table *pt = &anchor->pt;
	__poll_t res;

	if (!file)
		return 0;

	anchor->events = pt->_key = events;
	res = vfs_poll(file, pt);

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
	int cpu;

	local_irq_save(flags);
	cpu = smp_processor_id();
	channel = mgr->channels[cpu];

	spin_lock(&channel->worker_lock);
	/* Double-check under lock: may have raced with a delivered event. */
	spin_lock(&channel->wakeup_lock);
	if (channel->event_count > 0) {
		spin_unlock(&channel->wakeup_lock);
		spin_unlock(&channel->worker_lock);
		local_irq_restore(flags);
		goto out;
	}
	spin_unlock(&channel->wakeup_lock);

	list_add(&current->worker_context->anchor, &channel->sleeping_workers);
	set_current_state(TASK_INTERRUPTIBLE);
	spin_unlock(&channel->worker_lock);
	local_irq_restore(flags);

	mark_stealable(mgr, cpu);
again:
	schedule();

	/* schedule() can return without having been woken via our list;
	 * treat that as spurious and go back to sleep. */
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

/* Pop a recycled anchor for this CPU, or NULL if the pool is empty. */
static struct event_anchor *anchor_pool_get(void)
{
	struct anchor_pool *pool;
	struct event_anchor *anchor = NULL;

	pool = &get_cpu_var(anchor_pool);
	if (pool->count)
		anchor = pool->free[--pool->count];
	put_cpu_var(anchor_pool);

	return anchor;
}

/* Push a freed anchor onto this CPU's pool, or free it to the slab if full. */
static void anchor_pool_put(struct event_anchor *anchor)
{
	struct anchor_pool *pool;
	bool queued = false;

	pool = &get_cpu_var(anchor_pool);
	if (pool->count < ANCHOR_POOL_CAP) {
		pool->free[pool->count++] = anchor;
		queued = true;
	}
	put_cpu_var(anchor_pool);

	if (!queued)
		kmem_cache_free(anchor_cache, anchor);
}

/* kref release: recycle to the per-CPU pool. Only reached from task context
 * (attach_poll / the drain loop), where the pool is safe to touch. */
static void anchor_release_pool(struct kref *kref)
{
	anchor_pool_put(container_of(kref, struct event_anchor, refs));
}

/* kref release: free straight to the slab. Used by drop_anchor(), which is
 * softirq-reachable and must not touch the per-CPU pool. */
static void anchor_release_slab(struct kref *kref)
{
	kmem_cache_free(anchor_cache, container_of(kref, struct event_anchor, refs));
}

static struct event_anchor *build_anchor(struct event_manager *mgr, struct up_event *evt)
{
	struct event_anchor *anchor;

	anchor = anchor_pool_get();
	if (!anchor)
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
	/*
	 * Two lifetime references: one for the arming path (attach_poll, dropped
	 * when it returns) and one for the event itself (dropped when the event
	 * is delivered by the drain, or discarded by drop_anchor).  The anchor is
	 * recycled only when both are gone, so attach_poll's armed-arbitration can
	 * never touch an anchor that the async path already completed and another
	 * worker recycled.  kref_init() gives the first ref; kref_get() the second.
	 */
	kref_init(&anchor->refs);
	kref_get(&anchor->refs);
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
		armed = atomic_dec_return(&anchor->armed);
		if (!armed) {
			/* whead is NULL if the poll op never called poll_wait()
			 * (e.g. DEFAULT_POLLMASK files) -- nothing to remove. */
			if (anchor->whead)
				remove_wait_queue(anchor->whead, &anchor->wait);
			post_event(anchor);
		}
	}

	/*
	 * Drop the arming-path reference.  Until here we held a ref, so no drain
	 * worker could recycle the anchor out from under the armed dec above.  If
	 * the event is already done (drained/dropped), this recycles it; else it
	 * stays alive for the async wakeup path.  Must be last -- `anchor` may be
	 * freed the instant kref_put() drops the final reference.
	 */
	kref_put(&anchor->refs, anchor_release_pool);

	return 0;
}

static int do_upcall_submit(struct event_manager *mgr, int in_cnt,
		struct up_event **in, int out_cnt, struct up_event **out)
{
	int out_idx = 0;
	int ret = 0;
	int last_fd = -1;
	bool polled = false;
	struct event_anchor *anchor;

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

		case UP_CLOSE:
			fdcache_invalidate(mgr, in[i]->fd);
			ret = close_fd(in[i]->fd);
			break;

		default:
			return -EINVAL;
		};
		in[i] = NULL;

		if (ret)
			return ret;
	}

again:
	while (out_idx < out_cnt) {
		anchor = get_next_wakeup(mgr);
		if (!anchor)
			break;

		switch (anchor->event->type) {
		case UP_READ:
			try_read(mgr, anchor->event);
			break;
		case UP_WRITE:
			try_write(mgr, anchor->event);
			break;
		case UP_ACCEPT:
			try_accept(anchor->event);
			break;
		default:
			return -EINVAL;
		}
		out[out_idx] = anchor->event;
		last_fd = anchor->event->fd;
		out_idx++;
		put_mgr(mgr);
		/* Drop the event reference; recycled once the arming path is done
		 * with the anchor too. */
		kref_put(&anchor->refs, anchor_release_pool);
	}

	if (!polled && out_idx > 0 && (size_t)out_idx < mgr->napi_poll_threshold) {
		struct file *file = fdcache_get(mgr, last_fd);
		struct socket *sock = file ? sock_from_file(file) : NULL;

		polled = true;
		if (sock && sock->sk) {
			unsigned int napi_id = READ_ONCE(sock->sk->sk_napi_id);

			if (napi_id_valid(napi_id))
				napi_busy_loop(napi_id, NULL, NULL, false, BUSY_POLL_BUDGET);
		}
		goto again;
	}

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

static void free_manager(struct event_manager *mgr)
{
	struct event_channel *chan;
	unsigned long flags;
	int cpu;

	spin_lock_irqsave(&core_pool.lock, flags);
	for_each_cpu(cpu, &mgr->owned_mask) {
		WRITE_ONCE(core_pool.owner[cpu], NULL);
		cpumask_clear_cpu(cpu, &core_pool.stealable_mask);
		cpumask_set_cpu(cpu, &core_pool.free_mask);
	}
	cpumask_clear(&mgr->owned_mask);
	cpumask_clear(&mgr->guaranteed_mask);
	spin_unlock_irqrestore(&core_pool.lock, flags);

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

	/* Release any fds this manager never got an explicit UP_CLOSE for
	 * (app exit without draining every connection). */
	for (unsigned int i = 0; i < mgr->fd_cache_size; i++) {
		if (mgr->fd_cache[i])
			fput(mgr->fd_cache[i]);
	}
	vfree(mgr->fd_cache);

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
		struct event_channel *reg_channel;
		int reg_cpu;

		ctx = build_context();
		if (!ctx)
			goto out;
		ctx->worker = current;
		current->worker_context = ctx;
		local_irq_save(flags);
		reg_cpu = smp_processor_id();
		reg_channel = mgr->channels[reg_cpu];
		spin_lock(&reg_channel->worker_lock);
		if (mgr->pcpu_workers[reg_cpu] == NULL) {
			mgr->pcpu_workers[reg_cpu] = ctx;
		}
		spin_unlock(&reg_channel->worker_lock);
		local_irq_restore(flags);

		/* After dropping worker_lock so core_pool.lock never nests under it. */
		claim_guaranteed_core(mgr, reg_cpu);
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

		if (item->fd < 0 && item->type != UP_VEC) {
			pr_err("Corrupted submission at %d of %d, bad fd(%d)\n", i, in_cnt, item->fd);
			clean_kitems(i + 1, kitems);
			ret = -EINVAL;
			goto out_free;
		}

		/* UP_VEC and UP_CLOSE don't need a continuation. */
		if (item->work_fn == NULL && !(item->type == UP_VEC || item->type == UP_CLOSE)) {
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

static struct event_manager *create_manager(void)
{
	int i;
	struct event_manager *mgr;

	mgr = kzalloc(sizeof(struct event_manager), GFP_KERNEL);
	if (!mgr)
		return mgr;

	for_each_online_cpu(i) {
		mgr->channels[i] = create_channel();
		if (!mgr->channels[i])
			goto out_free;
		mgr->channels[i]->cpu = i;
	}

	/* An fd beyond this just falls back to uncached (-EBADF). */
	mgr->fd_cache_size = FD_CACHE_SIZE;
	mgr->fd_cache = vzalloc(mgr->fd_cache_size * sizeof(struct file *));
	if (!mgr->fd_cache)
		goto out_free;

	kref_init(&mgr->ref_count);
	mgr->id = atomic_inc_return(&upcall_mgr_ids);

	return mgr;

out_free:
	for_each_online_cpu(i) {
		kfree(mgr->channels[i]);
	}
	vfree(mgr->fd_cache);
	kfree(mgr);
	return NULL;
}

SYSCALL_DEFINE2(upcall_create, size_t, batch_sz, int, flags)
{
	int fd, error = 0;
	struct event_manager *mgr;
	struct file *file;

	if (batch_sz == 0)
		return -EINVAL;

	mgr = create_manager();
	if (!mgr)
		return -ENOMEM;

	mgr->batch_size = batch_sz;
	mgr->spread_threshold = (batch_sz * 3) / 4;
	mgr->napi_poll_threshold = batch_sz / 4;

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

/* debugfs: /sys/kernel/debug/upcall/owners */
static int upcall_owners_show(struct seq_file *s, void *v)
{
	unsigned long flags;
	int cpu;

	spin_lock_irqsave(&core_pool.lock, flags);
	for_each_online_cpu(cpu) {
		struct event_manager *mgr = READ_ONCE(core_pool.owner[cpu]);

		if (!mgr)
			seq_printf(s, "cpu %3d: free\n", cpu);
		else
			seq_printf(s, "cpu %3d: mgr %d%s\n", cpu, mgr->id,
				   cpumask_test_cpu(cpu, &mgr->guaranteed_mask) ?
				   " (guaranteed)" :
				   cpumask_test_cpu(cpu, &core_pool.stealable_mask) ?
				   " (stealable)" : "");
	}
	spin_unlock_irqrestore(&core_pool.lock, flags);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(upcall_owners);

static int __init upcall_init(void)
{
	int cpu;

	spin_lock_init(&core_pool.lock);
	cpumask_clear(&core_pool.stealable_mask);
	cpumask_clear(&core_pool.free_mask);
	for_each_online_cpu(cpu)
		cpumask_set_cpu(cpu, &core_pool.free_mask);

	upcall_debugfs_dir = debugfs_create_dir("upcall", NULL);
	debugfs_create_file("owners", 0444, upcall_debugfs_dir, NULL,
			    &upcall_owners_fops);

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


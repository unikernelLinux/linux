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
	/* Each CPU has its own pointer to an event_channel
	 */
	struct event_channel	*channels[NR_CPUS];
	struct worker_context	*pcpu_workers[NR_CPUS];
	/*
	 * Cooperative core pool ownership.  owned_mask mirrors the global
	 * core_pool.owner[] for cheap lock-free reads on the delivery path;
	 * guaranteed_mask (a subset of owned_mask, ~1 core per LLC domain) is
	 * never released.  Both masks are only mutated under the relevant
	 * channel->wakeup_lock (ownership flips) and/or core_pool.lock (free
	 * core selection); see the locking invariant in claim/release.
	 */
	struct cpumask		owned_mask;
	struct cpumask		guaranteed_mask;
	atomic_t		owned_count;
	int			id;		/* small stable id for observability */
};

/*
 * Machine-global core pool: the only cross-manager structure.  A core is
 * owned by at most one manager at any instant (spatial partitioning).
 * core_pool.lock guards free_mask and the selection of a free core to claim;
 * it is NOT taken on the per-event delivery path.  owner[] entries flip under
 * the owning channel's wakeup_lock so they serialise against post_event().
 */
struct upcall_core_pool {
	spinlock_t		lock;
	struct event_manager	*owner[NR_CPUS];
	struct cpumask		free_mask;	/* tier 1: never-owned / returned on exit */
	struct cpumask		stealable_mask;	/* tier 2: owned but worker parked idle */
};

static struct upcall_core_pool core_pool;

/* Monotonic id source + debugfs handle for observability. */
static atomic_t upcall_mgr_ids = ATOMIC_INIT(0);
static struct dentry *upcall_debugfs_dir;

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

/*
 * The cache domain used for event spreading and elastic core claiming.  We
 * want the finest grouping that still contains more than one CPU: prefer the
 * LLC (L3) sharing domain, then the socket, then the whole machine.  The
 * fallbacks matter because some topologies (notably QEMU, which reports each
 * CPU as its own singleton cluster/LLC) would otherwise make every "domain" a
 * single CPU — which silently breaks spreading and elastic claim (a worker
 * could never find a free sibling in a domain of size one).
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
 * Set the global owner of a physical CPU under that CPU's (this manager's)
 * channel wakeup_lock, so the store serialises against post_event()'s
 * ownership re-validation which reads owner[] under the same lock.  Caller
 * holds core_pool.lock (lock order: pool outer, wakeup_lock inner).
 */
static void set_owner_locked(struct event_manager *mgr, int cpu,
			     struct event_manager *val)
{
	struct event_channel *chan = mgr->channels[cpu];

	spin_lock(&chan->wakeup_lock);
	core_pool.owner[cpu] = val;
	spin_unlock(&chan->wakeup_lock);
}

/*
 * Acquire a core for mgr within `domain`, preferring a truly free core (tier 1)
 * and otherwise stealing an idle core another app marked stealable (tier 2).
 * Caller holds core_pool.lock.  Returns the cpu acquired (now in mgr->owned_mask
 * and removed from the free/stealable pools) or -1 if none is available.
 *
 * A steal flips owner[cpu] under the *victim's* channel wakeup_lock and only
 * while that core is still idle (event_count == 0) — the same gate a release
 * used.  If the victim just got work we back off; its post_event re-validates
 * ownership under the same lock and routes elsewhere, so no event strands.  A
 * stealable core whose owner has since been handed work (a stale mark) is simply
 * dropped from the pool as we pass over it.
 */
static int acquire_core_locked(struct event_manager *mgr,
			       const struct cpumask *domain)
{
	int cpu;

	/* Tier 1: a truly free core. */
	cpu = cpumask_any_and(domain, &core_pool.free_mask);
	if (cpu < nr_cpu_ids) {
		cpumask_clear_cpu(cpu, &core_pool.free_mask);
		set_owner_locked(mgr, cpu, mgr);
		cpumask_set_cpu(cpu, &mgr->owned_mask);
		atomic_inc(&mgr->owned_count);
		return cpu;
	}

	/* Tier 2: steal an idle core from another app. */
	while ((cpu = cpumask_any_and(domain, &core_pool.stealable_mask)) < nr_cpu_ids) {
		struct event_manager *victim = core_pool.owner[cpu];
		struct event_channel *vchan;

		if (!victim || victim == mgr) {
			cpumask_clear_cpu(cpu, &core_pool.stealable_mask);
			continue;
		}
		vchan = victim->channels[cpu];
		spin_lock(&vchan->wakeup_lock);
		if (vchan->event_count == 0) {
			core_pool.owner[cpu] = mgr;
			cpumask_clear_cpu(cpu, &victim->owned_mask);
			cpumask_set_cpu(cpu, &mgr->owned_mask);
			atomic_dec(&victim->owned_count);
			atomic_inc(&mgr->owned_count);
			cpumask_clear_cpu(cpu, &core_pool.stealable_mask);
			spin_unlock(&vchan->wakeup_lock);
			return cpu;
		}
		/* Owner is reclaiming it: drop the stale mark and try another. */
		cpumask_clear_cpu(cpu, &core_pool.stealable_mask);
		spin_unlock(&vchan->wakeup_lock);
	}
	return -1;
}

/*
 * Ensure mgr owns a guaranteed (never-released) core in cpu's cache domain if it
 * does not already.  The "already have one?" test and the acquire happen
 * together under core_pool.lock so concurrent workers in a domain create at most
 * one.  Acquires via the two-tier pool, so a late-starting app can steal an idle
 * incumbent's core for its anchor.  Backstop: if the domain yields nothing and
 * the app still owns no core at all, acquire anywhere machine-wide so it can
 * never strand at zero cores.
 *
 * Relies on upcall_domain_mask() grouping more than one CPU per domain; see the
 * note there about degenerate (QEMU singleton) topologies.
 */
static void claim_guaranteed_core(struct event_manager *mgr, int cpu)
{
	const struct cpumask *domain = upcall_domain_mask(cpu);
	unsigned long flags;
	int c;

	spin_lock_irqsave(&core_pool.lock, flags);
	if (cpumask_intersects(&mgr->guaranteed_mask, domain))
		goto out;
	c = acquire_core_locked(mgr, domain);
	if (c < 0 && atomic_read(&mgr->owned_count) == 0)
		c = acquire_core_locked(mgr, cpu_online_mask);
	if (c >= 0)
		cpumask_set_cpu(c, &mgr->guaranteed_mask);
out:
	spin_unlock_irqrestore(&core_pool.lock, flags);
}

/*
 * Elastic scale-up: acquire a core in `domain` for mgr (tier-1 free, else steal
 * a tier-2 stealable core).  Returns the cpu acquired, or -1 if none available.
 */
static int take_core(struct event_manager *mgr, const struct cpumask *domain)
{
	unsigned long flags;
	int cpu;

	spin_lock_irqsave(&core_pool.lock, flags);
	cpu = acquire_core_locked(mgr, domain);
	spin_unlock_irqrestore(&core_pool.lock, flags);
	return cpu;
}

/*
 * Scale-down without releasing: when a non-guaranteed core's worker parks with
 * an empty queue, mark the core stealable instead of freeing it.  It stays owned
 * by mgr (so post_event reclaims it the instant work arrives) but becomes a
 * tier-2 candidate another app may take if it needs a core and none are free.
 * The event_count==0 / owner==mgr test under the channel wakeup_lock avoids
 * marking a core that just raced in some work.  A guaranteed core is never
 * marked — it is the app's permanent anchor.
 */
static void mark_stealable(struct event_manager *mgr, int cpu)
{
	struct event_channel *chan = mgr->channels[cpu];
	unsigned long flags;

	if (cpumask_test_cpu(cpu, &mgr->guaranteed_mask))
		return;

	spin_lock_irqsave(&core_pool.lock, flags);
	spin_lock(&chan->wakeup_lock);
	if (chan->event_count == 0 && core_pool.owner[cpu] == mgr)
		cpumask_set_cpu(cpu, &core_pool.stealable_mask);
	spin_unlock(&chan->wakeup_lock);
	spin_unlock_irqrestore(&core_pool.lock, flags);
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
 * Prefers the least-loaded core mgr owns within my_cpu's cache domain (fast
 * path: the local core if it is owned and idle); if the domain has no owned
 * core, falls back to a guaranteed core (never released, always a valid
 * target).  Reads owned/guaranteed masks lock-free — hint quality; post_event
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

		if (local && READ_ONCE(local->event_count) == 0)
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

/*
 * Discard an event that cannot be delivered because its manager owns no cores
 * (only reachable on a fully-allocated machine — see pick_target()).  Frees the
 * event, drops the manager reference the anchor holds, and frees the anchor.
 */
static void drop_anchor(struct event_anchor *anchor)
{
	pr_warn_once("upcall: manager owns no cores, dropping event\n");
	kmem_cache_free(event_cache, anchor->event);
	put_mgr(anchor->mgr);
	kmem_cache_free(anchor_cache, anchor);
}

/*
 * Congestion-driven scale-up, invoked from the event-placement path when an
 * event is queued onto a core that already has outstanding work.  Acquire one
 * core in cpu's cache domain for mgr (a free core, else steal an idle stealable
 * one) and wake its worker so the backlog drains in parallel.  Runs with IRQs
 * disabled (placement context); the lock-free pool tests avoid taking the pool
 * lock when neither tier has a candidate.
 */
static void upcall_scale_up(struct event_manager *mgr, int cpu)
{
	int claimed;

	if (cpumask_empty(&core_pool.free_mask) &&
	    cpumask_empty(&core_pool.stealable_mask))
		return;
	claimed = take_core(mgr, upcall_domain_mask(cpu));
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

	/*
	 * The softirq/poll wakeup fires on whatever CPU ran the network work,
	 * which under partitioning may not be a core this manager owns.  Choose
	 * the least-loaded core mgr owns within the local cache domain, spreading
	 * work across its owned cores (the "Shenango metric" congestion signal).
	 */
	target = pick_target(mgr, my_cpu);
	if (!target) {
		local_irq_restore(flags);
		drop_anchor(anchor);
		return;
	}

	INIT_LIST_HEAD(&anchor->anchor);

	/*
	 * Re-validate ownership under the target's wakeup_lock: if mgr released
	 * the core between pick_target() and here, owner[] no longer points at
	 * mgr and we must not enqueue (the core's worker has parked and would
	 * never drain it).  Fall back to a guaranteed core, which is never
	 * released and therefore always a valid target.
	 */
	spin_lock(&target->wakeup_lock);
	if (core_pool.owner[target->cpu] == mgr) {
		/* Congestion: the chosen (least-loaded owned) core already has
		 * outstanding events, so every owned core in this domain is busy. */
		congested = target->event_count > 0;
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
		congested = target->event_count > 0;
		list_add_tail(&anchor->anchor, &target->wakeups);
		target->event_count++;
		spin_unlock(&target->wakeup_lock);
	}

	wake_owned_worker(mgr, target->cpu);

	/* Scaling decision lives here in the placement path: if we just queued
	 * behind outstanding work, bring another core online to drain it. */
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

	if (!file)
		return 0;

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
	int cpu;

	local_irq_save(flags);
	cpu = smp_processor_id();
	channel = mgr->channels[cpu];
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

	/*
	 * We hold no work and are committed to sleeping.  If this is not a
	 * guaranteed core, mark it stealable: we keep ownership (so post_event()
	 * reclaims it the instant work arrives) but another app may take it if it
	 * needs a core and none are free.  mark_stealable() only marks when
	 * event_count is still 0 under the channel wakeup_lock, so a concurrently
	 * delivered event that reclaims us wins the race and we are not marked.
	 * A guaranteed core is kept unmarked (permanent awake-able anchor).
	 */
	mark_stealable(mgr, cpu);
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
			/*
			 * whead is NULL if the file's poll function never called
			 * poll_wait (e.g. files with no poll op return
			 * DEFAULT_POLLMASK). Nothing was added to a wait queue,
			 * so there is nothing to remove.
			 */
			if (anchor->whead)
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

static void free_manager(struct event_manager *mgr)
{
	struct event_channel *chan;
	unsigned long flags;
	int cpu;

	/*
	 * Return every core this manager still owns to the free pool — teardown is
	 * the only path that produces truly-free cores in steady state.  Cores it
	 * had marked stealable are dropped from that pool here too.
	 */
	spin_lock_irqsave(&core_pool.lock, flags);
	for_each_cpu(cpu, &mgr->owned_mask) {
		core_pool.owner[cpu] = NULL;
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

		/*
		 * Ensure the manager owns a guaranteed core in this worker's cache
		 * domain.  Done after dropping worker_lock so core_pool.lock never
		 * nests under a channel lock.  libupcall pins one worker per CPU, so
		 * every domain the app runs in gets exactly one guaranteed core; the
		 * remaining workers register their context above and park without
		 * owning a core until one is claimed for them (upcall_scale_up).
		 */
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

		// Check if we have an fd, UP_VEC doesn't need one
		if (item->fd < 0 && item->type != UP_VEC) {
			pr_err("Corrupted submission at %d of %d, bad fd(%d)\n", i, in_cnt, item->fd);
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

	kref_init(&mgr->ref_count);
	mgr->id = atomic_inc_return(&upcall_mgr_ids);

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

	mgr = create_manager();
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

/*
 * debugfs: /sys/kernel/debug/upcall/owners — one line per online CPU showing
 * which manager (if any) currently owns it, and whether that is a guaranteed
 * core.  Read under core_pool.lock; a non-NULL owner cannot be freed while the
 * lock is held (free_manager() clears owner[] under the same lock before any
 * kfree).
 */
static int upcall_owners_show(struct seq_file *s, void *v)
{
	unsigned long flags;
	int cpu;

	spin_lock_irqsave(&core_pool.lock, flags);
	for_each_online_cpu(cpu) {
		struct event_manager *mgr = core_pool.owner[cpu];

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


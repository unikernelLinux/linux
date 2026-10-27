// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Upcall event handler implementation
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/build_bug.h>
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
#include <net/sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/log2.h>
#include <linux/hash.h>
#include <linux/timekeeping.h>

#include <linux/sched.h>

struct event_channel {
	spinlock_t		event_lock;
	spinlock_t		worker_lock;
	struct list_head	event_list;
	struct list_head	sleeping_workers;
	/* Used to measure available slots in the next trip to userspace */
	size_t			event_count;
	uint32_t		cpu;
	uint8_t			pad[12];
};
/* Pad to a cacheline so each channel's hot event_lock/event_count don't
 * share a line with an adjacent channel's allocation. Only holds for the
 * perf-build config (no lockdep/debug spinlocks); catch any drift here
 * instead of silently losing the alignment. */
static_assert(sizeof(struct event_channel) == 64);

/*
 * How to run read/write on a cached fd. Resolved once when the fd is first
 * cached (see fdcache_get) so the hot path skips the read()/write() demux
 * (fdget -> f_op->read_iter -> LSM -> ops->recvmsg -> sk_prot->recvmsg) and
 * calls the protocol endpoint directly. TCP/UDP get a direct (retpoline-free)
 * call; any other socket goes through sk_prot; a non-socket fd falls back to
 * f_op->read_iter/write_iter.
 */
enum fd_io_kind {
	FD_IO_NONSOCK = 0,	/* not a socket -- use f_op->read_iter/write_iter */
	FD_IO_TCP,
	FD_IO_UDP,
	FD_IO_SOCK_OTHER,	/* socket, but not TCP/UDP -- via sk->sk_prot */
};

struct filep_cache {
	struct file	*file;	/* borrowed ref; slot empty when NULL */
	struct sock	*sk;	/* set before file is published; NULL if non-socket */
	enum fd_io_kind	kind;
};

#ifdef CONFIG_UPCALLS_STATS
struct upcall_place_stats {
	u64	local;			/* placed on the local core (fast path) */
	u64	remote_not_ours;	/* local core not owned -> spread remote */
	u64	remote_full;		/* local core owned but full -> spread remote */
	u64	lost;			/* target stolen between pick and enqueue */
};
#endif

struct event_manager {
	struct file		*file;
	struct kref		ref_count;
	struct event_channel	*channels[NR_CPUS];
	struct worker_context	*pcpu_workers[NR_CPUS];
	/* owned_mask mirrors core_pool.owner[] for lock-free reads on the
	 * delivery path; a stolen owner[] flip is serialised against
	 * post_event() by the owning channel's event_lock. guaranteed_mask
	 * (subset of owned_mask, ~1 core per LLC domain) is never released. */
	struct cpumask		owned_mask;
	struct cpumask		guaranteed_mask;
	struct cpumask		guaranteed_electing;	/* per-domain create-once token */
	atomic_t		owned_count;
	size_t			batch_size;
	/* Kept separate from batch_size -- coupling scale-up to the placement
	 * threshold caused a regression before. */
	size_t			spread_threshold;
	/* Below this completion count, do one NAPI poll budget before returning. */
	size_t			napi_poll_threshold;
	int			id;		/* small stable id for observability */
	/* fd -> cached {file, sk, io kind}; entries only clear via UP_CLOSE,
	 * the only path that closes an fd this manager touches. */
	struct filep_cache	*filep_cache;
	unsigned int		filer_cache_sz;
	/* (fd,type) -> live event_anchor, for re-arm find-or-create and teardown. */
	struct hlist_head	*anchor_hash;
	spinlock_t		anchor_lock;
#ifdef CONFIG_UPCALLS_STATS
	/* Placement observability: per-CPU to avoid bouncing a shared cacheline
	 * across every posting CPU; summed only at debugfs read. */
	struct upcall_place_stats __percpu *place_stats;
	struct dentry		*dbg;		/* /sys/kernel/debug/upcall/managers/<id> */
#endif
};

/*
 * Event placement counters: always called unconditionally from the
 * placement/submit paths; the real bodies only exist when
 * CONFIG_UPCALLS_STATS is enabled, otherwise these are no-op stubs so no
 * #ifdef is needed at any call site.
 */
#ifdef CONFIG_UPCALLS_STATS
static inline void place_stat_local(struct event_manager *mgr)
{
	this_cpu_inc(mgr->place_stats->local);
}

static inline void place_stat_remote_full(struct event_manager *mgr)
{
	this_cpu_inc(mgr->place_stats->remote_full);
}

static inline void place_stat_remote_not_ours(struct event_manager *mgr)
{
	this_cpu_inc(mgr->place_stats->remote_not_ours);
}

static inline void place_stat_lost(struct event_manager *mgr)
{
	this_cpu_inc(mgr->place_stats->lost);
}

static inline bool upcall_place_stats_alloc(struct event_manager *mgr)
{
	mgr->place_stats = alloc_percpu(struct upcall_place_stats);
	return mgr->place_stats != NULL;
}

static inline void upcall_place_stats_free(struct event_manager *mgr)
{
	free_percpu(mgr->place_stats);
}
#else
static inline void place_stat_local(struct event_manager *mgr) { }
static inline void place_stat_remote_full(struct event_manager *mgr) { }
static inline void place_stat_remote_not_ours(struct event_manager *mgr) { }
static inline void place_stat_lost(struct event_manager *mgr) { }
static inline bool upcall_place_stats_alloc(struct event_manager *mgr) { return true; }
static inline void upcall_place_stats_free(struct event_manager *mgr) { }
#endif

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
#ifdef CONFIG_UPCALLS_STATS
static struct dentry *upcall_mgr_dbg_dir;	/* .../upcall/managers */

/* Histogram of whole-syscall upcall_submit() time, log2(ns), summed at read. */
#define UPCALL_SUBMIT_BUCKETS 40
static u64 upcall_submit_hist[NR_CPUS][UPCALL_SUBMIT_BUCKETS];

static void upcall_submit_record(u64 delta)
{
	int cpu, b = delta ? ilog2(delta) : 0;

	if (b >= UPCALL_SUBMIT_BUCKETS)
		b = UPCALL_SUBMIT_BUCKETS - 1;
	cpu = get_cpu();
	upcall_submit_hist[cpu][b]++;
	put_cpu();
}

static inline u64 upcall_submit_time_start(void)
{
	return ktime_get_mono_fast_ns();
}

static inline void upcall_submit_time_end(u64 t0)
{
	upcall_submit_record(ktime_get_mono_fast_ns() - t0);
}
#else
static inline u64 upcall_submit_time_start(void) { return 0; }
static inline void upcall_submit_time_end(u64 t0) { }
#endif

/*
 * Anchor lifecycle (atomic). One-shot today: the ARMED -> QUEUED claim is won
 * by exactly one poster (the wakeup callback or the arming-path poll), after
 * which the drain recycles the anchor. IDLE (delivered, awaiting re-arm) and
 * DEAD (closing) are reserved for the persistent/teardown stages.
 */
enum anchor_state {
	ANCHOR_ARMED,
	ANCHOR_QUEUED,
	ANCHOR_IDLE,
	ANCHOR_DEAD,
};

/* Per-manager (fd,type) -> live anchor registry. Touched only at subscribe
 * and anchor free (syscall/softirq frequency, not per-packet), so one lock. */
#define UPCALL_ANCHOR_HASH_BITS	10
#define UPCALL_ANCHOR_HASH_SZ	(1u << UPCALL_ANCHOR_HASH_BITS)

struct event_anchor {
	struct list_head	anchor;
	struct up_event		event;
	struct event_manager	*mgr;
	struct file		*file;	/* own fget; resolved at build, fput at release */
	struct sock		*sk;	/* from file; NULL if non-socket */
	enum fd_io_kind		kind;
	struct hlist_node	hash_node;	/* (fd,type) registry membership */
	atomic_t		state;	/* enum anchor_state */
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
 * reinitialize every field on reuse. Every free runs through anchor_release_pool
 * in task context (drain, UP_CLOSE, teardown) -- the softirq-reachable
 * drop_anchor() only un-claims and never frees -- so preempt-disable
 * (get_cpu_var/put_cpu_var) is enough without irq-off.
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

/* anchor->refs release callback: recycle to the per-CPU pool. Only ever called
 * from task context (drain, UP_CLOSE, teardown), never from the softirq
 * post_event/drop_anchor path. */
static void anchor_release_pool(struct kref *kref);

/* Per-manager debugfs (placement counters); defined with the debugfs section.
 * Always called unconditionally -- no-op stubs when stats are disabled. */
static void upcall_mgr_debugfs_add(struct event_manager *mgr);
static void upcall_mgr_debugfs_del(struct event_manager *mgr);

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
 * under its own channel event_lock and flips owner[cpu] with cmpxchg -- the
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
			spin_lock(&vchan->event_lock);
			if (vchan->event_count == 0 &&
			    cmpxchg(&core_pool.owner[cpu], victim, mgr) == victim) {
				cpumask_clear_cpu(cpu, &victim->owned_mask);
				cpumask_set_cpu(cpu, &mgr->owned_mask);
				atomic_dec(&victim->owned_count);
				atomic_inc(&mgr->owned_count);
				spin_unlock(&vchan->event_lock);
				spin_unlock_irqrestore(&core_pool.lock, flags);
				return cpu;
			}
			spin_unlock(&vchan->event_lock);
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

	spin_lock_irqsave(&chan->event_lock, flags);
	if (chan->event_count == 0 && READ_ONCE(core_pool.owner[cpu]) == mgr)
		cpumask_set_cpu(cpu, &core_pool.stealable_mask);
	spin_unlock_irqrestore(&chan->event_lock, flags);
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
 * below mgr->batch_sz. Past that, scans the domain starting at my_cpu and
 * wrapping (not always from the domain's lowest cpu), in two passes merged
 * into one loop: prefer the first owned core that already has queued work
 * and isn't full; failing that, fall back to the first owned core seen
 * sitting completely idle. If neither exists, fall back to a guaranteed
 * core (never released, always a valid target). Reads owned/guaranteed
 * masks lock-free — hint quality; post_event re-validates the chosen core's
 * ownership under its event_lock. Returns NULL only if the manager owns no
 * cores at all (pathological, fully-allocated machine).
 */
static struct event_channel *pick_target(struct event_manager *mgr, int my_cpu)
{
	const struct cpumask *domain = upcall_domain_mask(my_cpu);
	struct event_channel *idle = NULL;
	int cpu;

	if (cpumask_test_cpu(my_cpu, &mgr->owned_mask)) {
		struct event_channel *local = mgr->channels[my_cpu];

		if (local && READ_ONCE(local->event_count) < mgr->batch_size) {
			place_stat_local(mgr);
			return local;
		}
		/* Owned but full -> spread remote. */
		place_stat_remote_full(mgr);
	} else {
		/* Local core isn't ours -> spread remote. */
		place_stat_remote_not_ours(mgr);
	}

	/* First-fit, not least-loaded: a core with event_count > 0 already has
	 * work queued (and so is very likely already running, not parked), so
	 * placing here shouldn't need wake_owned_worker() to call
	 * try_to_wake_up() on a remote core. Stop at the first match. Remember
	 * the first idle owned core we pass over so we can use it instead of
	 * the guaranteed core if the scan finds no active match. */
	for_each_cpu_wrap(cpu, domain, my_cpu) {
		struct event_channel *chan;
		size_t count;

		if (!cpumask_test_cpu(cpu, &mgr->owned_mask))
			continue;
		chan = mgr->channels[cpu];
		if (!chan)
			continue;
		count = READ_ONCE(chan->event_count);
		if (count > 0 && count < mgr->batch_size)
			return chan;
		if (count == 0 && !idle)
			idle = chan;
	}

	if (idle)
		return idle;

	cpu = cpumask_first(&mgr->guaranteed_mask);
	if (cpu < nr_cpu_ids)
		return mgr->channels[cpu];

	return NULL;
}

/* Only reachable when mgr owns no cores at all (fully-allocated machine). */
static void drop_anchor(struct event_anchor *anchor)
{
	pr_warn_once("upcall: manager owns no cores, dropping event\n");
	/* Persistent: keep the subscription (its refs, mgr ref, and wait-queue
	 * entry) and just drop this event by un-claiming, so a later wakeup or
	 * re-arm retries. Freeing here would be unsafe -- the anchor is still on
	 * the wait queue and this path can run under the waker's lock. */
	atomic_cmpxchg(&anchor->state, ANCHOR_QUEUED, ANCHOR_ARMED);
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

/*
 * Softirq-reachable: places anchor on a target channel's wakeup queue and
 * wakes its worker. May run on a CPU this manager doesn't own (NAPI softirq
 * follows the interrupt, not mgr's ownership).
 */
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
	spin_lock(&target->event_lock);
	if (READ_ONCE(core_pool.owner[target->cpu]) == mgr) {
		congested = target->event_count > mgr->spread_threshold;
		/* Queued ref: held while on the channel list and across the drain;
		 * the worker drops it. Keeps the anchor alive against a concurrent
		 * UP_CLOSE that drops the subscription ref. Taken before the anchor
		 * is visible to a draining worker. */
		kref_get(&anchor->refs);
		list_add_tail(&anchor->anchor, &target->event_list);
		target->event_count++;
		enqueued = true;
	}
	spin_unlock(&target->event_lock);

	if (!enqueued) {
		/* Chosen target was stolen between pick_target() and the lock. */
		place_stat_lost(mgr);
		gcpu = cpumask_first(&mgr->guaranteed_mask);
		if (gcpu >= nr_cpu_ids) {
			local_irq_restore(flags);
			drop_anchor(anchor);
			return;
		}
		target = mgr->channels[gcpu];
		spin_lock(&target->event_lock);
		congested = target->event_count > mgr->spread_threshold;
		kref_get(&anchor->refs);	/* queued ref (see above) */
		list_add_tail(&anchor->anchor, &target->event_list);
		target->event_count++;
		spin_unlock(&target->event_lock);
	}

	wake_owned_worker(mgr, target->cpu);

	if (congested)
		upcall_scale_up(mgr, my_cpu);

	local_irq_restore(flags);
}

/* Claim the anchor for posting: exactly one caller wins ARMED -> QUEUED. */
static inline bool anchor_claim(struct event_anchor *anchor)
{
	return atomic_cmpxchg(&anchor->state, ANCHOR_ARMED, ANCHOR_QUEUED) == ANCHOR_ARMED;
}

static int handle_poll_event(struct wait_queue_entry *wq_entry, unsigned mode,
		int flags, void *key)
{
	struct event_anchor *anchor = container_of(wq_entry, struct event_anchor, wait);
	__poll_t pollflags = key_to_poll(key);

	if (pollflags && !(pollflags & anchor->events))
		return 0;

	if (!anchor_claim(anchor))
		return 0;	/* another poster won the ARMED->QUEUED claim */

	/* Persistent waiter: the anchor stays on the wait queue across posts.
	 * The claim above gates double-posting (wakeups while QUEUED/IDLE no-op),
	 * so there is nothing to remove here. */
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

static enum fd_io_kind classify_sk(struct sock *sk)
{
	if (sk->sk_prot->recvmsg == tcp_recvmsg)
		return FD_IO_TCP;
	if (sk->sk_prot->recvmsg == udp_recvmsg)
		return FD_IO_UDP;
	return FD_IO_SOCK_OTHER;
}

/*
 * Returns the cache entry for fd (file reference borrowed -- callers must
 * never fput() it), or NULL. On the first lookup the fd's socket and I/O kind
 * are resolved and stored before the file pointer is published, so any reader
 * that sees entry->file also sees a consistent sk/kind. fdcache_invalidate()
 * runs before close_fd() actually closes the fd, so a lookup never observes a
 * stale pointer.
 */
static struct filep_cache *fdcache_get(struct event_manager *mgr, int fd)
{
	struct filep_cache *e;
	struct file *file, *raced;
	struct socket *sock;

	if (fd < 0 || (unsigned int)fd >= mgr->filer_cache_sz)
		return NULL;

	e = &mgr->filep_cache[fd];
	if (smp_load_acquire(&e->file))
		return e;

	file = fget(fd);
	if (!file)
		return NULL;

	sock = sock_from_file(file);
	if (sock && sock->sk) {
		e->sk = sock->sk;
		e->kind = classify_sk(sock->sk);
	} else {
		e->sk = NULL;
		e->kind = FD_IO_NONSOCK;
	}

	/* Publish file last (cmpxchg is a full barrier) so the sk/kind stores
	 * above are visible to any reader that observes e->file. A racing filler
	 * resolves the same fd to identical sk/kind, so the loser's stores are
	 * harmless. */
	raced = cmpxchg(&e->file, NULL, file);
	if (raced)
		fput(file);	/* someone published first; drop our extra ref */
	return e;
}

/* Called before close_fd() so no lookup can observe a stale cached file. */
static void fdcache_invalidate(struct event_manager *mgr, int fd)
{
	struct file *file;

	if (fd < 0 || (unsigned int)fd >= mgr->filer_cache_sz)
		return;

	file = xchg(&mgr->filep_cache[fd].file, NULL);
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

/*
 * One recvmsg into base[0..len). TCP/UDP are called directly (no retpoline);
 * any other socket goes through sk_prot. The protocol manages its own socket
 * locking.
 */
static int sock_recv_one(struct sock *sk, enum fd_io_kind kind, void *base, size_t len, int flags)
{
	struct msghdr msg = {};
	int addr_len = 0;

	iov_iter_ubuf(&msg.msg_iter, ITER_DEST, base, len);

	switch (kind) {
	case FD_IO_TCP:
		return tcp_recvmsg(sk, &msg, len, flags, &addr_len);
	case FD_IO_UDP:
		return udp_recvmsg(sk, &msg, len, flags, &addr_len);
	default:
		return sk->sk_prot->recvmsg(sk, &msg, len, flags, &addr_len);
	}
}

/* One sendmsg from base[0..len); flags travel in msg_flags (MSG_DONTWAIT). */
static int sock_send_one(struct sock *sk, enum fd_io_kind kind, void *base, size_t len, int flags)
{
	struct msghdr msg = { .msg_flags = flags };

	iov_iter_ubuf(&msg.msg_iter, ITER_SOURCE, base, len);

	switch (kind) {
	case FD_IO_TCP:
		return tcp_sendmsg(sk, &msg, len);
	case FD_IO_UDP:
		return udp_sendmsg(sk, &msg, len);
	default:
		return sk->sk_prot->sendmsg(sk, &msg, len);
	}
}

static void try_read(struct event_anchor *anchor)
{
	struct up_event *evt = &anchor->event;
	struct file *file = anchor->file;
	struct kiocb kiocb;
	struct iov_iter iter;
	struct iovec iov;
	size_t cursor = 0;
	int flags, ret;

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

	flags = (file->f_flags & O_NONBLOCK) ? MSG_DONTWAIT : 0;
	init_sync_kiocb(&kiocb, file);

	while (cursor < iov.iov_len) {
		if (anchor->kind == FD_IO_NONSOCK) {
			iov_iter_ubuf(&iter, ITER_DEST, iov.iov_base + cursor,
				      iov.iov_len - cursor);
			ret = file->f_op->read_iter(&kiocb, &iter);
		} else {
			ret = sock_recv_one(anchor->sk, anchor->kind,
					    iov.iov_base + cursor,
					    iov.iov_len - cursor, flags);
		}

		if (ret <= 0) {
			/* Report bytes already read on this call, not the error/EAGAIN
			 * that stopped it -- discarding them here would silently drop
			 * data for payloads that span multiple reads. */
			evt->result = cursor > 0 ? cursor : ret;
			return;
		}
		cursor += ret;
	}

	evt->result = cursor;
}

static void try_write(struct event_anchor *anchor)
{
	struct up_event *evt = &anchor->event;
	struct file *file = anchor->file;
	struct kiocb kiocb;
	struct iov_iter iter;
	struct iovec iov;
	size_t cursor = 0;
	int flags, ret;

	if (!file) {
		evt->result = -EBADF;
		return;
	}

	iov.iov_base = evt->buf;
	iov.iov_len = evt->len;

	flags = (file->f_flags & O_NONBLOCK) ? MSG_DONTWAIT : 0;
	init_sync_kiocb(&kiocb, file);

	while (cursor < iov.iov_len) {
		if (anchor->kind == FD_IO_NONSOCK) {
			iov_iter_ubuf(&iter, ITER_SOURCE, iov.iov_base + cursor,
				      iov.iov_len - cursor);
			ret = file->f_op->write_iter(&kiocb, &iter);
		} else {
			ret = sock_send_one(anchor->sk, anchor->kind,
					    iov.iov_base + cursor,
					    iov.iov_len - cursor, flags);
		}

		if (ret <= 0) {
			/* Report bytes already written on this call, not the error/EAGAIN
			 * that stopped it -- same reasoning as try_read(). */
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
	struct file *file = anchor->file;
	poll_table *pt = &anchor->pt;
	__poll_t res;

	if (!file)
		return 0;

	anchor->events = pt->_key = events;
	res = vfs_poll(file, pt);

	return res & events;
}

static void mark_handled_events(struct event_manager *mgr, unsigned int cnt)
{
	unsigned long flags;
	struct event_channel *channel;

	local_irq_save(flags);
	channel = get_event_channel(mgr);
	scoped_guard(spinlock, &channel->event_lock) {
		channel->event_count -= cnt;
	}
	local_irq_restore(flags);
}

static struct event_anchor *get_next_wakeup(struct event_manager *mgr)
{
	unsigned long flags;
	struct event_channel *channel;
	struct event_anchor *anchor;

	local_irq_save(flags);
	channel = get_event_channel(mgr);
	scoped_guard(spinlock, &channel->event_lock) {
		anchor = list_first_entry_or_null(&channel->event_list, struct event_anchor, anchor);
		if (!anchor)
			goto out;
		list_del_init(&anchor->anchor);
	}
out:
	local_irq_restore(flags);
	return anchor;
}

/* Park the calling worker until an event arrives or a spurious wakeup
 * retries. Re-checks event_count under lock immediately before parking to
 * close the race with a concurrent post_event(). */
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
	spin_lock(&channel->event_lock);
	if (channel->event_count > 0) {
		spin_unlock(&channel->event_lock);
		spin_unlock(&channel->worker_lock);
		local_irq_restore(flags);
		goto out;
	}
	spin_unlock(&channel->event_lock);

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
	/* Running again: no longer a steal candidate (symmetric with the
	 * mark_stealable() on the way to sleep). */
	cpumask_clear_cpu(cpu, &core_pool.stealable_mask);
	local_irq_restore(flags);
out:
	return;
}

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

static inline unsigned int anchor_bucket(int fd)
{
	return hash_32((u32)fd, UPCALL_ANCHOR_HASH_BITS);
}

static void anchor_insert(struct event_manager *mgr, struct event_anchor *anchor)
{
	unsigned long flags;

	spin_lock_irqsave(&mgr->anchor_lock, flags);
	hlist_add_head(&anchor->hash_node,
		       &mgr->anchor_hash[anchor_bucket(anchor->event.fd)]);
	spin_unlock_irqrestore(&mgr->anchor_lock, flags);
}

/* Find the live anchor for (fd,type) and take a reference so the caller can use
 * it safely against a concurrent close that drops the subscription ref. Caller
 * must kref_put(anchor_release_pool) when done. */
static struct event_anchor *anchor_lookup(struct event_manager *mgr,
					  int fd, int type)
{
	struct event_anchor *a;
	unsigned long flags;
	struct event_anchor *found = NULL;

	spin_lock_irqsave(&mgr->anchor_lock, flags);
	hlist_for_each_entry(a, &mgr->anchor_hash[anchor_bucket(fd)], hash_node) {
		if (a->event.fd == fd && a->event.type == type) {
			kref_get(&a->refs);
			found = a;
			break;
		}
	}
	spin_unlock_irqrestore(&mgr->anchor_lock, flags);
	return found;
}

/*
 * Tear down every (fd, *) subscription at UP_CLOSE, before close_fd() drops the
 * fd. Under anchor_lock, mark each matching anchor DEAD (this gates
 * handle_poll_event's ARMED->QUEUED claim, so no new event posts, and makes the
 * drain suppress any event already in flight) and unhash it, re-chaining it onto
 * a local list via the now-free hash_node. After dropping the lock -- so we are
 * not under the waker's whead->lock -- detach from the wait queue and drop the
 * subscription ref. A queued ref may still keep the anchor alive until a
 * draining worker sees DEAD and releases it; the last ref frees it.
 */
static void close_fd_anchors(struct event_manager *mgr, int fd)
{
	struct event_anchor *a;
	struct hlist_node *tmp;
	unsigned long flags;
	HLIST_HEAD(dying);

	spin_lock_irqsave(&mgr->anchor_lock, flags);
	hlist_for_each_entry_safe(a, tmp,
				  &mgr->anchor_hash[anchor_bucket(fd)], hash_node) {
		if (a->event.fd != fd)
			continue;
		atomic_set(&a->state, ANCHOR_DEAD);
		hlist_del(&a->hash_node);
		hlist_add_head(&a->hash_node, &dying);
	}
	spin_unlock_irqrestore(&mgr->anchor_lock, flags);

	hlist_for_each_entry_safe(a, tmp, &dying, hash_node) {
		hlist_del(&a->hash_node);
		if (a->whead)
			remove_wait_queue(a->whead, &a->wait);
		kref_put(&a->refs, anchor_release_pool);	/* drop subscription ref */
	}
}

/*
 * Final free, once both refs (subscription + any queued) are gone. The closer
 * (close_fd_anchors / manager teardown) has already removed the anchor from the
 * hash and the wait queue before the last ref could drop, so there is no hash
 * work here. Runs in task context (drain or UP_CLOSE), so the per-CPU pool and
 * put_mgr()'s possible free_manager() are both safe.
 */
static void anchor_release_pool(struct kref *kref)
{
	struct event_anchor *anchor = container_of(kref, struct event_anchor, refs);

	put_mgr(anchor->mgr);
	if (anchor->file)
		fput(anchor->file);
	anchor_pool_put(anchor);
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
	anchor->event = *evt;	/* embedded copy; input stays owned by the caller */

	/* The anchor owns its own file reference for its entire lifetime, so the
	 * drain path (try_*) and poll can use anchor->file/sk without racing a
	 * concurrent fdcache invalidate/close. fput happens at anchor release. */
	anchor->file = fget(evt->fd);
	if (!anchor->file) {
		kmem_cache_free(anchor_cache, anchor);
		return NULL;
	}
	{
		struct socket *sock = sock_from_file(anchor->file);

		if (sock && sock->sk) {
			anchor->sk = sock->sk;
			anchor->kind = classify_sk(sock->sk);
		} else {
			anchor->sk = NULL;
			anchor->kind = FD_IO_NONSOCK;
		}
	}

	INIT_LIST_HEAD(&anchor->anchor);
	INIT_LIST_HEAD(&anchor->wait.entry);
	anchor->whead = NULL;	/* set by upcall_poll_init; keeps the close guard honest */
	anchor->mgr = mgr;
	kref_get(&mgr->ref_count);
	atomic_set(&anchor->state, ANCHOR_ARMED);
	/*
	 * One "subscription" reference: the anchor lives from first subscribe
	 * until teardown (UP_CLOSE / manager exit, stage 5). Delivery moves it to
	 * IDLE and re-arm back to ARMED -- it is never recycled per event.
	 */
	kref_init(&anchor->refs);
	anchor_insert(mgr, anchor);
	return anchor;
}

static void attach_buffers(uint64_t cnt, struct iovec __user *bufs)
{
	struct worker_context *ctx = current->worker_context;
	struct event_buffer *buf;

	for (uint64_t i = 0; i < cnt; i++) {
		buf = kmem_cache_alloc(buffer_cache, GFP_KERNEL);
		if (!buf) {
			pr_warn("Failed to allocate buffer cached object, dropping remaining buffers");
			return;
		}
		INIT_LIST_HEAD(&buf->anchor);
		if (copy_from_user(&buf->iovec, &bufs[i], sizeof(struct iovec))) {
			kmem_cache_free(buffer_cache, buf);
			return;
		}
		list_add(&buf->anchor, &ctx->buffers);
	}
}

static int attach_poll(struct event_manager *mgr, struct up_event *evt, __poll_t rdw)
{
	struct event_anchor *anchor;

	/* Re-arm an existing (fd,type) subscription if one is live. anchor_lookup
	 * returns with a reference held; drop it before returning. */
	anchor = anchor_lookup(mgr, evt->fd, evt->type);
	if (anchor) {
		int rc = 0;

		/* Valid only from IDLE: a non-IDLE anchor is still armed or has an
		 * event in flight, so refreshing its payload would race the drain. */
		if (atomic_read(&anchor->state) != ANCHOR_IDLE) {
			rc = -EBUSY;
		} else {
			/* Refresh payload while IDLE (no concurrent reader), then
			 * publish ARMED (the cmpxchg is the release) so a claimer
			 * sees it whole. */
			anchor->event = *evt;
			if (atomic_cmpxchg(&anchor->state, ANCHOR_IDLE, ANCHOR_ARMED) != ANCHOR_IDLE) {
				rc = -EBUSY;	/* raced a teardown; drop the re-arm */
			} else if (vfs_poll(anchor->file, NULL) & anchor->events) {
				/* Re-check readiness WITHOUT re-adding to the wait
				 * queue (already registered): vfs_poll(file, NULL)
				 * polls without poll_wait(). Closes the
				 * delivered-then-ready-before-rearm stranding window. */
				if (anchor_claim(anchor))
					post_event(anchor);
			}
		}
		kref_put(&anchor->refs, anchor_release_pool);	/* drop lookup ref */
		return rc;
	}

	/* First subscribe: build, register on the wait queue, post if ready. */
	anchor = build_anchor(mgr, evt);
	if (!anchor)
		return -ENOMEM;

	init_poll_funcptr(&anchor->pt, upcall_poll_init);
	if (upcall_item_poll(anchor, rdw | EPOLLERR | EPOLLHUP | EPOLLPRI)) {
		/* Stays on the wait queue (persistent); the claim gates posting. */
		if (anchor_claim(anchor))
			post_event(anchor);
	}

	return 0;
}

/*
 * Two phases: arm every input (attach_poll/attach_buffers/UP_CLOSE), then
 * drain up to out_cnt completions. The drain loop (`again:`) can re-enter
 * itself via busy-poll or worker_sleep when nothing is ready yet, so it
 * only returns once it has output, has slept, or the caller asked for
 * nothing (out_cnt == 0).
 */
static int do_upcall_submit(struct event_manager *mgr, int in_cnt,
		struct up_event **in, int out_cnt, struct up_event *out)
{
	unsigned int out_idx = 0;
	unsigned int drained = 0;	/* anchors popped off the channel this call */
	int ret = 0;
	int last_fd = -1;
	int presleep_fd = -1;		/* first readable arm: queue to poll before sleeping */
	bool polled = false;
	bool presleep_polled = false;
	struct event_anchor *anchor;

	for (int i = 0; i < in_cnt; i++) {
		ret = 0;
		switch (in[i]->type) {
		case UP_VEC:
			attach_buffers(in[i]->len, (struct iovec*)in[i]->buf);
			break;

		case UP_ACCEPT:
		case UP_READ:
			/* Remember the first readable fd so the pre-sleep poll below
			 * knows which RX queue we're waiting on. */
			if (presleep_fd < 0)
				presleep_fd = in[i]->fd;
			ret = attach_poll(mgr, in[i], EPOLLIN | POLLRDNORM);
			break;

		case UP_WRITE:
			ret = attach_poll(mgr, in[i], EPOLLOUT | POLLWRNORM);
			break;

		case UP_CLOSE:
			close_fd_anchors(mgr, in[i]->fd);
			fdcache_invalidate(mgr, in[i]->fd);
			ret = close_fd(in[i]->fd);
			break;

		default:
			ret = -EINVAL;
			break;
		};
		/* build_anchor() copied the event; the input array stays owned by
		 * the syscall wrapper, which frees every kitems[] entry uniformly. */

		/* A failed arm is terminal for that input: report it as a completion
		 * carrying the errno (result < 0) so the app learns exactly which
		 * input failed, rather than aborting the whole batch on the first
		 * error. Written in the arm phase, before any drained completion, so
		 * errors take the out[] slots ahead of ready events. */
		if (ret < 0 && out_idx < out_cnt) {
			out[out_idx] = *in[i];
			out[out_idx].result = ret;
			out_idx++;
		}
	}

again:
	while (out_idx < out_cnt) {
		anchor = get_next_wakeup(mgr);
		if (!anchor)
			break;
		drained++;	/* popped off the channel; event_count owes a decrement */

		/* Closing: a concurrent UP_CLOSE marked it DEAD. Suppress -- no I/O,
		 * no delivery -- and drop the queued ref (may free it now). */
		if (atomic_read(&anchor->state) == ANCHOR_DEAD) {
			kref_put(&anchor->refs, anchor_release_pool);
			continue;
		}

		switch (anchor->event.type) {
		case UP_READ:
			try_read(anchor);
			break;
		case UP_WRITE:
			try_write(anchor);
			break;
		case UP_ACCEPT:
			try_accept(&anchor->event);
			break;
		default:
			kref_put(&anchor->refs, anchor_release_pool);
			mark_handled_events(mgr, drained);
			return -EINVAL;
		}
		/* Deliver iff still ours: QUEUED -> IDLE. A close that raced in
		 * during try_* set DEAD, so the cmpxchg fails and we suppress the
		 * now-stale event. Copy out by value before dropping the ref. */
		if (atomic_cmpxchg(&anchor->state, ANCHOR_QUEUED, ANCHOR_IDLE) == ANCHOR_QUEUED) {
			out[out_idx] = anchor->event;
			last_fd = anchor->event.fd;
			out_idx++;
		}
		kref_put(&anchor->refs, anchor_release_pool);	/* drop queued ref */
	}

	if (!polled && out_idx > 0 && (size_t)out_idx < mgr->napi_poll_threshold) {
		struct filep_cache *e = fdcache_get(mgr, last_fd);
		struct sock *sk = e ? e->sk : NULL;

		polled = true;
		if (sk) {
			unsigned int napi_id = READ_ONCE(sk->sk_napi_id);

			if (napi_id_valid(napi_id))
				napi_busy_loop(napi_id, NULL, NULL, false, BUSY_POLL_BUDGET);
		}
		goto again;
	}

	if (!out_idx && out_cnt > 0) {
		/*
		 * About to sleep with nothing ready. Do one busy-poll pass on the
		 * RX queue of a connection we're waiting on (presleep_fd) first: a
		 * packet may already be sitting in that ring unprocessed. The poll
		 * runs the full stack, and sk_data_ready() posts any resulting event
		 * into our channel, so the re-drain finds it and we skip the
		 * sleep/softirq-wake round trip. napi_busy_loop polls the whole NAPI
		 * instance, so siblings on the same queue are drained too. One pass
		 * per sleep attempt (presleep_polled), then actually sleep.
		 */
		if (!presleep_polled && presleep_fd >= 0) {
			struct filep_cache *e = fdcache_get(mgr, presleep_fd);
			struct sock *sk = e ? e->sk : NULL;

			presleep_polled = true;
			if (sk) {
				unsigned int napi_id = READ_ONCE(sk->sk_napi_id);

				if (napi_id_valid(napi_id))
					napi_busy_loop(napi_id, NULL, NULL, false, BUSY_POLL_BUDGET);
			}
			goto again;
		}

		worker_sleep(mgr);
		presleep_polled = false;	/* fresh poll allowed on the next sleep */
		goto again;
	}

	/* Decrement by anchors actually dequeued, not out_idx: the latter also
	 * counts arm-phase error reports (never on the channel) and omits
	 * DEAD-skipped / suppressed pops (dequeued but not delivered). */
	mark_handled_events(mgr, drained);

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
		kfree(chan);
	}

	/* Release any fds this manager never got an explicit UP_CLOSE for
	 * (app exit without draining every connection). */
	for (unsigned int i = 0; i < mgr->filer_cache_sz; i++) {
		if (mgr->filep_cache[i].file)
			fput(mgr->filep_cache[i].file);
	}
	vfree(mgr->filep_cache);
	kfree(mgr->anchor_hash);

	upcall_mgr_debugfs_del(mgr);	/* blocks readers before we free place_stats */
	upcall_place_stats_free(mgr);
	kfree(mgr);
}

static void free_manager_kref(struct kref *kref)
{
	struct event_manager *mgr = container_of(kref, struct event_manager, ref_count);
	free_manager(mgr);
}

/*
 * Manager teardown. Runs from the upcall fd's .release, so no new upcall_submit
 * can start and -- because the syscall holds the fd across its whole run -- none
 * is mid-drain. Reclaims every anchor the app never UP_CLOSE'd, plus any event
 * still queued on a channel that no worker drained. Each anchor holds a mgr ref
 * (build_anchor), so this MUST precede the base-ref put below: free_manager
 * cannot run until these releases drop the last anchor's mgr ref.
 *
 * Phase A fences softirqs (set DEAD so handle_poll_event's claim fails, then
 * remove_wait_queue) and drops the subscription ref. Phase B, now that every
 * anchor is off its wait queue and DEAD (so no post can arrive), drops the
 * queued refs left on the channel lists. An anchor holding both refs is freed
 * by whichever drop is last.
 */
static void teardown_anchors(struct event_manager *mgr)
{
	struct event_anchor *a;
	struct hlist_node *tmp;
	unsigned long flags;
	HLIST_HEAD(dying);

	spin_lock_irqsave(&mgr->anchor_lock, flags);
	for (unsigned int b = 0; b < UPCALL_ANCHOR_HASH_SZ; b++) {
		hlist_for_each_entry_safe(a, tmp, &mgr->anchor_hash[b], hash_node) {
			atomic_set(&a->state, ANCHOR_DEAD);
			hlist_del(&a->hash_node);
			hlist_add_head(&a->hash_node, &dying);
		}
	}
	spin_unlock_irqrestore(&mgr->anchor_lock, flags);

	hlist_for_each_entry_safe(a, tmp, &dying, hash_node) {
		hlist_del(&a->hash_node);
		if (a->whead)
			remove_wait_queue(a->whead, &a->wait);
		kref_put(&a->refs, anchor_release_pool);	/* subscription ref */
	}

	for (int cpu = 0; cpu < NR_CPUS; cpu++) {
		struct event_channel *chan = mgr->channels[cpu];

		if (!chan)
			continue;
		for (;;) {
			spin_lock_irqsave(&chan->event_lock, flags);
			a = list_first_entry_or_null(&chan->event_list,
						     struct event_anchor, anchor);
			if (a)
				list_del_init(&a->anchor);
			spin_unlock_irqrestore(&chan->event_lock, flags);
			if (!a)
				break;
			kref_put(&a->refs, anchor_release_pool);	/* queued ref */
		}
	}
}

static int upcall_tear_down(struct inode *inode, struct file *file)
{
	struct event_manager *mgr = file->private_data;
	if (mgr) {
		teardown_anchors(mgr);
		kref_put(&mgr->ref_count, free_manager_kref);
	}
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

static struct event_channel *create_channel(void)
{
	struct event_channel *ret = kzalloc(sizeof(struct event_channel), GFP_KERNEL);

	if (!ret)
		return ret;

	INIT_LIST_HEAD(&ret->event_list);
	INIT_LIST_HEAD(&ret->sleeping_workers);
	spin_lock_init(&ret->event_lock);
	spin_lock_init(&ret->worker_lock);

	return ret;
}

SYSCALL_DEFINE5(upcall_submit, int, upfd, int, in_cnt, struct up_event __user *, in,
		int, out_cnt, struct up_event __user *, output)
{
	struct event_manager *mgr = NULL;
	struct up_event **kitems = NULL;
	struct up_event *koutput = NULL;
	int ret = -EINVAL;
	int cnt;
	struct worker_context *ctx;
	unsigned long flags;
	u64 t0 = upcall_submit_time_start();

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
	koutput = kzalloc(sizeof(struct up_event) * out_cnt, GFP_KERNEL);
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
		if (!reg_channel) {
			reg_channel = create_channel();
			mgr->channels[reg_cpu] = reg_channel;
		}
		spin_lock(&reg_channel->worker_lock);
		/* Assumes one worker thread per CPU. If a second task ever registers
		 * here, this slot already belongs to the first, so this ctx never
		 * gets published to pcpu_workers[]; wake_owned_worker() only ever
		 * targets the published ctx, so the second task's own parks
		 * (worker_sleep) would never be woken by it. */
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
		if (copy_to_user(&output[i], &koutput[i], sizeof(struct up_event))) {
			ret = -EFAULT;
			goto out_clean;
		}
	}

	ret = cnt;
out_clean:
	/* Inputs are copied into anchors by build_anchor(), never transferred,
	 * so free every input event here. koutput is a plain value buffer. */
	clean_kitems(in_cnt, kitems);
out_free:
	kfree(kitems);
	kfree(koutput);
out:
	upcall_submit_time_end(t0);
	return ret;
}

static struct event_manager *create_manager(void)
{
	int i;
	struct event_manager *mgr;

	mgr = kzalloc(sizeof(struct event_manager), GFP_KERNEL);
	if (!mgr)
		return mgr;

	/* An fd beyond this just falls back to uncached (-EBADF). */
	mgr->filer_cache_sz = FD_CACHE_SIZE;
	mgr->filep_cache = vzalloc(mgr->filer_cache_sz * sizeof(struct filep_cache));
	if (!mgr->filep_cache)
		goto out_free;

	mgr->anchor_hash = kcalloc(UPCALL_ANCHOR_HASH_SZ, sizeof(struct hlist_head),
				   GFP_KERNEL);
	if (!mgr->anchor_hash)
		goto out_free;
	spin_lock_init(&mgr->anchor_lock);

	if (!upcall_place_stats_alloc(mgr))
		goto out_free;

	kref_init(&mgr->ref_count);
	mgr->id = atomic_inc_return(&upcall_mgr_ids);
	upcall_mgr_debugfs_add(mgr);

	return mgr;

out_free:
	for_each_online_cpu(i) {
		kfree(mgr->channels[i]);
	}
	vfree(mgr->filep_cache);
	kfree(mgr->anchor_hash);
	upcall_place_stats_free(mgr);
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
	mgr->spread_threshold = batch_sz - 2;
	mgr->napi_poll_threshold = batch_sz / 2;

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

#ifdef CONFIG_UPCALLS_STATS
/* debugfs: /sys/kernel/debug/upcall/submit_ns -- whole-syscall upcall_submit()
 * time histogram.  Read dumps "upper_ns count" log2 buckets; any write resets. */
static int upcall_submit_show(struct seq_file *s, void *v)
{
	u64 sum[UPCALL_SUBMIT_BUCKETS] = {0};
	int cpu, b;

	for_each_possible_cpu(cpu)
		for (b = 0; b < UPCALL_SUBMIT_BUCKETS; b++)
			sum[b] += upcall_submit_hist[cpu][b];
	for (b = 0; b < UPCALL_SUBMIT_BUCKETS; b++)
		if (sum[b])
			seq_printf(s, "%llu %llu\n", 1ULL << (b + 1), sum[b]);
	return 0;
}

static int upcall_submit_open(struct inode *inode, struct file *file)
{
	return single_open(file, upcall_submit_show, NULL);
}

static ssize_t upcall_submit_write(struct file *file, const char __user *ubuf,
				   size_t len, loff_t *off)
{
	memset(upcall_submit_hist, 0, sizeof(upcall_submit_hist));
	return len;
}

static const struct file_operations upcall_submit_fops = {
	.owner		= THIS_MODULE,
	.open		= upcall_submit_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= upcall_submit_write,
};

/* debugfs: /sys/kernel/debug/upcall/managers/<id> -- per-manager placement. */
static int upcall_mgr_show(struct seq_file *s, void *v)
{
	struct event_manager *mgr = s->private;
	u64 local = 0, not_ours = 0, full = 0, lost = 0;
	int cpu;

	for_each_possible_cpu(cpu) {
		struct upcall_place_stats *st = per_cpu_ptr(mgr->place_stats, cpu);

		local    += st->local;
		not_ours += st->remote_not_ours;
		full     += st->remote_full;
		lost     += st->lost;
	}
	seq_printf(s, "local            %llu\n", (unsigned long long)local);
	seq_printf(s, "remote_not_ours  %llu\n", (unsigned long long)not_ours);
	seq_printf(s, "remote_full      %llu\n", (unsigned long long)full);
	seq_printf(s, "place_lost       %llu\n", (unsigned long long)lost);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(upcall_mgr);

static void upcall_mgr_debugfs_add(struct event_manager *mgr)
{
	char name[16];

	if (!upcall_mgr_dbg_dir)
		return;
	snprintf(name, sizeof(name), "%d", mgr->id);
	mgr->dbg = debugfs_create_file(name, 0444, upcall_mgr_dbg_dir, mgr,
				       &upcall_mgr_fops);
}

static void upcall_mgr_debugfs_del(struct event_manager *mgr)
{
	debugfs_remove(mgr->dbg);	/* blocks on active readers; safe before kfree */
	mgr->dbg = NULL;
}

static void upcall_stats_debugfs_init(struct dentry *parent)
{
	debugfs_create_file("submit_ns", 0644, parent, NULL, &upcall_submit_fops);
	upcall_mgr_dbg_dir = debugfs_create_dir("managers", parent);
}
#else
static void upcall_mgr_debugfs_add(struct event_manager *mgr) { }
static void upcall_mgr_debugfs_del(struct event_manager *mgr) { }
static void upcall_stats_debugfs_init(struct dentry *parent) { }
#endif /* CONFIG_UPCALLS_STATS */

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
	upcall_stats_debugfs_init(upcall_debugfs_dir);

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

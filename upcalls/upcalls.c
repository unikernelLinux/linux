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
	/* napi_id of the RX ring that last delivered to this channel; the
	 * busy-poll target in do_upcall_submit() (0 == none seen yet). */
	uint32_t		napi_id;
	uint8_t			pad[8];
};
/* Pad to a cacheline so each channel's hot event_lock/event_count don't
 * share a line with an adjacent channel's allocation. Only holds for the
 * perf-build config (no lockdep/debug spinlocks); catch any drift here
 * instead of silently losing the alignment. */
static_assert(sizeof(struct event_channel) == 64);

/*
 * A channel's event_list is a FIFO of these fixed-capacity batches, not a flat
 * anchor list: the tail batch accumulates anchors until it hits batch_size
 * (sealed) and a fresh tail starts; a drainer/hunter claims one whole batch at
 * a time (O(1) detach). The last batch is kept resident when empty so trickle
 * load doesn't churn the slab. Protected by the owning channel's event_lock.
 */
struct event_batch {
	struct list_head	node;		/* link in channel->event_list */
	struct list_head	anchors;	/* anchors in this batch, FIFO */
	unsigned int		count;		/* anchors currently in `anchors` */
	bool			closed;		/* no more enqueues: hit batch_size, or claimed */
};

/*
 * How to run read/write on a socket fd. Resolved once when an anchor is first
 * built (see build_anchor) so the hot path skips the read()/write() demux
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

#ifdef CONFIG_UPCALLS_STATS
/*
 * Pull-model runtime stats, per manager per cpu: this_cpu_inc on the hot path
 * (no cross-cpu bouncing), summed/printed only at debugfs read. dwell[] is the
 * completion-dwell histogram -- claim (ARMED->QUEUED) to in-kernel delivery
 * (QUEUED->IDLE) -- in log2(ns) buckets.
 */
#define UPCALL_DWELL_BUCKETS 40
struct upcall_stats {
	u64	hunts_attempted;	/* hunt_claim() calls (own channel empty) */
	u64	hunts_succeeded;	/* hunts that moved a sibling batch */
	u64	stolen_events;		/* anchors pulled across cpus by hunts */
	u64	seals;			/* batches filled (scale-up trigger) */
	u64	scale_up_woke;		/* scale-up acquired a core */
	u64	scale_up_nocore;	/* scale-up wanted a core, none free/stealable */
	u64	local_wakes;		/* a post woke a parked local worker */
	u64	worker_sleeps;		/* a worker parked (domain empty) */
	u64	backstop_hits;		/* cross-domain guaranteed-core backstop fired */
	u64	local_arrivals;		/* local post_event()s on this cpu (monotonic) */
	u64	jitter_steals;		/* steals during which own channel got a local arrival */
	u64	idle_steals;		/* steals during which own channel stayed empty */
	u64	dwell[UPCALL_DWELL_BUCKETS];	/* claim->delivery, log2(ns) */
	u64	sleep[UPCALL_DWELL_BUCKETS];	/* worker parked interval, log2(ns) */
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
	/* Below this completion count, do one NAPI poll budget before returning. */
	size_t			napi_poll_threshold;
	int			id;		/* small stable id for observability */
	/* (fd,type) -> live event_anchor, for re-arm find-or-create and teardown. */
	struct hlist_head	*anchor_hash;
	spinlock_t		anchor_lock;
	/* Per-domain hint: domain_hint[domain_id] is the set of CPUs in that
	 * domain whose channel currently holds claimable work. Idle workers read
	 * it to find a batch to steal (Stage 3); maintained via atomic bitops as
	 * channels transition empty<->non-empty. Sized upcall_nr_domains. */
	struct cpumask		*domain_hint;
#ifdef CONFIG_UPCALLS_STATS
	struct upcall_stats __percpu *stats;
	struct dentry		*dbg;	/* /sys/kernel/debug/upcall/managers/<id> */
#endif
};

/*
 * Stat helpers: no-op stubs when CONFIG_UPCALLS_STATS is off, so call sites
 * never need an #ifdef. All use this_cpu_* (preempt-safe, local cpu only).
 */
#ifdef CONFIG_UPCALLS_STATS
static inline void stat_hunt_attempt(struct event_manager *mgr)
{ this_cpu_inc(mgr->stats->hunts_attempted); }
static inline void stat_hunt_success(struct event_manager *mgr, unsigned int n)
{ this_cpu_inc(mgr->stats->hunts_succeeded); this_cpu_add(mgr->stats->stolen_events, n); }
static inline void stat_seal(struct event_manager *mgr)
{ this_cpu_inc(mgr->stats->seals); }
static inline void stat_scale_up(struct event_manager *mgr, bool woke)
{ if (woke) this_cpu_inc(mgr->stats->scale_up_woke); else this_cpu_inc(mgr->stats->scale_up_nocore); }
static inline void stat_local_wake(struct event_manager *mgr)
{ this_cpu_inc(mgr->stats->local_wakes); }
static inline void stat_sleep(struct event_manager *mgr)
{ this_cpu_inc(mgr->stats->worker_sleeps); }
static inline void stat_backstop(struct event_manager *mgr)
{ this_cpu_inc(mgr->stats->backstop_hits); }
static inline void stat_local_arrival(struct event_manager *mgr)
{ this_cpu_inc(mgr->stats->local_arrivals); }
static inline u64 stat_local_arrivals_read(struct event_manager *mgr)
{ return this_cpu_read(mgr->stats->local_arrivals); }
/* Classify a completed steal: if our own channel took a local arrival between
 * `snapshot` (grabbed when we found it empty) and now, we raided a sibling in
 * the sub-us gap before our own next packet -- jitter, not real idle. */
static inline void stat_steal_class(struct event_manager *mgr, u64 snapshot)
{
	if (this_cpu_read(mgr->stats->local_arrivals) > snapshot)
		this_cpu_inc(mgr->stats->jitter_steals);
	else
		this_cpu_inc(mgr->stats->idle_steals);
}
static inline void stat_sleep_hist(struct event_manager *mgr, u64 ns)
{
	int b = ns ? ilog2(ns) : 0;

	if (b >= UPCALL_DWELL_BUCKETS)
		b = UPCALL_DWELL_BUCKETS - 1;
	this_cpu_inc(mgr->stats->sleep[b]);
}
static inline bool upcall_stats_alloc(struct event_manager *mgr)
{ mgr->stats = alloc_percpu(struct upcall_stats); return mgr->stats != NULL; }
static inline void upcall_stats_free(struct event_manager *mgr)
{ free_percpu(mgr->stats); }
#else
static inline void stat_hunt_attempt(struct event_manager *mgr) { }
static inline void stat_hunt_success(struct event_manager *mgr, unsigned int n) { }
static inline void stat_seal(struct event_manager *mgr) { }
static inline void stat_scale_up(struct event_manager *mgr, bool woke) { }
static inline void stat_local_wake(struct event_manager *mgr) { }
static inline void stat_sleep(struct event_manager *mgr) { }
static inline void stat_backstop(struct event_manager *mgr) { }
static inline void stat_local_arrival(struct event_manager *mgr) { }
static inline u64 stat_local_arrivals_read(struct event_manager *mgr) { return 0; }
static inline void stat_steal_class(struct event_manager *mgr, u64 snapshot) { }
static inline void stat_sleep_hist(struct event_manager *mgr, u64 ns) { }
static inline bool upcall_stats_alloc(struct event_manager *mgr) { return true; }
static inline void upcall_stats_free(struct event_manager *mgr) { }
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
/* upcall_submit_time_start/end are defined after struct worker_context, since
 * they read the per-worker slept-time accumulator to exclude sleep. */
#endif

/*
 * Per-anchor forensic ring for the claim/enqueue/dequeue/deliver lifecycle --
 * added to catch a reproducible lost-wakeup strand (an anchor stuck QUEUED
 * with its owning worker parked forever) that static review couldn't pin
 * down. A single global ring was tried first and discarded: one busy channel
 * drowns it before a rarer stuck anchor's history survives to be read. Each
 * anchor instead keeps its own small ring, so a stuck anchor's history is
 * never overwritten by traffic on any other anchor or channel. Only
 * claim/enqueue/dequeue/deliver/re-arm are recorded -- these are the events
 * that have a specific anchor to attach to; channel-level wake/park events
 * don't and are left to each task's wchan (under /proc) and the owners/
 * anchors dumps. The enum is declared unconditionally so call sites don't
 * need their own #ifdef;
 * only the ring itself (and the recording work) is compiled out when
 * disabled.
 */
enum anchor_trace_ev {
	ANCHOR_TR_CLAIM,	/* ARMED->QUEUED claim won (any of the 3 sites) */
	ANCHOR_TR_ENQUEUE,	/* post_event added anchor to target's event_list */
	ANCHOR_TR_DEQUEUE,	/* drain_anchor took this anchor off a claimed batch */
	ANCHOR_TR_DEAD_SKIP,	/* drain saw DEAD, suppressed */
	ANCHOR_TR_DELIVER,	/* QUEUED->IDLE, delivered to out[] */
	ANCHOR_TR_REARM_BUSY,	/* attach_poll re-arm bailed with -EBUSY */
	ANCHOR_TR_REARM_OK,	/* attach_poll re-arm published ARMED */
};

#ifdef CONFIG_UPCALLS_STATS
#define ANCHOR_TRACE_SZ 16
struct anchor_trace_entry {
	u64	ts;
	int	cpu;
	int	ev;
};
#endif

/*
 * Anchor lifecycle (atomic). One-shot today: the ARMED -> QUEUED claim is won
 * by exactly one poster (the wakeup callback or the arming-path poll), after
 * which the drain recycles the anchor. IDLE (delivered, awaiting re-arm) and
 * DEAD (closing) are reserved for the persistent/teardown stages.
 */

/* QUEUED is probably the incorrect name for this state, it is better described as fired
 * meaning that we have an active subscription and a notification has fired (so we don't
 * want new ones). */
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
#ifdef CONFIG_UPCALLS_STATS
	struct anchor_trace_entry trace[ANCHOR_TRACE_SZ];
	atomic_t		trace_idx;
	u64			claim_ns;	/* ktime at ARMED->QUEUED, for dwell */
#endif
};

/*
 * Record one lifecycle event into anchor's own ring. Real body only exists
 * when CONFIG_UPCALLS_STATS is enabled; call sites never need an #ifdef.
 * trace_idx is left unzeroed across anchor slab reuse -- the ring is
 * read as "last N events for whatever this anchor is now", not a log scoped
 * to one subscription, so stale entries just age out as the anchor is reused.
 */
#ifdef CONFIG_UPCALLS_STATS
static inline void anchor_trace(struct event_anchor *anchor, int ev)
{
	unsigned int idx = (unsigned int)atomic_inc_return(&anchor->trace_idx) - 1;
	struct anchor_trace_entry *e = &anchor->trace[idx & (ANCHOR_TRACE_SZ - 1)];

	e->ts = ktime_get_mono_fast_ns();
	e->cpu = smp_processor_id();
	e->ev = ev;
}
#else
static inline void anchor_trace(struct event_anchor *anchor, int ev) { }
#endif

#ifdef CONFIG_UPCALLS_STATS
static inline void anchor_mark_claim(struct event_anchor *anchor)
{ anchor->claim_ns = ktime_get_mono_fast_ns(); }
/* Completion dwell: claim (ARMED->QUEUED) -> now (in-kernel delivery), bucketed
 * log2(ns) on the delivering cpu. */
static inline void stat_dwell(struct event_manager *mgr, struct event_anchor *anchor)
{
	u64 d = ktime_get_mono_fast_ns() - anchor->claim_ns;
	int b = d ? ilog2(d) : 0;

	if (b >= UPCALL_DWELL_BUCKETS)
		b = UPCALL_DWELL_BUCKETS - 1;
	this_cpu_inc(mgr->stats->dwell[b]);
}
#else
static inline void anchor_mark_claim(struct event_anchor *anchor) { }
static inline void stat_dwell(struct event_manager *mgr, struct event_anchor *anchor) { }
#endif

struct event_buffer {
	struct iovec		iovec;
	struct list_head	anchor;
};

struct worker_context {
	struct task_struct	*worker;
	struct list_head	buffers;
	struct list_head	anchor;
	uint64_t		spurious_count;
#ifdef CONFIG_UPCALLS_STATS
	u64			slept_ns;	/* sleep accumulated this upcall_submit() */
#endif
};

/*
 * submit_ns excludes time spent parked: worker_sleep() accumulates each
 * schedule() sleep into the worker's slept_ns, start zeroes it, end subtracts
 * it from the whole-syscall delta so the histogram reflects active work only.
 * Per-worker (not per-cpu) because co-tenant apps' workers can share a cpu.
 */
#ifdef CONFIG_UPCALLS_STATS
static inline u64 sleep_clock(void)
{ return ktime_get_mono_fast_ns(); }

static inline void submit_sleep_add(u64 ns)
{ if (current->worker_context) current->worker_context->slept_ns += ns; }

static inline u64 upcall_submit_time_start(void)
{
	if (current->worker_context)
		current->worker_context->slept_ns = 0;
	return ktime_get_mono_fast_ns();
}

static inline void upcall_submit_time_end(u64 t0)
{
	u64 total = ktime_get_mono_fast_ns() - t0;
	u64 slept = current->worker_context ? current->worker_context->slept_ns : 0;

	upcall_submit_record(total > slept ? total - slept : 0);
}
#else
static inline u64 sleep_clock(void) { return 0; }
static inline void submit_sleep_add(u64 ns) { }
static inline u64 upcall_submit_time_start(void) { return 0; }
static inline void upcall_submit_time_end(u64 t0) { }
#endif

/* up_event cache */
static struct kmem_cache *event_cache __read_mostly;

/* Anchor cache */
static struct kmem_cache *anchor_cache __read_mostly;

/* Batch cache (struct event_batch); allocated in the softirq enqueue path. */
static struct kmem_cache *batch_cache __read_mostly;

/*
 * Per-CPU recycle pool for event_batch objects. Batches churn at I/O rate (one
 * per batch_size events), so pooling keeps the softirq enqueue path off the
 * slab allocator -- and off GFP_ATOMIC -- on the common path. Touched from both
 * the softirq enqueue (alloc) and task-context drain/teardown (free), so the
 * pool ops disable IRQs, not just preemption. Anchors, by contrast, now churn
 * only at file-descriptor rate and allocate straight from anchor_cache.
 */
#define BATCH_POOL_CAP 64
struct batch_pool {
	int			count;
	struct event_batch	*free[BATCH_POOL_CAP];
};
static DEFINE_PER_CPU(struct batch_pool, batch_pool);

/* Buffer cache */
static struct kmem_cache *buffer_cache __read_mostly;

static void free_manager_kref(struct kref *kref);

/* anchor->refs release callback: recycle to the per-CPU pool. Only ever called
 * from task context (drain, UP_CLOSE, teardown), never from the softirq
 * post_event() path. */
static void anchor_release(struct kref *kref);

/* Per-manager stats debugfs; defined with the debugfs section. Called
 * unconditionally -- no-op stubs when CONFIG_UPCALLS_STATS is off. */
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
 * cpu -> compact domain id, built once from topology. Done lazily at first
 * create_manager() rather than at __initcall time, because the LLC masks are
 * only fully populated once SMP topology is up; building too early would make
 * upcall_domain_mask() report singletons and scatter every CPU into its own
 * domain.
 */
static int upcall_cpu_domain[NR_CPUS] __read_mostly;
static int upcall_nr_domains __read_mostly;
static bool upcall_domains_ready __read_mostly;

/* Build upcall_cpu_domain[]/upcall_nr_domains. Caller holds core_pool.lock. */
static void upcall_build_domains(void)
{
	int cpu, id = 0;

	if (upcall_domains_ready)
		return;
	for (cpu = 0; cpu < NR_CPUS; cpu++)
		upcall_cpu_domain[cpu] = -1;
	for_each_online_cpu(cpu) {
		int c;

		if (upcall_cpu_domain[cpu] != -1)
			continue;	/* already folded into an earlier domain */
		for_each_cpu(c, upcall_domain_mask(cpu))
			upcall_cpu_domain[c] = id;
		id++;
	}
	upcall_nr_domains = id;
	smp_wmb();		/* publish the map before the ready flag */
	upcall_domains_ready = true;
}

static inline int domain_of(int cpu)
{
	return upcall_cpu_domain[cpu];
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
	if (c < 0 && atomic_read(&mgr->owned_count) == 0) {
		c = acquire_core(mgr, cpu_online_mask);
		/* Backstop: the domain had no free/stealable core and mgr owns none,
		 * so we grabbed one machine-wide -- possibly in another domain, which
		 * breaks the one-guaranteed-core-per-domain model (events in this
		 * domain would then have to cross to it). Shouldn't happen under sane
		 * provisioning; warn once if it does. */
		if (c >= 0) {
			stat_backstop(mgr);
			pr_warn_once("upcall: mgr %d claimed a guaranteed core via the machine-wide backstop (cpu %d's domain was exhausted)\n",
				     mgr->id, cpu);
		}
	}
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

/* Wake the manager's worker on cpu if it is parked. Returns true if it woke a
 * parked worker. Caller has IRQs off. */
static bool wake_owned_worker(struct event_manager *mgr, int cpu)
{
	struct event_channel *chan = mgr->channels[cpu];
	struct worker_context *ctx;
	bool woke = false;

	spin_lock(&chan->worker_lock);
	ctx = mgr->pcpu_workers[cpu];
	if (ctx && !list_empty(&ctx->anchor)) {
		list_del_init(&ctx->anchor);
		wake_up_process(ctx->worker);
		woke = true;
	}
	spin_unlock(&chan->worker_lock);
	return woke;
}

/* Runs with IRQs disabled (placement context). */
static void upcall_scale_up(struct event_manager *mgr, int cpu)
{
	int claimed;

	if (cpumask_empty(&core_pool.free_mask) &&
	    cpumask_empty(&core_pool.stealable_mask)) {
		stat_scale_up(mgr, false);
		return;
	}
	claimed = acquire_core(mgr, upcall_domain_mask(cpu));
	stat_scale_up(mgr, claimed >= 0);
	if (claimed >= 0)
		wake_owned_worker(mgr, claimed);
}

/* Per-CPU batch pool get/put. IRQs off (not just preempt) because batch_alloc
 * runs in the softirq enqueue path while frees run in task context -- a softirq
 * must not interrupt a task-context pool op on the same cpu. */
static struct event_batch *batch_pool_get(void)
{
	struct batch_pool *pool;
	struct event_batch *b = NULL;
	unsigned long flags;

	local_irq_save(flags);
	pool = this_cpu_ptr(&batch_pool);
	if (pool->count)
		b = pool->free[--pool->count];
	local_irq_restore(flags);
	return b;
}

static void batch_pool_put(struct event_batch *b)
{
	struct batch_pool *pool;
	unsigned long flags;
	bool pooled = false;

	local_irq_save(flags);
	pool = this_cpu_ptr(&batch_pool);
	if (pool->count < BATCH_POOL_CAP) {
		pool->free[pool->count++] = b;
		pooled = true;
	}
	local_irq_restore(flags);

	if (!pooled)
		kmem_cache_free(batch_cache, b);
}

/* Fresh empty batch, pool first then the slab (GFP_ATOMIC, softirq-callable).
 * We bet allocation failure is unlikely; BUG() loudly for now rather than
 * silently stranding an event (a real fallback is future work if this trips). */
static struct event_batch *batch_alloc(void)
{
	struct event_batch *b = batch_pool_get();

	if (!b)
		b = kmem_cache_alloc(batch_cache, GFP_ATOMIC);
	if (!b)
		BUG();
	INIT_LIST_HEAD(&b->node);
	INIT_LIST_HEAD(&b->anchors);
	b->count = 0;
	b->closed = false;
	return b;
}

/* Append anchor to the channel's open tail batch, starting a fresh one when the
 * tail is closed (full, or a re-queued/claimed batch). Marks the tail closed
 * when this add fills it to batch_size and returns true then -- the scale-up
 * signal. Caller holds channel->event_lock. */
static bool batch_add(struct event_channel *chan, struct event_anchor *anchor,
		      unsigned int cap)
{
	struct event_batch *tail;

	if (list_empty(&chan->event_list) ||
	    list_last_entry(&chan->event_list, struct event_batch, node)->closed) {
		tail = batch_alloc();
		list_add_tail(&tail->node, &chan->event_list);
	} else {
		tail = list_last_entry(&chan->event_list, struct event_batch, node);
	}
	list_add_tail(&anchor->anchor, &tail->anchors);
	tail->count++;
	if (tail->count == cap) {
		tail->closed = true;	/* sealed on full */
		return true;
	}
	return false;
}

/* Every batch on a channel carries at least one anchor (batch_add never leaves
 * an empty batch; claim/requeue move whole batches), so "has work" is just a
 * non-empty list. Caller holds channel->event_lock. */
static bool channel_has_work(struct event_channel *chan)
{
	return !list_empty(&chan->event_list);
}

/* Detach the oldest batch (O(1)) and CLOSE it -- now private to the caller,
 * drained lock-free and off every channel, so nothing adds to it or steals it
 * again. NULL if the channel is empty. Decrements event_count by the batch's
 * anchor count. Caller holds chan->event_lock. */
static struct event_batch *detach_head_batch(struct event_channel *chan)
{
	struct event_batch *head;

	if (list_empty(&chan->event_list))
		return NULL;
	head = list_first_entry(&chan->event_list, struct event_batch, node);
	list_del(&head->node);
	chan->event_count -= head->count;
	head->closed = true;
	return head;
}

/* Claim (detach + close) the oldest batch from `chan`, clearing the hint bit if
 * that empties the channel. Returns the now-private batch, or NULL. */
static struct event_batch *claim_batch(struct event_manager *mgr,
				       struct event_channel *chan)
{
	struct event_batch *batch;
	unsigned long flags;

	spin_lock_irqsave(&chan->event_lock, flags);
	batch = detach_head_batch(chan);
	if (batch && !channel_has_work(chan))
		cpumask_clear_cpu(chan->cpu, &mgr->domain_hint[domain_of(chan->cpu)]);
	spin_unlock_irqrestore(&chan->event_lock, flags);
	return batch;
}

/*
 * Idle-worker pull: `me`'s own channel is empty, so claim one whole batch from a
 * busy sibling in the same domain (hint-directed, rotating start) and return it
 * private -- the caller drains it lock-free. The claimed batch is off every
 * channel, so it can't be added to or stolen again (re-steal is impossible by
 * construction). Each channel lock is taken alone, so hunters can't deadlock. A
 * stale/missed hint bit only costs a hunt opportunity, never a strand --
 * local-enqueue + local-wake still deliver every event to its RX cpu's worker.
 */
static struct event_batch *hunt_claim(struct event_manager *mgr,
				      struct event_channel *me)
{
	struct cpumask *hint = &mgr->domain_hint[domain_of(me->cpu)];
	struct event_batch *batch = NULL;
	int victim;

	stat_hunt_attempt(mgr);
	for_each_cpu_wrap(victim, hint, me->cpu) {
		struct event_channel *vc = mgr->channels[victim];

		if (victim == me->cpu || !vc)
			continue;	/* skip self; channels are created up front */
		batch = claim_batch(mgr, vc);
		if (batch)
			break;
	}
	if (batch)
		stat_hunt_success(mgr, batch->count);
	return batch;
}

/* Out[] filled before the claimed batch drained: put the (still-closed) leftover
 * back at `chan`'s head and re-advertise the hint, so a sibling can relieve it
 * rather than wait for this worker's next trip (head-of-line avoidance). Caller
 * must not touch `batch` after this. */
static void requeue_leftover(struct event_manager *mgr, struct event_channel *chan,
			     struct event_batch *batch)
{
	unsigned long flags;

	spin_lock_irqsave(&chan->event_lock, flags);
	list_add(&batch->node, &chan->event_list);	/* head: oldest, claimed first */
	chan->event_count += batch->count;
	cpumask_set_cpu(chan->cpu, &mgr->domain_hint[domain_of(chan->cpu)]);
	spin_unlock_irqrestore(&chan->event_lock, flags);
}

/*
 * Softirq-reachable: enqueue anchor onto the LOCAL cpu's channel -- the cpu
 * that processed the packet -- for data locality, regardless of which cpu this
 * manager "owns" (ownership gates who drains, not where events land). The local
 * worker drains its own channel; idle domain siblings pull a backlog via the
 * hunt, and a sealed batch adds a core. channels[my_cpu] always exists (every
 * online cpu gets one at create_manager time).
 */
static void post_event(struct event_anchor *anchor)
{
	unsigned long flags;
	struct event_manager *mgr = anchor->mgr;
	struct event_channel *target;
	bool sealed;
	int my_cpu;

	local_irq_save(flags);
	my_cpu = smp_processor_id();
	target = mgr->channels[my_cpu];

	INIT_LIST_HEAD(&anchor->anchor);

	spin_lock(&target->event_lock);
	/* Queued ref: held while on the channel list and across the drain; the
	 * worker drops it. Keeps the anchor alive against a concurrent UP_CLOSE
	 * that drops the subscription ref. */
	kref_get(&anchor->refs);
	if (!channel_has_work(target))
		cpumask_set_cpu(my_cpu, &mgr->domain_hint[domain_of(my_cpu)]);
	sealed = batch_add(target, anchor, mgr->batch_size);
	target->event_count++;
	spin_unlock(&target->event_lock);

	anchor_trace(anchor, ANCHOR_TR_ENQUEUE);
	stat_local_arrival(mgr);	/* local work landed on this cpu's channel */

	/* Wake the local worker to drain its own channel (no-op if it is already
	 * running -- it drains this when it loops). If the channel just backed up
	 * a full batch, add a core to the domain so an extra worker can hunt the
	 * backlog. */
	if (wake_owned_worker(mgr, my_cpu))
		stat_local_wake(mgr);
	if (sealed) {
		stat_seal(mgr);
		upcall_scale_up(mgr, my_cpu);
	}

	local_irq_restore(flags);
}

/* Claim the anchor for posting: exactly one caller wins ARMED -> QUEUED. */
static inline bool anchor_claim(struct event_anchor *anchor)
{
	bool won = atomic_cmpxchg(&anchor->state, ANCHOR_ARMED, ANCHOR_QUEUED) == ANCHOR_ARMED;

	if (won) {
		anchor_mark_claim(anchor);	/* dwell clock starts here */
		anchor_trace(anchor, ANCHOR_TR_CLAIM);
	}
	return won;
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

/*
 * Process one anchor taken (lock-free) from a claimed, private batch. Returns
 * true if it was delivered to *out, false if suppressed (closed/DEAD or a
 * concurrent close raced). Drops the anchor's queued ref either way.
 */
static bool drain_anchor(struct event_manager *mgr, struct event_channel *my_chan,
			 struct event_anchor *anchor, struct up_event *out)
{
	anchor_trace(anchor, ANCHOR_TR_DEQUEUE);

	/* Closing: a concurrent UP_CLOSE marked it DEAD -- no I/O, no delivery. */
	if (atomic_read(&anchor->state) == ANCHOR_DEAD) {
		anchor_trace(anchor, ANCHOR_TR_DEAD_SKIP);
		kref_put(&anchor->refs, anchor_release);
		return false;
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
		/* Unreachable -- only READ/WRITE/ACCEPT are ever posted. Drop it. */
		WARN_ONCE(1, "upcall: drained anchor with bad type %d\n",
			  anchor->event.type);
		kref_put(&anchor->refs, anchor_release);
		return false;
	}

	/* Deliver iff still ours: QUEUED -> IDLE. A close that raced in during
	 * try_* set DEAD, so the cmpxchg fails and we suppress the now-stale event
	 * rather than hand the app a result for a closed fd. */
	if (atomic_cmpxchg(&anchor->state, ANCHOR_QUEUED, ANCHOR_IDLE) == ANCHOR_QUEUED) {
		anchor_trace(anchor, ANCHOR_TR_DELIVER);
		stat_dwell(mgr, anchor);	/* claim -> delivery */
		*out = anchor->event;
		/* Remember the RX ring that fed this channel for the busy-poll below. */
		if (anchor->sk)
			WRITE_ONCE(my_chan->napi_id, READ_ONCE(anchor->sk->sk_napi_id));
		kref_put(&anchor->refs, anchor_release);
		return true;
	}
	WARN_ONCE(atomic_read(&anchor->state) != ANCHOR_DEAD,
		  "upcall: suppressed non-QUEUED drained event (state %d)\n",
		  atomic_read(&anchor->state));
	kref_put(&anchor->refs, anchor_release);
	return false;
}

/* Park the calling worker until an event arrives or a spurious wakeup
 * retries. Re-checks event_count under lock immediately before parking to
 * close the race with a concurrent post_event(). */
static void worker_sleep(struct event_manager *mgr)
{
	unsigned long flags;
	struct event_channel *channel;
	int cpu;
	u64 sleep_t0;

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
	stat_sleep(mgr);	/* committed to parking (domain empty) */

	mark_stealable(mgr, cpu);
	sleep_t0 = sleep_clock();	/* start of the parked interval */
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
	/* Exclude the whole parked interval (incl. spurious re-sleeps) from
	 * submit_ns, and record it in the per-cpu sleep histogram. */
	{
		u64 slept = sleep_clock() - sleep_t0;

		submit_sleep_add(slept);
		stat_sleep_hist(mgr, slept);
	}
out:
	return;
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
 * must kref_put(anchor_release) when done. */
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
		kref_put(&a->refs, anchor_release);	/* drop subscription ref */
	}
}

/*
 * Final free, once both refs (subscription + any queued) are gone. The closer
 * (close_fd_anchors / manager teardown) has already removed the anchor from the
 * hash and the wait queue before the last ref could drop, so there is no hash
 * work here. Runs in task context (drain or UP_CLOSE), so the slab free and
 * put_mgr()'s possible free_manager() are both safe.
 */
static void anchor_release(struct kref *kref)
{
	struct event_anchor *anchor = container_of(kref, struct event_anchor, refs);

	put_mgr(anchor->mgr);
	if (anchor->file)
		fput(anchor->file);
	kmem_cache_free(anchor_cache, anchor);
}

static struct event_anchor *build_anchor(struct event_manager *mgr, struct up_event *evt)
{
	struct event_anchor *anchor;

	/* fd-rate churn (one per (fd,type) subscription), so straight from the
	 * dedicated slab -- no per-cpu pool needed. */
	anchor = kmem_cache_alloc(anchor_cache, GFP_KERNEL);
	if (!anchor) {
		// Not sure what to do here, needs thinking
		return NULL;
	}
	anchor->event = *evt;	/* embedded copy; input stays owned by the caller */

	/* The anchor owns its own file reference for its entire lifetime, so the
	 * drain path (try_*) and poll can use anchor->file/sk without racing a
	 * concurrent close. fput happens at anchor release. */
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
			anchor_trace(anchor, ANCHOR_TR_REARM_BUSY);
		} else {
			/* Refresh payload while IDLE (no concurrent reader), then
			 * publish ARMED (the cmpxchg is the release) so a claimer
			 * sees it whole. */
			anchor->event = *evt;
			if (atomic_cmpxchg(&anchor->state, ANCHOR_IDLE, ANCHOR_ARMED) != ANCHOR_IDLE) {
				rc = -EBUSY;	/* raced a teardown; drop the re-arm */
				anchor_trace(anchor, ANCHOR_TR_REARM_BUSY);
			} else {
				anchor_trace(anchor, ANCHOR_TR_REARM_OK);
			}
			if (rc == 0 && (vfs_poll(anchor->file, NULL) & anchor->events)) {
				/* Re-check readiness WITHOUT re-adding to the wait
				 * queue (already registered): vfs_poll(file, NULL)
				 * polls without poll_wait(). Closes the
				 * delivered-then-ready-before-rearm stranding window. */
				if (anchor_claim(anchor))
					post_event(anchor);
			}
		}
		kref_put(&anchor->refs, anchor_release);	/* drop lookup ref */
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
	int ret = 0;
	int presleep_fd = -1;		/* first readable arm: gate the pre-sleep poll */
	bool polled = false;
	bool presleep_polled = false;
	struct event_channel *my_chan;
	unsigned long cflags;

	/* This worker's own (per-cpu) channel. The worker is pinned to one cpu
	 * for its whole life, so this stays valid across the sleeps below; it is
	 * where we drain from and where we cache the busy-poll napi_id. */
	local_irq_save(cflags);
	my_chan = get_event_channel(mgr);
	local_irq_restore(cflags);

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
		/* Claim a whole batch -- own channel first, else steal a sibling's.
		 * The claimed batch is detached + closed, so it's private: we drain
		 * it with no event_lock, nothing adds to it, nothing re-steals it. */
		struct event_batch *batch = claim_batch(mgr, my_chan);
		bool stole = false;
		u64 arrivals_snap = 0;

		if (!batch) {
			/* Own channel empty: about to raid a sibling. Snapshot our
			 * local-arrival count so we can tell afterwards whether our
			 * own next packet landed while we were off stealing. */
			arrivals_snap = stat_local_arrivals_read(mgr);
			batch = hunt_claim(mgr, my_chan);
			stole = batch;
		}
		if (!batch)
			break;	/* own channel empty and nothing to steal in the domain */

		while (batch->count && out_idx < out_cnt) {
			struct event_anchor *a =
				list_first_entry(&batch->anchors, struct event_anchor,
						 anchor);

			list_del_init(&a->anchor);
			batch->count--;
			if (drain_anchor(mgr, my_chan, a, &out[out_idx]))
				out_idx++;
		}

		if (stole)
			stat_steal_class(mgr, arrivals_snap);

		if (batch->count)
			requeue_leftover(mgr, my_chan, batch);	/* out[] full: stay stealable */
		else
			batch_pool_put(batch);			/* fully drained */
	}

	/* Busy-poll the RX ring that last delivered to this channel (cached at
	 * delivery above), rather than inferring it from an arbitrary fd. */
	if (!polled && out_idx > 0 && (size_t)out_idx < mgr->napi_poll_threshold) {
		unsigned int napi_id = READ_ONCE(my_chan->napi_id);

		polled = true;
		if (napi_id_valid(napi_id))
			napi_busy_loop(napi_id, NULL, NULL, false, BUSY_POLL_BUDGET);
		goto again;
	}

	if (!out_idx && out_cnt > 0) {
		/*
		 * About to sleep with nothing ready. If we armed a readable fd this
		 * submit (presleep_fd) and we know a ring that has fed this channel,
		 * do one busy-poll pass first: a packet may already be sitting in that
		 * ring unprocessed. The poll runs the full stack, and sk_data_ready()
		 * posts any resulting event into our channel, so the re-drain finds it
		 * and we skip the sleep/softirq-wake round trip. napi_busy_loop polls
		 * the whole NAPI instance, so siblings on the same queue are drained
		 * too. One pass per sleep attempt (presleep_polled), then actually
		 * sleep.
		 */
		if (!presleep_polled && presleep_fd >= 0) {
			unsigned int napi_id = READ_ONCE(my_chan->napi_id);

			presleep_polled = true;
			if (napi_id_valid(napi_id))
				napi_busy_loop(napi_id, NULL, NULL, false, BUSY_POLL_BUDGET);
			goto again;
		}

		worker_sleep(mgr);
		presleep_polled = false;	/* fresh poll allowed on the next sleep */
		goto again;
	}

	/* event_count is maintained at claim/enqueue/requeue time (not here), so
	 * there is nothing to reconcile on the way out. */
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
		struct event_batch *b, *tmp;

		chan = mgr->channels[i];
		mgr->channels[i] = NULL;
		if (chan) {
			/* teardown_anchors() already drained the anchors; only the
			 * (now-empty) batch objects remain to free. */
			list_for_each_entry_safe(b, tmp, &chan->event_list, node)
				batch_pool_put(b);
		}
		kfree(chan);
	}

	kfree(mgr->domain_hint);
	kfree(mgr->anchor_hash);
	upcall_mgr_debugfs_del(mgr);	/* blocks readers before freeing stats */
	upcall_stats_free(mgr);
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
		kref_put(&a->refs, anchor_release);	/* subscription ref */
	}

	for (int cpu = 0; cpu < NR_CPUS; cpu++) {
		struct event_channel *chan = mgr->channels[cpu];
		struct event_batch *batch;

		if (!chan)
			continue;
		while ((batch = claim_batch(mgr, chan))) {
			while (batch->count) {
				a = list_first_entry(&batch->anchors,
						     struct event_anchor, anchor);
				list_del_init(&a->anchor);
				batch->count--;
				kref_put(&a->refs, anchor_release);	/* queued ref */
			}
			batch_pool_put(batch);
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

/* Allocated on cpu's own node so the channel's hot lock/list cacheline is
 * local to the CPU that will actually touch it on every event. */
static struct event_channel *create_channel(int cpu)
{
	struct event_channel *ret = kzalloc_node(sizeof(struct event_channel),
						  GFP_KERNEL, cpu_to_node(cpu));

	if (!ret)
		return ret;

	INIT_LIST_HEAD(&ret->event_list);
	INIT_LIST_HEAD(&ret->sleeping_workers);
	spin_lock_init(&ret->event_lock);
	spin_lock_init(&ret->worker_lock);
	ret->cpu = cpu;

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

	mgr->anchor_hash = kcalloc(UPCALL_ANCHOR_HASH_SZ, sizeof(struct hlist_head),
				   GFP_KERNEL);
	if (!mgr->anchor_hash)
		goto out_free;
	spin_lock_init(&mgr->anchor_lock);

	if (!upcall_stats_alloc(mgr))
		goto out_free;

	/* Build the cpu->domain map once (topology is up by now), then a
	 * per-domain hint cpumask for this manager. */
	scoped_guard(spinlock_irqsave, &core_pool.lock)
		upcall_build_domains();
	mgr->domain_hint = kcalloc(upcall_nr_domains, sizeof(struct cpumask),
				   GFP_KERNEL);
	if (!mgr->domain_hint)
		goto out_free;

	/* Every online cpu gets its channel up front, NUMA-local, instead of
	 * on that cpu's first upcall_submit() -- lazy per-thread creation left
	 * a window where a cpu could be claimed as owned/guaranteed (acquire_core
	 * only touches core_pool/masks) before its own worker had ever run,
	 * leaving mgr->channels[cpu] NULL for a target post_event() could still
	 * pick. */
	for_each_online_cpu(i) {
		mgr->channels[i] = create_channel(i);
		if (!mgr->channels[i])
			goto out_free;
	}

	kref_init(&mgr->ref_count);
	mgr->id = atomic_inc_return(&upcall_mgr_ids);
	upcall_mgr_debugfs_add(mgr);

	return mgr;

out_free:
	for_each_online_cpu(i) {
		kfree(mgr->channels[i]);
	}
	kfree(mgr->domain_hint);
	kfree(mgr->anchor_hash);
	upcall_stats_free(mgr);
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
	/* create_manager() fully allocated (channels, anchor_hash, domain_hint,
	 * stats, debugfs); free it all, not just the mgr struct. No cores owned
	 * and no other ref exists yet, so a direct free_manager() is safe. */
	free_manager(mgr);
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

#ifdef CONFIG_UPCALLS_ANCHOR_STATS
static const char *anchor_state_name(int st)
{
	switch (st) {
	case ANCHOR_ARMED:	return "ARMED";
	case ANCHOR_QUEUED:	return "QUEUED";
	case ANCHOR_IDLE:	return "IDLE";
	case ANCHOR_DEAD:	return "DEAD";
	default:		return "?";
	}
}

/*
 * Print a's own lifecycle ring (see anchor_trace()), oldest first, indented
 * under its state line in /sys/kernel/debug/upcall/anchors. Called under
 * mgr->anchor_lock; a torn read of one entry is acceptable for a debug dump.
 * Real body only when CONFIG_UPCALLS_STATS is enabled.
 */
#ifdef CONFIG_UPCALLS_STATS
static const char *anchor_trace_ev_name(int ev)
{
	static const char *names[] = {
		[ANCHOR_TR_CLAIM]	= "CLAIM",
		[ANCHOR_TR_ENQUEUE]	= "ENQUEUE",
		[ANCHOR_TR_DEQUEUE]	= "DEQUEUE",
		[ANCHOR_TR_DEAD_SKIP]	= "DEAD_SKIP",
		[ANCHOR_TR_DELIVER]	= "DELIVER",
		[ANCHOR_TR_REARM_BUSY]	= "REARM_BUSY",
		[ANCHOR_TR_REARM_OK]	= "REARM_OK",
	};
	return (ev >= 0 && ev < ARRAY_SIZE(names) && names[ev]) ? names[ev] : "?";
}

static void anchor_trace_dump(struct seq_file *s, struct event_anchor *a)
{
	unsigned int total = (unsigned int)atomic_read(&a->trace_idx);
	unsigned int start = total > ANCHOR_TRACE_SZ ? total - ANCHOR_TRACE_SZ : 0;
	unsigned int n = total - start;

	for (unsigned int i = 0; i < n; i++) {
		struct anchor_trace_entry *e = &a->trace[(start + i) & (ANCHOR_TRACE_SZ - 1)];

		seq_printf(s, "    %llu cpu=%d %s\n",
			   (unsigned long long)e->ts, e->cpu,
			   anchor_trace_ev_name(e->ev));
	}
}
#else
static inline void anchor_trace_dump(struct seq_file *s, struct event_anchor *a) { }
#endif

/*
 * debugfs: /sys/kernel/debug/upcall/anchors -- every live (fd,type) subscription
 * and its state, for diagnosing stranded connections. Ungated (works without
 * CONFIG_UPCALLS_STATS). Managers are discovered via the cores they own, so a
 * manager owning no core is not listed; the fixed snapshot cap keeps this off a
 * NR_CPUS-sized stack array. The anchor_lock walk below runs with IRQs off and
 * can be long under many connections -- acceptable for a debug read.
 */
#define UPCALL_ANCHORS_MGR_CAP 32
static int upcall_anchors_show(struct seq_file *s, void *v)
{
	struct event_manager *seen[UPCALL_ANCHORS_MGR_CAP];
	int nseen = 0;
	unsigned long flags;
	int cpu, i;

	spin_lock_irqsave(&core_pool.lock, flags);
	for_each_online_cpu(cpu) {
		struct event_manager *mgr = READ_ONCE(core_pool.owner[cpu]);
		bool dup = false;

		if (!mgr)
			continue;
		for (i = 0; i < nseen; i++)
			if (seen[i] == mgr) {
				dup = true;
				break;
			}
		if (!dup && nseen < UPCALL_ANCHORS_MGR_CAP)
			seen[nseen++] = mgr;
	}
	spin_unlock_irqrestore(&core_pool.lock, flags);

	for (i = 0; i < nseen; i++) {
		struct event_manager *mgr = seen[i];
		struct event_anchor *a;
		unsigned int b, n = 0;

		seq_printf(s, "mgr %d:\n", mgr->id);
		spin_lock_irqsave(&mgr->anchor_lock, flags);
		for (b = 0; b < UPCALL_ANCHOR_HASH_SZ; b++)
			hlist_for_each_entry(a, &mgr->anchor_hash[b], hash_node) {
				seq_printf(s, "  fd %d type %d state %s wq %c\n",
					   a->event.fd, a->event.type,
					   anchor_state_name(atomic_read(&a->state)),
					   a->whead ? 'y' : 'n');
				anchor_trace_dump(s, a);
				n++;
			}
		spin_unlock_irqrestore(&mgr->anchor_lock, flags);
		seq_printf(s, "  (%u anchors)\n", n);
	}
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(upcall_anchors);

static void upcall_anchors_debugfs_init(struct dentry *parent)
{
	debugfs_create_file("anchors", 0444, parent, NULL, &upcall_anchors_fops);
}
#else
static void upcall_anchors_debugfs_init(struct dentry *parent) { }
#endif /* CONFIG_UPCALLS_ANCHOR_STATS */

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

/*
 * debugfs: /sys/kernel/debug/upcall/managers/<id> -- per-cpu pull-model
 * counters plus the completion-dwell histogram. Read prints one counters row
 * per cpu followed by that cpu's non-empty dwell buckets (upper-bound ns,
 * count); any write zeroes every cpu's stats so a sweep brackets a run.
 */
static int upcall_mgr_show(struct seq_file *s, void *v)
{
	struct event_manager *mgr = s->private;
	int cpu, b;

	for_each_possible_cpu(cpu) {
		struct upcall_stats *st = per_cpu_ptr(mgr->stats, cpu);

		seq_printf(s,
			   "cpu %d hunts_attempted %llu hunts_succeeded %llu stolen_events %llu seals %llu scale_up_woke %llu scale_up_nocore %llu local_wakes %llu worker_sleeps %llu backstop_hits %llu jitter_steals %llu idle_steals %llu\n",
			   cpu, st->hunts_attempted, st->hunts_succeeded,
			   st->stolen_events, st->seals, st->scale_up_woke,
			   st->scale_up_nocore, st->local_wakes, st->worker_sleeps,
			   st->backstop_hits, st->jitter_steals, st->idle_steals);
		for (b = 0; b < UPCALL_DWELL_BUCKETS; b++)
			if (st->dwell[b])
				seq_printf(s, "cpu %d dwell_ns %llu %llu\n",
					   cpu, 1ULL << (b + 1), st->dwell[b]);
		for (b = 0; b < UPCALL_DWELL_BUCKETS; b++)
			if (st->sleep[b])
				seq_printf(s, "cpu %d sleep_ns %llu %llu\n",
					   cpu, 1ULL << (b + 1), st->sleep[b]);
	}
	return 0;
}

static int upcall_mgr_open(struct inode *inode, struct file *file)
{
	return single_open(file, upcall_mgr_show, inode->i_private);
}

static ssize_t upcall_mgr_write(struct file *file, const char __user *ubuf,
				size_t len, loff_t *off)
{
	struct event_manager *mgr = ((struct seq_file *)file->private_data)->private;
	int cpu;

	for_each_possible_cpu(cpu)
		memset(per_cpu_ptr(mgr->stats, cpu), 0, sizeof(struct upcall_stats));
	return len;
}

static const struct file_operations upcall_mgr_fops = {
	.owner		= THIS_MODULE,
	.open		= upcall_mgr_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= upcall_mgr_write,
};

static void upcall_mgr_debugfs_add(struct event_manager *mgr)
{
	char name[16];

	if (!upcall_mgr_dbg_dir)
		return;
	snprintf(name, sizeof(name), "%d", mgr->id);
	mgr->dbg = debugfs_create_file(name, 0644, upcall_mgr_dbg_dir, mgr,
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
	upcall_anchors_debugfs_init(upcall_debugfs_dir);
	upcall_stats_debugfs_init(upcall_debugfs_dir);

	event_cache = kmem_cache_create("upcall_event", sizeof(struct up_event),
			0, SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);
	if (!event_cache)
		return -ENOMEM;

	anchor_cache = kmem_cache_create("upcall_anchor", sizeof(struct event_anchor),
			0, SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);
	if (!anchor_cache)
		return -ENOMEM;

	batch_cache = kmem_cache_create("upcall_batch", sizeof(struct event_batch),
			0, SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);
	if (!batch_cache)
		return -ENOMEM;

	buffer_cache = kmem_cache_create("upcall_buffer", sizeof(struct event_buffer),
			0, SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);
	if (!buffer_cache)
		return -ENOMEM;

	return 0;
}

__initcall(upcall_init);

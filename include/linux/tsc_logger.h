#ifndef _LINUX_TSC_LOGGER_H
#define _LINUX_TSC_LOGGER_H

#include <asm/cache.h>

#define TscLogValue_t u64
struct TscLogEntry {
  u32	cpu;
  u32	tid;
  u64	tsc;
  TscLogValue_t values[];
};

#define TscLogEntrySize(numvals) ((sizeof(struct TscLogEntry) + (numvals * sizeof(TscLogValue_t))))

struct TscLog {
	union Header {
		char raw[L1_CACHE_BYTES];
		struct Info {
			void *		cur;
			void *		end;
			u32		overflow;
			u32		valperentry;
		} info;
	} hdr;
	u8 entries[];
} __attribute__ ((aligned (L1_CACHE_BYTES)));

struct TscBuf
{
	void *allocated;
	struct TcsLog *log;
} __attribute__ ((aligned (L1_CACHE_BYTES)));

struct KernelTscLog
{
	struct TscBuf __percpu *buf;
	struct proc_dir_entry *proc_logger;
	char proc_name[64];
};

struct KernelTscLog *tsclog_create(u64 entries, u8 vals_per_entry, char *name);

void tsclog_destroy(struct KernelTscLog *log);

static inline void write_nti64(void *p, const u64 v)
{
	asm volatile(	"movnti %0, (%1)\n\t"
			:
			: "r"(v), "r"(p)
			: "memory");
}

static inline void write_nti32(void *p, const u32 v)
{
	asm volatile(	"movnti %0, (%1)\n\t"
			:
			: "r"(v), "r"(p)
			: "memory");
}

static u64 inline __attribute__((always_inline)) now(void)
{
	u32 high, low;
	asm volatile(	"rdtsc;"
			"mov %%edx, %0;"
			"mov %%eax, %1;"
			"cpuid;"
			: "=r"(high), "=r"(low):
			: "%rax", "%rbx", "%rcx", "%rdx");
	return (((u64)high << 32 | low));
}

static u64 inline __attribute__((always_inline)) now_with_procid(u32 *cpuid)
{
	u32 high, low, tsc_sig;
	asm volatile(	"rdtscp;"
			"mov %%edx, %0;"
			"mov %%eax, %1;"
			"mov %%ecx, %2;"
			"cpuid;"
			: "=r"(high), "=r"(low), "=r"(tsc_sig):
			: "%rax", "%rbx", "%rcx", "%rdx");
	write_nti32(cpuid, tsc_sig);
	return (((u64)high << 32 | low));
}

static inline void tsclog_hdr(struct TscLogEntry *e, u64 now, u32 cpuid)
{
	write_nti64(&(e->tsc), now);
	write_nti32(&(e->cpu), cpuid);
	write_nti32(&(e->tid), current->pid);
}

static inline void * tsc_buffer_reserve(u32 bytes, void * volatile *cur, void *end)
{
	u8 *old, *fresh;
retry:
	old = *cur;
	fresh = old + bytes;
	if ((u64)fresh > (u64)end)
		return NULL;
	if (!__sync_bool_compare_and_swap(cur, (void *)old, (void *)fresh))
		goto retry;
	return (void *)old;
}

static inline int tsc_buffer_try_set(void * volatile *cur, void * fresh)
{
	void *old = *cur;
	return __sync_bool_compare_and_swap(cur, old, fresh);
}

static inline struct TscLogEntry *
tsclog_getentry(struct TscLog *lptr, u32 numvals)
{
	struct TscLogEntry *e;
	e = tsc_buffer_reserve(TscLogEntrySize(numvals), &(lptr->hdr.info.cur),
				lptr->hdr.info.end);
	if (e == NULL)
		lptr->hdr.info.overflow = 1;
	return e;
}

#define TSCLOG_INFO(kern_log, n, ...)				\
	u32 cpuid;						\
	u64 now            = now_with_procid(&cpuid);		\
	struct TscLogEntry *e;					\
	struct TscBuf *buf = this_cpu_ptr(kern_log->buf);	\
	e = tsclog_getentry(buf->log, n);			\
	if (e == NULL) return;					\
	tsclog_hdr(e, now, cpuid)

static inline void tsclog_0(struct KernelTscLog *lptr)
{
	TSCLOG_INFO(lptr, 0);
}

static inline void tsc_writeval(struct TscLogEntry *e, int i, TscLogValue_t v)
{
	write_nti64(&(e->values[i]), v);
}

static inline void tsclog_1(struct KernelTscLog *log, TscLogValue_t v0)
{
	TSCLOG_INFO(log,1);
	tsc_writeval(e,0,v0);
}

static inline void tsclog_2(struct KernelTscLog *log, TscLogValue_t v0, TscLogValue_t v1) {
	TSCLOG_INFO(log,2);
	tsc_writeval(e,0,v0);
	tsc_writeval(e,1,v1);
}

static inline void tsclog_3(struct KernelTscLog *log, TscLogValue_t v0, TscLogValue_t v1,
	 			TscLogValue_t v2) {
	TSCLOG_INFO(log,3);
	tsc_writeval(e,0,v0);
	tsc_writeval(e,1,v1);
	tsc_writeval(e,2,v2);
}

static inline void tsclog_4(struct KernelTscLog *log, TscLogValue_t v0, TscLogValue_t v1,
	 			TscLogValue_t v2, TscLogValue_t v3) {
	TSCLOG_INFO(log,4);
	tsc_writeval(e,0,v0);
	tsc_writeval(e,1,v1);
	tsc_writeval(e,2,v2);
	tsc_writeval(e,3,v3);
}

#endif

#include <linux/init.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/percpu.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>

#include <linux/tsc_logger.h>

#define PROC_NAME "tsc_log-"

MODULE_LICENSE("GPL");

static int logger_show(struct seq_file *m, void *v)
{
	unsigned int i;
	struct KernelTscLog *log = (struct KernelTscLog*)v;
	struct TscBuf *buf;
	struct TscLogEntry *e
	struct TscLogEntry *cur

	seq_printf(m, "CPU\tTID\tTSC");
	for (int i = 0; i < vals_per_entry; i++) {
		seq_printf(m, "\tValue%d", i);
	}
	seq_printf(m, "\n");

	for_each_possible_cpu(i) {
		buf = per_cpu_ptr(log->buf, i);
		e = (struct TscLogEntry *)&(buf->log->entries[0]);
		cur = buf->log->hdr.info.cur;
		while (e != cur) {
			seq_printf(m, "%u\t%u\t%llu", e->cpu, e->tid, e->tsc);
			for (int i = 0; i < vals_per_entry; i++) {
				seq_printf(m, "\t%llu", e->values[i]);
			}
			seq_printf(m, "\n");
			e = (struct TscLogEntry *)((u8*)e + TscLogEntrySize(vals_per_entry));
		}
	}

	return 0;
}

static int logger_open(struct inode *inode, struct file *file)
{
	return single_open(file, logger_show, pde_data(inode));
}

static const struct proc_ops logger_ops = {
	.proc_open	= logger_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

struct KernelTscLog *tsclog_create(u64 entries, u8 vals_per_entry, char *name)
{
	unsigned int i;
	struct KernelTscLog *ret = NULL;
	struct TscBuf *buf;
	u64 entry_sz = entries * TscLogEntrySize(vals_per_entry);
	u64 total_sz = sizeof(struct TscLog) + entry_sz + L1_CACHE_BYTES;
	char entry_name[64];

	if (entries == 0)
		return ret;

	ret = kzalloc(sizeof(struct KernelTscLog), GFP_KERNEL);
	if (!ret)
		return ret;

	ret->buf = alloc_percpu(struct TscBuf);
	if (!ret->buf)
		goto out_free;

	for_each_possible_cpu(i) {
		buf = per_cpu_ptr(ret->buf, i);
		buf->allocated = vmalloc(total_sz);
		if (!buf->allocated)
			goto out_pcpu_free;

		if ((u64)buf->allocated & (L1_CACHE_BYTES - 1))
			buf->log = (struct TscLog *)(((u64)buf->allocated + L1_CACHE_BYTES) & ~((u64) L1_CACHE_BYTES - 1));
		else
			buf->log = (struct TscLog *)buf->allocated;

		buf->log->hdr.info.cur = &(buf->log->entries[0]);
		buf->log->hdr.info.end = (void *)((u64)buf->log->hdr.info.cur + entry_sz);
		buf->log->hdr.overflow = 0;
		buf->log->hdr.info.valperentry = vals_per_entry;
	}

	snprintf(ret->proc_name, 64, "%s%s", PROC_NAME, name);
	ret->proc_logger = proc_create_data(ret->proc_name, S_IRUGO, NULL, &logger_ops, (void *)ret);
	if (!ret->proc_logger)
		goto out_pcpu_free;

	return ret;

out_pcpu_free:
	for_each_possible_cpu(i) {
		buf = per_cpu_ptr(ret->buf, i);
		vfree(buf->allocated);
	}
	free_percpu(ret->buf);
out_free:
	kfree(ret);
	return NULL;
}
EXPORT_SYMBOL_GPL(tsclog_create);

void tsclog_destroy(struct KernelTscLog *log)
{
	unsigned int i;
	struct TscBuf *buf;

	remove_proc_entry(log->proc_name, NULL);

	for_each_possible_cpu(i) {
		buf = per_cpu_ptr(log->buf, i);
		vfree(buf->allocated);
	}

	free_percpu(log->buf);
	kfree(log)
}
EXPORT_SYMBOL_GPL(tsclog_destroy);

static int __init setup_tsc_logger(void)
{
	return 0;
}

static void __exit cleanup_tsc_logger(void)
{
}

module_init(setup_tsc_logger);
module_exit(cleanup_tsc_logger);


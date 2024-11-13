#include <linux/init.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>

#include <linux/tsc_logger.h>

#define PROC_NAME "tsc_logger"

MODULE_LICENSE("GPL");

static void *allocated;

struct TscLog *ukl_tsc_log;
EXPORT_SYMBOL_GPL(ukl_tsc_log);

static int max_event_count = 1000000;
module_param(max_event_count, int, 0);

static int vals_per_entry = 1;
module_param(vals_per_entry, int, 0);

extern unsigned int __read_mostly tsc_khz;

static int logger_show(struct seq_file *m, void *v)
{
	struct TscLogEntry *e = (struct TscLogEntry *)&(ukl_tsc_log->entries[0]);
	struct TscLogEntry *cur = ukl_tsc_log->hdr.info.cur;

	pr_err("tsc_khz value is %u\n", tsc_khz);

	seq_printf(m, "CPU\tTID\tTSC");
	for (int i = 0; i < vals_per_entry; i++) {
		seq_printf(m, "\tValue%d", i);
	}
	seq_printf(m, "\n");

	while (e != cur) {
		seq_printf(m, "%u\t%u\t%llu", e->cpu, e->tid, e->tsc);
		for (int i = 0; i < vals_per_entry; i++) {
			seq_printf(m, "\t%llu", e->values[i]);
		}
		seq_printf(m, "\n");
		e = (struct TscLogEntry *)((u8*)e + TscLogEntrySize(vals_per_entry));
	}

	return 0;
}

static int logger_open(struct inode *inode, struct file *file)
{
	return single_open(file, logger_show, NULL);
}

static const struct proc_ops logger_ops = {
	.proc_open	= logger_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static struct proc_dir_entry *proc_logger;

static int __init setup_tsc_logger(void)
{
	u64 entry_sz = max_event_count * TscLogEntrySize(vals_per_entry);
	u64 total_sz = sizeof(struct TscLog) + entry_sz + L1_CACHE_BYTES;

	if (max_event_count == 0)
		return -EINVAL;

	allocated = vmalloc(total_sz);
	if (!allocated)
		return -ENOMEM;

	if ((u64)allocated & (L1_CACHE_BYTES - 1))
		ukl_tsc_log = (struct TscLog*)(((u64)allocated + L1_CACHE_BYTES) & ~((u64)L1_CACHE_BYTES - 1));
	else
		ukl_tsc_log = allocated;

	ukl_tsc_log->hdr.info.cur = &(ukl_tsc_log->entries[0]);
	ukl_tsc_log->hdr.info.end = (void *)((unsigned long)ukl_tsc_log->hdr.info.cur + entry_sz);
	ukl_tsc_log->hdr.info.overflow = 0;
	ukl_tsc_log->hdr.info.valperentry = vals_per_entry;

	// ProcFS entry
	proc_logger = proc_create(PROC_NAME, S_IRUGO, NULL, &logger_ops);
	if (!proc_logger)
		return -ENOMEM;

	return 0;
}

static void __exit cleanup_tsc_logger(void)
{
	remove_proc_entry(PROC_NAME, NULL);
	vfree(allocated);
}

module_init(setup_tsc_logger);
module_exit(cleanup_tsc_logger);


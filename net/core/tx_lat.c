// SPDX-License-Identifier: GPL-2.0
/*
 * Outbound-path latency histograms (experiment) -- see include/net/tx_lat.h.
 *
 * Each TX data skb carries one rolling timestamp (skb->tx_lat_ns), reused
 * across stages: set at creation, read+rewritten at xmit (recording the
 * create->xmit interval), read at ACK-free (recording the xmit->ACK interval).
 * The hooks only ever run on real TCP TX data skbs (the transmit hook fires
 * only for the cloned original, the free hook only for rtx-queue skbs), so no
 * per-skb "was it stamped" flag is needed; a sanity clamp drops any stray
 * unstamped straggler (e.g. instrumentation enabled mid-flight).
 *
 * Gated off by default: zero overhead until enabled via debugfs.
 */
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/smp.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/timekeeping.h>
#include <linux/log2.h>
#include <linux/string.h>
#include <net/tx_lat.h>

#define TX_LAT_BUCKETS	40			/* log2(ns): 1ns .. ~1000s */
#define TX_LAT_SANE_NS	(10ULL * NSEC_PER_SEC)	/* ignore absurd (unstamped) samples */

static bool tx_lat_on;
/* Per-CPU rows (contention-free writes, summed at read). */
static u64 tx_lat_create_hist[NR_CPUS][TX_LAT_BUCKETS];
static u64 tx_lat_ack_hist[NR_CPUS][TX_LAT_BUCKETS];
static u64 tx_lat_rx_hist[NR_CPUS][TX_LAT_BUCKETS];
static u64 tx_lat_app_hist[NR_CPUS][TX_LAT_BUCKETS];
static u64 tx_lat_napi_hist[NR_CPUS][TX_LAT_BUCKETS];
static u64 tx_lat_deliver_hist[NR_CPUS][TX_LAT_BUCKETS];

static void tx_lat_bump(u64 (*hist)[TX_LAT_BUCKETS], u64 delta)
{
	int b;

	if (delta >= TX_LAT_SANE_NS)
		return;
	b = delta ? ilog2(delta) : 0;
	if (b >= TX_LAT_BUCKETS)
		b = TX_LAT_BUCKETS - 1;
	hist[raw_smp_processor_id()][b]++;
}

void tx_lat_stamp(struct sk_buff *skb)
{
	if (!READ_ONCE(tx_lat_on))
		return;
	skb->tx_lat_ns = ktime_get_mono_fast_ns();
}

void tx_lat_xmit(struct sk_buff *skb)
{
	u64 now;

	if (!READ_ONCE(tx_lat_on) || !skb->tx_lat_ns)
		return;
	now = ktime_get_mono_fast_ns();
	tx_lat_bump(tx_lat_create_hist, now - skb->tx_lat_ns);
	skb->tx_lat_ns = now;		/* restart the clock for the xmit->ACK leg */
}

void tx_lat_free(struct sk_buff *skb)
{
	if (!READ_ONCE(tx_lat_on) || !skb->tx_lat_ns)
		return;
	tx_lat_bump(tx_lat_ack_hist, ktime_get_mono_fast_ns() - skb->tx_lat_ns);
}

void tx_lat_rx_stamp(struct sk_buff *skb)
{
	if (!READ_ONCE(tx_lat_on))
		return;
	skb->tx_lat_ns = ktime_get_mono_fast_ns();	/* arrival at the stack */
}

void tx_lat_rx_done(struct sk_buff *skb)
{
	if (!READ_ONCE(tx_lat_on) || !skb->tx_lat_ns)
		return;
	tx_lat_bump(tx_lat_rx_hist, ktime_get_mono_fast_ns() - skb->tx_lat_ns);
}

void tx_lat_app_ready(u64 *slot)
{
	if (!READ_ONCE(tx_lat_on))
		return;
	*slot = ktime_get_mono_fast_ns();
}

void tx_lat_app_done(u64 *slot)
{
	if (!READ_ONCE(tx_lat_on) || !*slot)
		return;
	tx_lat_bump(tx_lat_app_hist, ktime_get_mono_fast_ns() - *slot);
	*slot = 0;	/* one sample per data-ready */
}

void tx_lat_napi_sched(u64 *slot)
{
	if (!READ_ONCE(tx_lat_on))
		return;
	*slot = ktime_get_mono_fast_ns();
}

void tx_lat_napi_dispatch(u64 *slot)
{
	if (!READ_ONCE(tx_lat_on) || !*slot)
		return;
	tx_lat_bump(tx_lat_napi_hist, ktime_get_mono_fast_ns() - *slot);
	*slot = 0;	/* one sample per idle->scheduled; repolls skipped */
}

void tx_lat_deliver_stamp(u64 *slot)
{
	if (!READ_ONCE(tx_lat_on))
		return;
	*slot = ktime_get_mono_fast_ns();
}

void tx_lat_deliver_done(u64 *slot)
{
	if (!READ_ONCE(tx_lat_on) || !*slot)
		return;
	tx_lat_bump(tx_lat_deliver_hist, ktime_get_mono_fast_ns() - *slot);
	*slot = 0;
}

static void tx_lat_dump(struct seq_file *s, u64 (*hist)[TX_LAT_BUCKETS])
{
	u64 sum[TX_LAT_BUCKETS] = {0};
	int cpu, b;

	for_each_possible_cpu(cpu)
		for (b = 0; b < TX_LAT_BUCKETS; b++)
			sum[b] += hist[cpu][b];
	for (b = 0; b < TX_LAT_BUCKETS; b++)
		if (sum[b])
			seq_printf(s, "%llu %llu\n", 1ULL << (b + 1), sum[b]);
}

static int tx_lat_show(struct seq_file *s, void *v)
{
	seq_printf(s, "on %d\n", tx_lat_on);
	seq_puts(s, "=create upper_ns count\n");
	tx_lat_dump(s, tx_lat_create_hist);
	seq_puts(s, "=ack upper_ns count\n");
	tx_lat_dump(s, tx_lat_ack_hist);
	seq_puts(s, "=rx upper_ns count\n");
	tx_lat_dump(s, tx_lat_rx_hist);
	seq_puts(s, "=app upper_ns count\n");
	tx_lat_dump(s, tx_lat_app_hist);
	seq_puts(s, "=napi upper_ns count\n");
	tx_lat_dump(s, tx_lat_napi_hist);
	seq_puts(s, "=deliver upper_ns count\n");
	tx_lat_dump(s, tx_lat_deliver_hist);
	return 0;
}

static int tx_lat_open(struct inode *inode, struct file *file)
{
	return single_open(file, tx_lat_show, NULL);
}

/* Any write sets the gate to the given int (0/1) and resets the histograms. */
static ssize_t tx_lat_write(struct file *file, const char __user *ubuf,
			    size_t len, loff_t *off)
{
	int on, ret;

	ret = kstrtoint_from_user(ubuf, len, 10, &on);
	if (ret)
		return ret;

	memset(tx_lat_create_hist, 0, sizeof(tx_lat_create_hist));
	memset(tx_lat_ack_hist, 0, sizeof(tx_lat_ack_hist));
	memset(tx_lat_rx_hist, 0, sizeof(tx_lat_rx_hist));
	memset(tx_lat_app_hist, 0, sizeof(tx_lat_app_hist));
	memset(tx_lat_napi_hist, 0, sizeof(tx_lat_napi_hist));
	memset(tx_lat_deliver_hist, 0, sizeof(tx_lat_deliver_hist));
	WRITE_ONCE(tx_lat_on, !!on);
	return len;
}

static const struct file_operations tx_lat_fops = {
	.owner		= THIS_MODULE,
	.open		= tx_lat_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= tx_lat_write,
};

static int __init tx_lat_init(void)
{
	debugfs_create_file("tx_lat", 0644, NULL, NULL, &tx_lat_fops);
	return 0;
}
late_initcall(tx_lat_init);

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Outbound-path latency instrumentation (experiment). Two in-kernel histograms
 * over TCP TX data skbs, compared between baseline and upcall to rule the send
 * side of the tcp/driver stack in or out of the ~900k-1.4M-QPS latency bump:
 *   create : skb creation (tcp_stream_alloc_skb) -> xmit (__tcp_transmit_skb)
 *   ack    : xmit -> free on ACK (tcp_clean_rtx_queue)
 * Gated off by default; toggle/read/reset via debugfs /sys/kernel/debug/tx_lat.
 */
#ifndef _NET_TX_LAT_H
#define _NET_TX_LAT_H

struct sk_buff;

void tx_lat_stamp(struct sk_buff *skb);	/* TX: creation */
void tx_lat_xmit(struct sk_buff *skb);	/* TX: leaving TCP toward the wire */
void tx_lat_free(struct sk_buff *skb);	/* TX: freed on ACK */

/* RX side: arrival (stack entry, __netif_receive_skb_core) -> data queued to
 * the socket (tcp_queue_rcv, ~= post_event). Reuses skb->tx_lat_ns (an skb is
 * TX xor RX in its lifetime). */
void tx_lat_rx_stamp(struct sk_buff *skb);
void tx_lat_rx_done(struct sk_buff *skb);

/* App side: data-ready on a socket -> response skb allocated for it, i.e. the
 * full per-request "sk_data_ready -> worker woken -> processed -> sendmsg"
 * path. `slot` is &tcp_sk(sk)->app_ready_ns; done clears it (one sample per
 * data-ready). */
void tx_lat_app_ready(u64 *slot);
void tx_lat_app_done(u64 *slot);

/* NAPI dispatch delay: a napi instance queued for polling (____napi_schedule)
 * -> its poll actually running (__napi_poll). Measures the softirq/ksoftirqd
 * dispatch gap -- how long a "packet ready" signal waits for the CPU to run
 * the poll, which is deferred when a pinned worker occupies the core. `slot`
 * is &napi->sched_ns; dispatch clears it (one sample per idle->scheduled). */
void tx_lat_napi_sched(u64 *slot);
void tx_lat_napi_dispatch(u64 *slot);

/* Upcall event delivery delay: post_event (event ready, enqueued to a channel)
 * -> dequeue in do_upcall_submit (picked up by the worker). The pure wait
 * before processing. `slot` is &anchor->post_ns; done clears it. */
void tx_lat_deliver_stamp(u64 *slot);
void tx_lat_deliver_done(u64 *slot);

#endif /* _NET_TX_LAT_H */

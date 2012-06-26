#undef TRACE_SYSTEM
#define TRACE_SYSTEM addons

#if !defined(LTTNG_NET_H_) || defined(TRACE_HEADER_MULTI_READ)
#define LTTNG_NET_H_

#include <linux/tracepoint.h>
#include <net/sock.h>
#include <linux/tcp.h>

TRACE_EVENT(inet_sock_create,

	TP_PROTO(struct sock *sk),

	TP_ARGS(sk),

	TP_STRUCT__entry(
		__field_hex(struct sock *, sk)
	),

	TP_fast_assign(
		tp_assign(sk, sk)
	),

	TP_printk("%p", __entry->sk)
)

TRACE_EVENT(inet_sock_delete,

	TP_PROTO(struct sock *sk),

	TP_ARGS(sk),

	TP_STRUCT__entry(
		__field_hex(struct sock *, sk)
	),

	TP_fast_assign(
		tp_assign(sk, sk)
	),

	TP_printk("%p", __entry->sk)
)

TRACE_EVENT(inet_sock_clone,

	TP_PROTO(struct sock *osk, struct sock *nsk),

	TP_ARGS(osk, nsk),

	TP_STRUCT__entry(
		__field_hex(struct sock *, osk)
		__field_hex(struct sock *, nsk)
	),

	TP_fast_assign(
		tp_assign(osk, osk)
		tp_assign(nsk, nsk)
	),

	TP_printk("%p %p", __entry->osk, __entry->nsk)
)

TRACE_EVENT(inet_accept,
	TP_PROTO(struct sock *sk, uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport),
	TP_ARGS(sk, saddr, daddr, sport, dport),
	TP_STRUCT__entry(
		__field_hex(struct sock *, sk)
		__field_network_hex(uint32_t, saddr)
		__field_network_hex(uint32_t, daddr)
		__field_network_hex(uint16_t, sport)
		__field_network_hex(uint16_t, dport)
	),
	TP_fast_assign(
		tp_assign(sk, sk)
		tp_assign(saddr, saddr)
		tp_assign(daddr, daddr)
		tp_assign(sport, sport)
		tp_assign(dport, dport)
	),
	TP_printk("%p %x %x %x %x", __entry->sk, __entry->saddr, __entry->daddr
			__entry->sport, __entry->dport)
)

TRACE_EVENT(inet_connect,
	TP_PROTO(struct sock *sk, uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport),
	TP_ARGS(sk, saddr, daddr, sport, dport),
	TP_STRUCT__entry(
		__field_hex(struct sock *, sk)
		__field_network_hex(uint32_t, saddr)
		__field_network_hex(uint32_t, daddr)
		__field_network_hex(uint16_t, sport)
		__field_network_hex(uint16_t, dport)
	),
	TP_fast_assign(
		tp_assign(sk, sk)
		tp_assign(saddr, saddr)
		tp_assign(daddr, daddr)
		tp_assign(sport, sport)
		tp_assign(dport, dport)
	),
	TP_printk("%p %x %x %x %x", __entry->sk, __entry->saddr, __entry->daddr
			__entry->sport, __entry->dport)
)

TRACE_EVENT(inet_sock_local_in,
	TP_PROTO(struct sock *sk, struct tcphdr *tcph),
	TP_ARGS(sk, tcph),
	TP_STRUCT__entry(
		__field_hex(struct sock *, sk)
		__field_network_hex(uint32_t, seq)
		__field_network_hex(uint32_t, ack_seq)
	),
	TP_fast_assign(
		tp_assign(sk, sk)
		tp_assign(seq, tcph->seq)
		tp_assign(ack_seq, tcph->ack_seq)
	),
	TP_printk("%p %x %x", __entry->sk, __entry->seq, __entry->ack_seq)
)

TRACE_EVENT(inet_sock_local_out,
	TP_PROTO(struct sock *sk, struct tcphdr *tcph),
	TP_ARGS(sk, tcph),
	TP_STRUCT__entry(
		__field_hex(struct sock *, sk)
		__field_network_hex(uint32_t, seq)
		__field_network_hex(uint32_t, ack_seq)
	),
	TP_fast_assign(
		tp_assign(sk, sk)
		tp_assign(seq, tcph->seq)
		tp_assign(ack_seq, tcph->ack_seq)
	),
	TP_printk("%p %x %x", __entry->sk, __entry->seq, __entry->ack_seq)
)

#endif /* LTTNG_NET_H_ */

/* This part must be outside protection */
#include "../../../probes/define_trace.h"

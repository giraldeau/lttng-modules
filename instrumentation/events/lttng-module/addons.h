#undef TRACE_SYSTEM
#define TRACE_SYSTEM addons

#if !defined(LTTNG_ADDONS_H_) || defined(TRACE_HEADER_MULTI_READ)
#define LTTNG_ADDONS_H_

#include "../../../probes/lttng-tracepoint-event.h"
#include <linux/tcp.h>
#include <net/sock.h>

LTTNG_TRACEPOINT_EVENT_CLASS(inet_sock_local_template,
	TP_PROTO(struct sock *sk, struct tcphdr *tcph),
	TP_ARGS(sk, tcph),
	TP_STRUCT__entry(
		__field_hex(struct sock *, sk)
		__field_network_hex(uint32_t, seq)
		__field_network_hex(uint32_t, ack_seq)
		__field_network_hex(uint16_t, check)
		__field_network_hex(uint16_t, window)
		__field_network_hex(uint16_t, flags)
	),
	TP_fast_assign(
		tp_assign(sk, sk)
		tp_assign(seq, tcph->seq)
		tp_assign(ack_seq, tcph->ack_seq)
		tp_assign(check, tcph->check)
		tp_assign(window, tcph->window)
		tp_assign(flags, *(((uint16_t *)tcph) + 6)) // flags are in network order
	),
	TP_printk("%p %x %x %x %x %x", __entry->sk, __entry->seq, __entry->ack_seq,
			__entry->check, __entry->window, __entry->flags)
)

LTTNG_TRACEPOINT_EVENT_INSTANCE(inet_sock_local_template, inet_sock_local_in,
	TP_PROTO(struct sock *sk, struct tcphdr *tcph),
	TP_ARGS(sk, tcph))

LTTNG_TRACEPOINT_EVENT_INSTANCE(inet_sock_local_template, inet_sock_local_out,
	TP_PROTO(struct sock *sk, struct tcphdr *tcph),
	TP_ARGS(sk, tcph))


#endif /* LTTNG_ADDONS_H_ */

/* This part must be outside protection */
#include "../../../probes/define_trace.h"

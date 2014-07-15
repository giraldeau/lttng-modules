#undef TRACE_SYSTEM
#define TRACE_SYSTEM addons

#if !defined(LTTNG_NET_H_) || defined(TRACE_HEADER_MULTI_READ)
#define LTTNG_NET_H_

#include <linux/tracepoint.h>
#include <net/sock.h>
#include <linux/tcp.h>

TRACE_EVENT(inet_sock_local_in,
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
#if defined(__LITTLE_ENDIAN_BITFIELD)
		tp_assign(flags, (tcph->cwr << 15) + (tcph->ece << 14) + (tcph->urg << 13) +
				(tcph->ack << 12) + (tcph->psh << 11) + (tcph->rst << 10) +
				(tcph->syn << 9) + (tcph->fin << 8)  + (tcph->doff << 4) + (tcph->res1) )
#elif defined(__BIG_ENDIAN_BITFIELD)
		tp_assign(flags, (tcph->doff << 12) + (tcph->res1 << 8) + (tcph->cwr << 7) +
				(tcph->ece << 6) + (tcph->urg << 5) + (tcph->ack << 4) + (tcph->psh << 3) +
				(tcph->rst << 2) + (tcph->syn << 1) + (tcph->fin) )
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
	),
	TP_printk("%p %x %x %x %x %x", __entry->sk, __entry->seq, __entry->ack_seq,
			__entry->check, __entry->window, __entry->flags)
)

TRACE_EVENT(inet_sock_local_out,
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
#if defined(__LITTLE_ENDIAN_BITFIELD)
		tp_assign(flags, (tcph->cwr << 15) + (tcph->ece << 14) + (tcph->urg << 13) +
				(tcph->ack << 12) + (tcph->psh << 11) + (tcph->rst << 10) +
				(tcph->syn << 9) + (tcph->fin << 8)  + (tcph->doff << 4) + (tcph->res1) )
#elif defined(__BIG_ENDIAN_BITFIELD)
			tp_assign(flags, (tcph->doff << 12) + (tcph->res1 << 8) + (tcph->cwr << 7) +
				(tcph->ece << 6) + (tcph->urg << 5) + (tcph->ack << 4) + (tcph->psh << 3) +
				(tcph->rst << 2) + (tcph->syn << 1) + (tcph->fin) )
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
	),
	TP_printk("%p %x %x %x %x %x", __entry->sk, __entry->seq, __entry->ack_seq,
			__entry->check, __entry->window, __entry->flags)
)

TRACE_EVENT(mmap_exec_file,
		TP_PROTO(const char *name, unsigned long start, unsigned long len, unsigned long pgoff),
		TP_ARGS(name, start, len, pgoff),
		TP_STRUCT__entry(
			__string(name, name)
			__field_hex(unsigned long, start)
			__field_hex(unsigned long, len)
			__field_hex(unsigned long, pgoff)
		),
		TP_fast_assign(
			tp_strcpy(name, name)
			tp_assign(start, start)
			tp_assign(len, len)
			tp_assign(pgoff, pgoff)
		),
		TP_printk("%s %x %x %x", __entry->name, __entry->start, __entry->len, __entry->pgoff)
)

TRACE_EVENT(sys_entry,
	TP_PROTO(short id),
	TP_ARGS(id),
	TP_STRUCT__entry(
		__field(short, id)
	),
	TP_fast_assign(
		tp_assign(id, id)
	),
	TP_printk("%d", __entry->id)
)

TRACE_EVENT(sys_entry_callsite,
	TP_PROTO(int id),
	TP_ARGS(id),
	TP_STRUCT__entry(
		__field(short, id)
		__dynamic_array_hex(unsigned long, callsite, ({
			extern int stack_trace_get_size(void);
			int x = stack_trace_get_size();
			x;
		}))
	),
	TP_fast_assign(
		tp_assign(id, id)
		tp_memcpy_dyn(callsite, ({
			extern unsigned long *stack_trace_get_entries(void);
			unsigned long *entries = stack_trace_get_entries();
			entries;
		}))
	),
	TP_printk("%d", __entry->id)
)

TRACE_EVENT(sched_ttwu,
	TP_PROTO(int tid),
	TP_ARGS(tid),
	TP_STRUCT__entry(
		__field(int, tid)
	),
	TP_fast_assign(
		tp_assign(tid, tid)
	),
	TP_printk("%d", __entry->tid)
)

TRACE_EVENT(vmsync_gh_guest,
	TP_PROTO(unsigned int cnt),
	TP_ARGS(cnt),
	TP_STRUCT__entry(
		__field(unsigned int, cnt)
	),
	TP_fast_assign(
		tp_assign(cnt, cnt)
	),
	TP_printk("%u", __entry->cnt)
)

TRACE_EVENT(vmsync_gh_host,
	TP_PROTO(unsigned int cnt),
	TP_ARGS(cnt),
	TP_STRUCT__entry(
		__field(unsigned int, cnt)
	),
	TP_fast_assign(
		tp_assign(cnt, cnt)
	),
	TP_printk("%u", __entry->cnt)
)

TRACE_EVENT(vmsync_hg_guest,
		TP_PROTO(unsigned int cnt),
		TP_ARGS(cnt),
		TP_STRUCT__entry(
			__field(unsigned int, cnt)
			),
		TP_fast_assign(
			tp_assign(cnt, cnt)
			),
		TP_printk("%u", __entry->cnt)
		)

TRACE_EVENT(vmsync_hg_host,
		TP_PROTO(unsigned int cnt),
		TP_ARGS(cnt),
		TP_STRUCT__entry(
			__field(unsigned int, cnt)
			),
		TP_fast_assign(
			tp_assign(cnt, cnt)
			),
		TP_printk("%u", __entry->cnt)
)

#endif /* LTTNG_NET_H_ */

/* This part must be outside protection */
#include "../../../probes/define_trace.h"

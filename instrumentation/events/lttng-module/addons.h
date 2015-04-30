#undef TRACE_SYSTEM
#define TRACE_SYSTEM addons

#if !defined(LTTNG_NET_H_) || defined(TRACE_HEADER_MULTI_READ)
#define LTTNG_NET_H_

#include <linux/tracepoint.h>
#include <linux/stacktrace.h>
#include <net/sock.h>
#include <linux/tcp.h>

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>

#include <linux/sched.h>
#include <linux/binfmts.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0))
#include <linux/sched/rt.h>
#endif

DECLARE_EVENT_CLASS(inet_sock_local_template,
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

DEFINE_EVENT(inet_sock_local_template, inet_sock_local_in,
		TP_PROTO(struct sock *sk, struct tcphdr *tcph),
		TP_ARGS(sk, tcph))

DEFINE_EVENT(inet_sock_local_template, inet_sock_local_out,
		TP_PROTO(struct sock *sk, struct tcphdr *tcph),
		TP_ARGS(sk, tcph))

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
			extern int lttng_stack_trace_get_size(void);
			int x = lttng_stack_trace_get_size();
			x;
		}))
	),
	TP_fast_assign(
		tp_assign(id, id)
		tp_memcpy_dyn(callsite, ({
			extern unsigned long *lttng_stack_trace_get_entries(void);
			unsigned long *entries = lttng_stack_trace_get_entries();
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
	TP_PROTO(unsigned int cnt, unsigned long vm_uid),
	TP_ARGS(cnt, vm_uid),
	TP_STRUCT__entry(
		__field(unsigned int, cnt)
		__field(unsigned long, vm_uid)
	),
	TP_fast_assign(
		tp_assign(cnt, cnt)
		tp_assign(vm_uid, vm_uid)
	),
	TP_printk("%u %lu", __entry->cnt, __entry->vm_uid)
)

TRACE_EVENT(vmsync_gh_host,
	TP_PROTO(unsigned int cnt, unsigned long vm_uid),
	TP_ARGS(cnt, vm_uid),
	TP_STRUCT__entry(
		__field(unsigned int, cnt)
		__field(unsigned long, vm_uid)
	),
	TP_fast_assign(
		tp_assign(cnt, cnt)
		tp_assign(vm_uid, vm_uid)
	),
	TP_printk("%u %lu", __entry->cnt, __entry->vm_uid)
)

TRACE_EVENT(vmsync_hg_guest,
	TP_PROTO(unsigned int cnt, unsigned long vm_uid),
	TP_ARGS(cnt, vm_uid),
	TP_STRUCT__entry(
		__field(unsigned int, cnt)
		__field(unsigned long, vm_uid)
	),
	TP_fast_assign(
		tp_assign(cnt, cnt)
		tp_assign(vm_uid, vm_uid)
	),
	TP_printk("%u %lu", __entry->cnt, __entry->vm_uid)
)

TRACE_EVENT(vmsync_hg_host,
		TP_PROTO(unsigned int cnt, unsigned long vm_uid),
		TP_ARGS(cnt, vm_uid),
		TP_STRUCT__entry(
			__field(unsigned int, cnt)
			__field(unsigned long, vm_uid)
			),
		TP_fast_assign(
			tp_assign(cnt, cnt)
			tp_assign(vm_uid, vm_uid)
			),
		TP_printk("%u %lu", __entry->cnt, __entry->vm_uid)
)

DECLARE_EVENT_CLASS(net_dev_filter_template,

	TP_PROTO(struct sk_buff *skb),

	TP_ARGS(skb),

	TP_STRUCT__entry(
		__field(	void *,		skbaddr		)
		__field(	unsigned int,	len		)
		__string(	name,		skb->dev->name	)
	),

	TP_fast_assign(
		tp_assign(skbaddr, skb)
		tp_assign(len, skb->len)
		tp_strcpy(name, skb->dev->name)
	),

	TP_printk("dev=%s skbaddr=%p len=%u",
		__get_str(name), __entry->skbaddr, __entry->len)
)

DEFINE_EVENT(net_dev_filter_template, netif_receive_skb_filter,

	TP_PROTO(struct sk_buff *skb),

	TP_ARGS(skb)
)
/*
TRACE_EVENT(netif_receive_skb_more,

	TP_PROTO(struct sk_buff *skb),

	TP_ARGS(skb),

	TP_STRUCT__entry(
		__field(	void *,		skbaddr		)
		__field(	unsigned int,	len		)
		__string(	name,		skb->dev->name	)
		__field(	unsigned int,	protocol	)
	),

	TP_fast_assign(
		tp_assign(skbaddr, skb)
		tp_assign(len, skb->len)
		tp_strcpy(name, skb->dev->name)
		tp_assign(protocol, skb->protocol)
	),

	TP_printk("dev=%s skbaddr=%p len=%u prot=%u",
		__get_str(name), __entry->skbaddr, __entry->len)
)
*/

#ifndef _TRACE_SCHED_DEF_
#define _TRACE_SCHED_DEF_

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0))

static inline long __trace_sched_switch_state(struct task_struct *p)
{
        long state = p->state;

#ifdef CONFIG_PREEMPT
        /*
 *          * For all intents and purposes a preempted task is a running task.
 *                   */
        if (task_preempt_count(p) & PREEMPT_ACTIVE)
                state = TASK_RUNNING | TASK_STATE_MAX;
#endif

        return state;
}

#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0))

static inline long __trace_sched_switch_state(struct task_struct *p)
{
        long state = p->state;

#ifdef CONFIG_PREEMPT
        /*
 *          * For all intents and purposes a preempted task is a running task.
 *                   */
        if (task_thread_info(p)->preempt_count & PREEMPT_ACTIVE)
                state = TASK_RUNNING | TASK_STATE_MAX;
#endif

        return state;
}

#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35))

static inline long __trace_sched_switch_state(struct task_struct *p)
{
        long state = p->state;

#ifdef CONFIG_PREEMPT
        /*
 *          * For all intents and purposes a preempted task is a running task.
 *                   */
        if (task_thread_info(p)->preempt_count & PREEMPT_ACTIVE)
                state = TASK_RUNNING;
#endif

        return state;
}

#endif

#endif /* _TRACE_SCHED_DEF_ */

TRACE_EVENT(sched_switch_filter,

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35))
        TP_PROTO(struct task_struct *prev,
                 struct task_struct *next),

        TP_ARGS(prev, next),
#else /* #if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)) */
        TP_PROTO(struct rq *rq, struct task_struct *prev,
                 struct task_struct *next),

        TP_ARGS(rq, prev, next),
#endif /* #if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)) */

        TP_STRUCT__entry(
                __array_text(   char,   prev_comm,      TASK_COMM_LEN   )
                __field(        pid_t,  prev_tid                        )
                __field(        int,    prev_prio                       )
                __field(        long,   prev_state                      )
                __array_text(   char,   next_comm,      TASK_COMM_LEN   )
                __field(        pid_t,  next_tid                        )
                __field(        int,    next_prio                       )
        ),

        TP_fast_assign(
                tp_memcpy(next_comm, next->comm, TASK_COMM_LEN)
                tp_assign(prev_tid, prev->pid)
                tp_assign(prev_prio, prev->prio - MAX_RT_PRIO)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35))
                tp_assign(prev_state, __trace_sched_switch_state(prev))
#else
                tp_assign(prev_state, prev->state)
#endif
                tp_memcpy(prev_comm, prev->comm, TASK_COMM_LEN)
                tp_assign(next_tid, next->pid)
                tp_assign(next_prio, next->prio - MAX_RT_PRIO)
        ),

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0))
        TP_printk("prev_comm=%s prev_tid=%d prev_prio=%d prev_state=%s%s ==> next_comm=%s next_tid=%d next_prio=%d",
                __entry->prev_comm, __entry->prev_tid, __entry->prev_prio,
                __entry->prev_state & (TASK_STATE_MAX-1) ?
                  __print_flags(__entry->prev_state & (TASK_STATE_MAX-1), "|",
                                { 1, "S"} , { 2, "D" }, { 4, "T" }, { 8, "t" },
                                { 16, "Z" }, { 32, "X" }, { 64, "x" },
                                { 128, "W" }) : "R",
                __entry->prev_state & TASK_STATE_MAX ? "+" : "",
                __entry->next_comm, __entry->next_tid, __entry->next_prio)
#else
        TP_printk("prev_comm=%s prev_tid=%d prev_prio=%d prev_state=%s ==> next_comm=%s next_tid=%d next_prio=%d",
                __entry->prev_comm, __entry->prev_tid, __entry->prev_prio,
                __entry->prev_state ?
                  __print_flags(__entry->prev_state, "|",
                                { 1, "S"} , { 2, "D" }, { 4, "T" }, { 8, "t" },
                                { 16, "Z" }, { 32, "X" }, { 64, "x" },
                                { 128, "W" }) : "R",
                __entry->next_comm, __entry->next_tid, __entry->next_prio)
#endif
)

#endif /* LTTNG_NET_H_ */

/* This part must be outside protection */
#include "../../../probes/define_trace.h"

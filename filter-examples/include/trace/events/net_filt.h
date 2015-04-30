/* subsystem name is "net_filt" */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM net_filt

#if !defined(_TRACE_NET_FILT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_NET_FILT_H

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tracepoint.h>

TRACE_EVENT(net_filt,

	TP_PROTO(struct sk_buff *skb),

	TP_ARGS(skb),

	TP_STRUCT__entry(
		__field(	void *,		skbaddr		)
		__field(	unsigned int,	len		)
		__string(	name,		skb->dev->name	)
	),

	TP_fast_assign(
		__entry->skbaddr = skb;
		__entry->len = skb->len;
		__assign_str(name, skb->dev->name);
	),

	TP_printk("dev=%s skbaddr=%p len=%u",
		__get_str(name), __entry->skbaddr, __entry->len)
);

#endif /* _TRACE_NET_FILT_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

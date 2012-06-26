#undef TRACE_SYSTEM
#define TRACE_SYSTEM net

#if !defined(LTTNG_NET_H_) || defined(TRACE_HEADER_MULTI_READ)
#define LTTNG_NET_H_

#include <linux/tracepoint.h>

TRACE_EVENT(lttng_net,

	TP_PROTO(int num),

	TP_ARGS(num),

	TP_STRUCT__entry(
		__field(int, num)
	),

	TP_fast_assign(
		tp_assign(num, num)
	),

	TP_printk("%d", __entry->num)
)

#endif /* UEVENT_H_ */

/* This part must be outside protection */
#include "../../../probes/define_trace.h"

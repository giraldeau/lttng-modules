#undef TRACE_SYSTEM
#define TRACE_SYSTEM uevent

#if !defined(UEVENT_H_) || defined(TRACE_HEADER_MULTI_READ)
#define UEVENT_H_

#include <linux/tracepoint.h>

TRACE_EVENT(lttng_uevent,

	TP_PROTO(const char *str, size_t len),

	TP_ARGS(str, len),

	/*
	 * Uses sequence to hold variable size data, by default considered
	 * as text. Null-terminal character is optional and is not enforced.
	 */
	TP_STRUCT__entry(
		__dynamic_array_text(char, text, len)
	),

	TP_fast_assign(
		tp_memcpy_dyn_from_user(text, str)
	),

	TP_printk("")
)

#endif /* UEVENT_H_ */

/* This part must be outside protection */
#include "../../../probes/define_trace.h"

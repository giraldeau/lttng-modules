#undef TRACE_SYSTEM
#define TRACE_SYSTEM ekm

#if !defined(LTTNG_EKM_H_) || defined(TRACE_HEADER_MULTI_READ)
#define LTTNG_EKM_H_

#include "../../../probes/lttng-tracepoint-event.h"

LTTNG_TRACEPOINT_EVENT(ekm_lucky_int,
	TP_PROTO(int arg1),
	TP_ARGS(arg1),
	TP_FIELDS(
		ctf_integer(int, field1, arg1)
	)
)

#endif /* LTTNG_EKM_H_ */

/* This part must be outside protection */
#include "../../../probes/define_trace.h"

#undef TRACE_SYSTEM
#define TRACE_SYSTEM addons

#if !defined(LTTNG_ADDONS_H_) || defined(TRACE_HEADER_MULTI_READ)
#define LTTNG_ADDONS_H_

#include <linux/tracepoint.h>

#endif /* LTTNG_ADDONS_H_ */

/* This part must be outside protection */
#include "../../../probes/define_trace.h"

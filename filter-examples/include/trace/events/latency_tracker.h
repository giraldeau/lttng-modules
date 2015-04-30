/* subsystem name is "latency_tracker" */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM latency_tracker

#if !defined(_TRACE_LATENCY_TRACKER_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_LATENCY_TRACKER_H

#include <linux/tracepoint.h>

TRACE_EVENT(
  syscall_latency,
  TP_PROTO(u64 start_ts, u64 duration, int id),
  TP_ARGS(start_ts, duration, id),
  TP_STRUCT__entry(
    __field(u64, start_ts)
    __field(u64, duration)
    __field(int, id)
    ),
  TP_fast_assign(
    entry->start_ts = start_ts;
    entry->duration = duration;
    entry->id = id;
    ),
  TP_printk("start_ts=%llu, duration=%llu, id=%d",
    __entry->start_ts, __entry->duration, __entry->id)
   );

#endif /* _TRACE_LATENCY_TRACKER_H */

/* this part must be outside protection */
#include <trace/define_trace.h>

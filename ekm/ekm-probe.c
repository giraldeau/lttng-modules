/*
 * ekm-probe.c
 *
 *  Created on: Aug 23, 2015
 *      Author: francis
 */

#include <linux/module.h>

/*
 * Create tracepoint probes.
 */
#define LTTNG_PACKAGE_BUILD
#define CREATE_TRACE_POINTS
#define TRACE_INCLUDE_PATH ../instrumentation/events/lttng-module

#include "../instrumentation/events/lttng-module/ekm.h"

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Put Your Name Here");
MODULE_DESCRIPTION("Ericsson Kernel Module Probe");




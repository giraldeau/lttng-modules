/*
 * lttng-stacktrace.h
 *
 *  Created on: 22 août 2014
 *      Author: francis
 */

#ifndef LTTNG_STACKTRACE_H_
#define LTTNG_STACKTRACE_H_

#define MAX_ENTRIES 10

int lttng_stack_trace_init(void);
int lttng_stack_trace_alloc(int max_entries);
void lttng_stack_trace_free(void);
int lttng_stack_trace_get_size(void);
unsigned long *lttng_stack_trace_get_entries(void);

#endif /* LTTNG_STACKTRACE_H_ */

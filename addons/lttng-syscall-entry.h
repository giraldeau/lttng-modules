/*
 * lttng-syscall-entry.h
 *
 *  Created on: 2013-08-31
 *      Author: francis
 */

#ifndef LTTNG_SYSCALL_ENTRY_H_
#define LTTNG_SYSCALL_ENTRY_H_

int stack_trace_get_size(void);
unsigned long *stack_trace_get_entries(void);

#endif /* LTTNG_SYSCALL_ENTRY_H_ */

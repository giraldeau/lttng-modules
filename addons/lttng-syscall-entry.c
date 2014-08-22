/*
 * addons/lttng-syscall-entry.c
 *
 * Record system call entry
 *
 * Copyright (C) 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/stacktrace.h>
#include <asm/ptrace.h>
#include <asm/syscall.h>

#include "lttng-stacktrace.h"
#include "../wrapper/tracepoint.h"
#include "../wrapper/kallsyms.h"
#include "../lttng-abi.h"
#include "../instrumentation/events/lttng-module/addons.h"

DEFINE_TRACE(sys_entry);
DEFINE_TRACE(sys_entry_callsite);

static void syscall_entry_handler(void *__data, struct pt_regs *regs, long id)
{
	trace_sys_entry(id);

	preempt_disable();
	trace_sys_entry_callsite(id);
	preempt_enable();
}

static int __init lttng_addons_syscall_init(void)
{
	int ret;

	(void) wrapper_lttng_fixup_sig(THIS_MODULE);

	ret = lttng_stack_trace_init();
	if (ret)
		return ret;
	ret = lttng_stack_trace_alloc(MAX_ENTRIES);
	if (ret)
		return ret;

	ret = lttng_wrapper_tracepoint_probe_register("sys_enter",
			syscall_entry_handler, NULL);
	if (ret)
		goto error;
	printk("lttng_addons syscall loaded\n");
	return 0;
error:
lttng_stack_trace_free();
	return -1;
}
module_init(lttng_addons_syscall_init);

static void __exit lttng_addons_syscall_exit(void)
{

	lttng_wrapper_tracepoint_probe_unregister("sys_enter",
			syscall_entry_handler, NULL);
	/*
	 * make sure any currently running probe
	 * has finished before freeing memory
	 */
	synchronize_sched();
	lttng_stack_trace_free();
	printk("lttng_addons syscall removed\n");
}
module_exit(lttng_addons_syscall_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng syscall events");

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

#include "../wrapper/tracepoint.h"
#include "../wrapper/kallsyms.h"
#include "../lttng-abi.h"
#include "../instrumentation/events/lttng-module/addons.h"

DEFINE_TRACE(sys_entry);
DEFINE_TRACE(sys_entry_callsite);

#define MAX_ENTRIES 10

struct stack_trace __percpu *traces;
static void (*save_func)(struct stack_trace *trace);

static
void stack_trace_free(void)
{
	int cpu;

	if (!traces)
		return;
	for_each_possible_cpu(cpu) {
		struct stack_trace *item = per_cpu_ptr(traces, cpu);
		kfree(item->entries);
	}
	free_percpu(traces);
}

static
int stack_trace_alloc(int max_entries)
{
	int cpu;
	struct stack_trace *item;

	traces = alloc_percpu(struct stack_trace);
	if (!traces)
		goto error_alloc;
	for_each_possible_cpu(cpu) {
		item = per_cpu_ptr(traces, cpu);
		item->entries = kzalloc(sizeof(unsigned long) * max_entries, GFP_KERNEL);
		if (!item->entries)
			goto error_alloc;
		item->max_entries = max_entries;
	}
	return 0;

error_alloc:
	stack_trace_free();
	return -ENOMEM;
}

/*
 * Fill struct stack_trace for this CPU and the current task
 *
 * @return size
 */
int stack_trace_get_size(void)
{
	struct stack_trace *item;
	int cpu;

	cpu = get_cpu();
	item = per_cpu_ptr(traces, cpu);
	item->nr_entries = 0;
	save_func(item);
	put_cpu();
	return item->nr_entries;
}
EXPORT_SYMBOL(stack_trace_get_size);

unsigned long *stack_trace_get_entries(void)
{
	struct stack_trace *item;
	int cpu;

	cpu = get_cpu();
	item = per_cpu_ptr(traces, cpu);
	put_cpu();
	return item->entries;
}
EXPORT_SYMBOL(stack_trace_get_entries);

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

	save_func = (void *)kallsyms_lookup_funcptr("save_stack_trace_user");
	if (!save_func)
		return -EINVAL;

	ret = stack_trace_alloc(MAX_ENTRIES);
	if (ret)
		return ret;

	ret = kabi_2635_tracepoint_probe_register("sys_enter",
			syscall_entry_handler, NULL);
	if (ret)
		goto error;
	printk("lttng_addons syscall loaded\n");
	return 0;
error:
	stack_trace_free();
	return -1;
}
module_init(lttng_addons_syscall_init);

static void __exit lttng_addons_syscall_exit(void)
{

	kabi_2635_tracepoint_probe_unregister("sys_enter",
			syscall_entry_handler, NULL);
	/*
	 * make sure any currently running probe
	 * has finished before freeing memory
	 */
	synchronize_sched();
	stack_trace_free();
	printk("lttng_addons syscall removed\n");
}
module_exit(lttng_addons_syscall_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng syscall events");

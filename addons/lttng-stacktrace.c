/*
 * addons/lttng-stacktrace.c
 *
 * Stacktrace storage
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
#include <linux/percpu.h>
#include <linux/slab.h>
#include <asm/ptrace.h>
#include <asm/syscall.h>
#include "../wrapper/kallsyms.h"

struct stack_trace __percpu *traces;
static void (*save_func)(struct stack_trace *trace);

int lttng_stack_trace_init(void)
{
	save_func = (void *)kallsyms_lookup_funcptr("save_stack_trace_user");
	if (!save_func)
		return -EINVAL;
	return 0;
}
EXPORT_SYMBOL(lttng_stack_trace_init);

void lttng_stack_trace_free(void)
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
EXPORT_SYMBOL(lttng_stack_trace_free);

int lttng_stack_trace_alloc(int max_entries)
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
	lttng_stack_trace_free();
	return -ENOMEM;
}
EXPORT_SYMBOL(lttng_stack_trace_alloc);
/*
 * Fill struct stack_trace for this CPU and the current task
 *
 * @return size
 */
int lttng_stack_trace_get_size(void)
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
EXPORT_SYMBOL(lttng_stack_trace_get_size);

unsigned long *lttng_stack_trace_get_entries(void)
{
	struct stack_trace *item;
	int cpu;

	cpu = get_cpu();
	item = per_cpu_ptr(traces, cpu);
	put_cpu();
	return item->entries;
}
EXPORT_SYMBOL(lttng_stack_trace_get_entries);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng stacktrace");

/*
 * lttng-context-callstack.c
 *
 * LTTng callstack context.
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
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/utsname.h>
#include <linux/stacktrace.h>
#include <linux/spinlock.h>
#include "lttng-events.h"
//#include "wrapper/ringbuffer/frontend_types.h"
#include "wrapper/ringbuffer/backend.h"
#include "wrapper/ringbuffer/frontend.h"
#include "wrapper/vmalloc.h"
#include "lttng-tracer.h"

#define MAX_ENTRIES 40
#define MAX_NESTING 4 // defined according to frontend_api.h

struct lttng_cs {
	struct stack_trace items[MAX_NESTING];
};

//static char str[4096];
//DEFINE_SPINLOCK(lock);

static
size_t callstack_get_size(size_t offset, struct lttng_ctx_field *field,
			  struct lib_ring_buffer_ctx *ctx,
			  struct lttng_channel *chan)
{
	size_t size = 0;
	int cpu, nesting;
	struct lttng_cs *cs;
	struct lttng_cs *cs_set = field->data;
	struct stack_trace *trace;
	int i;

	cpu = get_cpu();
	cs = per_cpu_ptr(cs_set, cpu);
	nesting = per_cpu(lib_ring_buffer_nesting, cpu) - 1;
	trace = ctx->data = &cs->items[nesting];
	put_cpu();

	memset(trace->entries, 0, sizeof(unsigned long) * trace->max_entries);
	trace->nr_entries = 0;
	// TEMP: fill with test data
	for (i = 0; i < trace->max_entries; i++) {
		trace->entries[i] = i;
	}
	trace->nr_entries = trace->max_entries;
	//save_stack_trace(trace);

	//printk("ctx=0x%p trace=0x%p\n", ctx, trace);

	size += lib_ring_buffer_align(offset, lttng_alignof(unsigned int));
	size += sizeof(unsigned int);
	size += sizeof(unsigned long) * trace->nr_entries;
	return size;
}

static
void callstack_record(struct lttng_ctx_field *field,
		      struct lib_ring_buffer_ctx *ctx,
		      struct lttng_channel *chan)
{
	int i;
	struct stack_trace *trace = ctx->data;
	int len = trace->nr_entries;

	//printk("trace=0x%p nr_entries=%d\n", trace, trace->nr_entries);
	printk("nr_entries=%d\n", trace->nr_entries);
	chan->ops->event_write(ctx, &len, sizeof(unsigned int));
	for (i = 0; i < trace->nr_entries; i++)
		chan->ops->event_write(ctx, &trace->entries[i], sizeof(unsigned long));
}

static
void callstack_data_free(struct lttng_cs __percpu *cs_set)
{
	int cpu, i;
	struct lttng_cs *cs;

	if (!cs_set)
		return;
	for_each_possible_cpu(cpu) {
		cs = per_cpu_ptr(cs_set, cpu);
		for (i = 0; i < MAX_NESTING; i++) {
			kfree(cs->items[i].entries);
		}
	}
	free_percpu(cs_set);
}

static
struct lttng_cs __percpu *callstack_data_create(unsigned int entries)
{
	int cpu, i;
	struct stack_trace *item;
	struct lttng_cs *cs;
	struct lttng_cs __percpu *cs_set;

	cs_set = alloc_percpu(struct lttng_cs);
	if (!cs_set)
		return NULL;
	for_each_possible_cpu(cpu) {
		cs = per_cpu_ptr(cs_set, cpu);
		for (i = 0; i < MAX_NESTING; i++) {
			item = &cs->items[i];
			item->entries = kzalloc(sizeof(unsigned long) * entries, GFP_KERNEL);
			if (!item->entries) {
				goto error_alloc;
			}
			item->max_entries = entries;
		}
	}
	return cs_set;

error_alloc:
	callstack_data_free(cs_set);
	return NULL;
}

int lttng_add_callstack_kernel_to_ctx(struct lttng_ctx **ctx)
{
	struct lttng_ctx_field *field;
	struct lttng_cs *cs;
	int ret;

	field = lttng_append_context(ctx);
	if (!field)
		return -ENOMEM;
	if (lttng_find_context(*ctx, "kcallstack")) {
		printk("kcallstack lttng_find_context failed\n");
		ret = -EEXIST;
		goto error_find;
	}
	cs = callstack_data_create(MAX_ENTRIES);
	if (!cs) {
		ret = -ENOMEM;
		goto error_create;
	}

	field->event_field.name = "kcallstack";

	field->event_field.type.atype = atype_sequence;
	field->event_field.type.u.sequence.elem_type.atype = atype_integer;
	field->event_field.type.u.sequence.elem_type.u.basic.integer.size = sizeof(unsigned long) * CHAR_BIT;
	field->event_field.type.u.sequence.elem_type.u.basic.integer.alignment = lttng_alignof(long) * CHAR_BIT;
	field->event_field.type.u.sequence.elem_type.u.basic.integer.signedness = lttng_is_signed_type(unsigned long);
	field->event_field.type.u.sequence.elem_type.u.basic.integer.reverse_byte_order = 0;
	field->event_field.type.u.sequence.elem_type.u.basic.integer.base = 16;
	field->event_field.type.u.sequence.elem_type.u.basic.integer.encoding = lttng_encode_none;

	field->event_field.type.u.sequence.length_type.atype = atype_integer;
	field->event_field.type.u.sequence.length_type.u.basic.integer.size = sizeof(unsigned int) * CHAR_BIT;
	field->event_field.type.u.sequence.length_type.u.basic.integer.alignment = lttng_alignof(unsigned int) * CHAR_BIT;
	field->event_field.type.u.sequence.length_type.u.basic.integer.signedness = lttng_is_signed_type(unsigned int);
	field->event_field.type.u.sequence.length_type.u.basic.integer.reverse_byte_order = 0;
	field->event_field.type.u.sequence.length_type.u.basic.integer.base = 10;
	field->event_field.type.u.sequence.length_type.u.basic.integer.encoding = lttng_encode_none;

	field->get_size_arg = callstack_get_size;
	field->record = callstack_record;
	field->data = cs;
	wrapper_vmalloc_sync_all();
	return 0;

error_create:
	callstack_data_free(cs);
error_find:
	lttng_remove_context_field(ctx, field);
	return ret;
}
EXPORT_SYMBOL_GPL(lttng_add_callstack_kernel_to_ctx);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau");
MODULE_DESCRIPTION("Linux Trace Toolkit Callstack Support");

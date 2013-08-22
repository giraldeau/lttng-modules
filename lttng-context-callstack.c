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
#include "wrapper/ringbuffer/backend.h"
#include "wrapper/ringbuffer/frontend.h"
#include "wrapper/vmalloc.h"
#include "lttng-tracer.h"

#define MAX_ENTRIES 25 // BUG: saving more than 30 entries causes trace corruption
#define MAX_NESTING 4 // defined according to frontend_api.h

struct lttng_cs {
	struct stack_trace items[MAX_NESTING];
};

struct field_data {
	int type;
	struct lttng_cs __percpu *cs_percpu;
};

struct lttng_cs_type {
	const char *name;
	const char *save_func_name;
	void (*save_func)(struct stack_trace *trace);
};

enum cs_ctx_types {
		KCALLSTACK = 0,
		UCALLSTACK = 1,
};

static struct lttng_cs_type cs_types[] = {
		{ 	.name = "kcallstack",
			.save_func_name = "save_stack_trace",
			.save_func = NULL, },
		{ 	.name = "ucallstack",
			.save_func_name = "save_stack_trace_user",
			.save_func = NULL, },
};

int init_type(int type)
{
	unsigned long func;

	if (cs_types[type].save_func)
		return 0;
	func = kallsyms_lookup_funcptr(cs_types[type].save_func_name);
	if (!func) {
		printk(KERN_WARNING "LTTng: symbol lookup failed: %s\n",
				cs_types[type].save_func_name);
		return -EINVAL;
	}
	cs_types[type].save_func = (void *) func;
	return 0;
}

static
struct stack_trace *stack_trace_context(struct lttng_ctx_field *field,
		struct lib_ring_buffer_ctx *ctx)
{
	int nesting;
	struct lttng_cs *cs;
	struct field_data *fdata = field->data;

	/*
	 * get_cpu() is not required, preemption is already
	 * disabled while event is written
	 */
	cs = per_cpu_ptr(fdata->cs_percpu, ctx->cpu);
	nesting = per_cpu(lib_ring_buffer_nesting, ctx->cpu) - 1;
	return &cs->items[nesting];
}

static
size_t callstack_get_size(size_t offset, struct lttng_ctx_field *field,
			  struct lib_ring_buffer_ctx *ctx,
			  struct lttng_channel *chan)
{
	size_t size = 0;
	int i;
	struct field_data *fdata = field->data;
	struct stack_trace *trace = stack_trace_context(field, ctx);

	// reset stack trace
	for (i = 0; i < trace->max_entries; i++)
		trace->entries[i] = 0;
	trace->nr_entries = 0;

	cs_types[fdata->type].save_func(trace);

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
	struct stack_trace *trace = stack_trace_context(field, ctx);
	chan->ops->event_write(ctx, &trace->nr_entries, sizeof(unsigned int));
	chan->ops->event_write(ctx, trace->entries,
			sizeof(unsigned long) * trace->nr_entries);
}

static
void field_data_free(struct field_data *fdata)
{
	int cpu, i;
	struct lttng_cs *cs;

	if (!fdata)
		return;
	for_each_possible_cpu(cpu) {
		cs = per_cpu_ptr(fdata->cs_percpu, cpu);
		for (i = 0; i < MAX_NESTING; i++) {
			kfree(cs->items[i].entries);
		}
	}
	free_percpu(fdata->cs_percpu);
	kfree(fdata);
}

static
struct field_data __percpu *field_data_create(unsigned int entries)
{
	int cpu, i;
	struct stack_trace *item;
	struct lttng_cs *cs;
	struct lttng_cs __percpu *cs_set;
	struct field_data* fdata;

	fdata = kzalloc(sizeof(unsigned long) * entries, GFP_KERNEL);
	if (!fdata)
		return NULL;
	cs_set = alloc_percpu(struct lttng_cs);
	if (!cs_set) {
		goto error_alloc;
	}
	fdata->cs_percpu = cs_set;
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
	return fdata;

error_alloc:
	field_data_free(fdata);
	return NULL;
}

int lttng_add_callstack_generic(struct lttng_ctx **ctx, int ctx_type)
{
	const char *ctx_name = cs_types[ctx_type].name;
	struct lttng_ctx_field *field;
	struct field_data *fdata;
	int ret;

	ret = init_type(ctx_type);
	if (ret)
		return ret;

	field = lttng_append_context(ctx);
	if (!field)
		return -ENOMEM;
	if (lttng_find_context(*ctx, ctx_name)) {
		printk("%s lttng_find_context failed\n", ctx_name);
		ret = -EEXIST;
		goto error_find;
	}
	fdata = field_data_create(MAX_ENTRIES);
	if (!fdata) {
		ret = -ENOMEM;
		goto error_create;
	}
	fdata->type = ctx_type;

	field->event_field.name = ctx_name;

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
	field->data = fdata;
	wrapper_vmalloc_sync_all();
	return 0;

error_create:
	field_data_free(fdata);
error_find:
	lttng_remove_context_field(ctx, field);
	return ret;
}

int lttng_add_callstack_user_to_ctx(struct lttng_ctx **ctx)
{
	return lttng_add_callstack_generic(ctx, UCALLSTACK);
}
EXPORT_SYMBOL_GPL(lttng_add_callstack_user_to_ctx);

int lttng_add_callstack_kernel_to_ctx(struct lttng_ctx **ctx)
{
	return lttng_add_callstack_generic(ctx, KCALLSTACK);
}
EXPORT_SYMBOL_GPL(lttng_add_callstack_kernel_to_ctx);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau");
MODULE_DESCRIPTION("Linux Trace Toolkit Callstack Support");

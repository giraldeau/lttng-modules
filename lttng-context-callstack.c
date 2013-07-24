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
#include "lttng-events.h"
#include "wrapper/ringbuffer/frontend_types.h"
#include "wrapper/vmalloc.h"
#include "lttng-tracer.h"

#define MAX_ENTRIES 10

static
size_t callstack_get_size(size_t offset, struct lttng_ctx_field *field,
			  struct lib_ring_buffer_ctx *ctx,
			  struct lttng_channel *chan)
{
	size_t size = 0;

	// FIXME: does the alignment is handled correctly here?
	// FIXME: return only required space for this particular sequence instead of MAX_ENTRIES
	size += lib_ring_buffer_align(offset, lttng_alignof(unsigned char));
	size += sizeof(unsigned char);
	size += sizeof(unsigned long) * MAX_ENTRIES;
	return size;
}

static
void callstack_record(struct lttng_ctx_field *field,
		      struct lib_ring_buffer_ctx *ctx,
		      struct lttng_channel *chan)
{
	unsigned char len = MAX_ENTRIES;
	unsigned long entries[MAX_ENTRIES];
	struct stack_trace trace;

	memset(entries, 0, sizeof(entries));
	trace.skip = 0;
	trace.nr_entries = 0;
	trace.max_entries = MAX_ENTRIES;
	trace.entries = entries;

	save_stack_trace(&trace);

	chan->ops->event_write(ctx, &len, sizeof(unsigned char));
	chan->ops->event_write(ctx, entries, sizeof(unsigned long) * MAX_ENTRIES);
}

int lttng_add_callstack_kernel_to_ctx(struct lttng_ctx **ctx)
{
	struct lttng_ctx_field *field;

	field = lttng_append_context(ctx);
	if (!field)
		return -ENOMEM;
	if (lttng_find_context(*ctx, "kcallstack")) {
		lttng_remove_context_field(ctx, field);
		printk("kcallstack lttng_find_context failed\n");
		return -EEXIST;
	}
	field->event_field.name = "kcallstack";

	field->event_field.type.atype = atype_sequence;
	field->event_field.type.u.sequence.elem_type.atype = atype_integer;
	field->event_field.type.u.sequence.elem_type.u.basic.integer.size = sizeof(unsigned long) * CHAR_BIT;
	field->event_field.type.u.sequence.elem_type.u.basic.integer.alignment = lttng_alignof(char) * CHAR_BIT;
	field->event_field.type.u.sequence.elem_type.u.basic.integer.signedness = lttng_is_signed_type(unsigned long);
	field->event_field.type.u.sequence.elem_type.u.basic.integer.reverse_byte_order = 0;
	field->event_field.type.u.sequence.elem_type.u.basic.integer.base = 16;
	field->event_field.type.u.sequence.elem_type.u.basic.integer.encoding = lttng_encode_none;

	field->event_field.type.u.sequence.length_type.atype = atype_integer;
	field->event_field.type.u.sequence.length_type.u.basic.integer.size = sizeof(unsigned char) * CHAR_BIT;
	field->event_field.type.u.sequence.length_type.u.basic.integer.alignment = lttng_alignof(unsigned char) * CHAR_BIT;
	field->event_field.type.u.sequence.length_type.u.basic.integer.signedness = lttng_is_signed_type(unsigned long);
	field->event_field.type.u.sequence.length_type.u.basic.integer.reverse_byte_order = 0;
	field->event_field.type.u.sequence.length_type.u.basic.integer.base = 10;
	field->event_field.type.u.sequence.length_type.u.basic.integer.encoding = lttng_encode_none;

	field->get_size_arg = callstack_get_size;
	field->record = callstack_record;
	wrapper_vmalloc_sync_all();
	return 0;
}
EXPORT_SYMBOL_GPL(lttng_add_callstack_kernel_to_ctx);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau");
MODULE_DESCRIPTION("Linux Trace Toolkit Callstack Support");

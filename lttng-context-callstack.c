/*
 * lttng-context-callstack.c
 *
 * LTTng callstack event context.
 *
 * Copyright (C) 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2014 Francis Giraldeau <francis.giraldeau@gmail.com>
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
 *
 * The callstack context can be added to any kernel
 * event. It records either the kernel or the userspace callstack, up to a
 * max depth. The context is a CTF sequence, such that it uses only the space
 * required for the number of callstack entries.
 *
 * It allocates callstack buffers per-CPU up to 4 interrupt nesting. This
 * nesting limit is the same as defined in the ring buffer. It therefore uses a
 * fixed amount of memory, proportional to the number of CPUs, one for each
 * mode:
 *
 *   size = cpus * nest * depth * sizeof(unsigned long) * modes
 *
 * Which is about 800 bytes per-CPUs on 64-bit host and a depth of 25 and
 * per-mode. The allocation is done at the initialization to avoid memory
 * allocation overhead while tracing.
 *
 * The kernel callstack is recovered using save_stack_trace(), and the
 * userspace callstack uses save_stack_trace_user(). They rely on frame
 * pointers. These are usually available for the kernel, but the compiler
 * option -fomit-frame-pointer frequently used in popular Linux distributions
 * may cause the userspace callstack to be unreliable, and is a known
 * limitation of this approach. If frame pointers are not available, it
 * produces no error, but the callstack will be empty. We still provide the
 * feature, because it works well for runtime environments having frame
 * pointers. In the future, unwind support and/or last branch record may
 * provide a solution to this problem.
 *
 * The symbol name resolution is left to the trace reader.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/utsname.h>
#include <linux/stacktrace.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include "lttng-events.h"
#include "wrapper/ringbuffer/backend.h"
#include "wrapper/ringbuffer/frontend.h"
#include "wrapper/vmalloc.h"
#include "lttng-tracer.h"

#define MAX_ENTRIES 25 /* BUG: saving more than 30 entries causes trace corruption */

/*
 * Definitions of callstack modes
 */
enum cs_mode {
	CALLSTACK_KERNEL = 0,
	CALLSTACK_USER = 1,
	CALLSTACK_LAST = 2,
};

struct cs_set {
	struct stack_trace st[RING_BUFFER_MAX_NESTING];
	unsigned long *entries_buf;
};

struct cs_def {
	const enum cs_mode mode;
	const char *name;
	const char *save_func_name;
	void (*save_func)(struct stack_trace *trace);
	struct cs_set __percpu *items;
	struct kref ref;
	int active;
};

static struct cs_def cs_table[] = {
	{
	  .mode           = CALLSTACK_KERNEL,
	  .name           = "callstack_kernel",
	  .save_func_name = "save_stack_trace",
	},
	{
	  .mode           = CALLSTACK_USER,
	  .name           = "callstack_user",
	  .save_func_name = "save_stack_trace_user",
	},
	{ },
};

/* mutex to protect cs_table */
DEFINE_MUTEX(cs_table_mutex);

static
struct stack_trace *stack_trace_context(struct cs_def *def, int cpu)
{
	int nesting;
	struct cs_set *set;
	/*
	 * get_cpu() is not required, preemption is already
	 * disabled while event is written.
	 *
	 * max nesting is enforced in lib_ring_buffer_get_cpu().
	 * Check it again as a safety net.
	 */
	set = per_cpu_ptr(def->items, cpu);
	nesting = per_cpu(lib_ring_buffer_nesting, cpu) - 1;
	if (nesting >= RING_BUFFER_MAX_NESTING) {
		return NULL;
	}
	return &set->st[nesting];
}

/*
 * In order to reserve the correct size, the callstack is computed. The
 * resulting callstack is saved to be accessed in the record step.
 */
static
size_t lttng_callstack_get_size(size_t offset, struct lttng_ctx_field *field,
				struct lib_ring_buffer_ctx *ctx,
				struct lttng_channel *chan)
{
	size_t size = 0;
	struct stack_trace *trace;
	struct cs_def *def = &cs_table[field->u.mode];

	/* sequence length is mandatory */
	size += lib_ring_buffer_align(offset, lttng_alignof(unsigned int));
	size += sizeof(unsigned int);

	/* do not write data if no space is available */
	trace = stack_trace_context(def, ctx->cpu);
	if (!trace)
		return size;

	/* reset stack trace, no need to clear memory */
	trace->nr_entries = 0;

	/* do the real work and reserve space */
	def->save_func(trace);
	size += lib_ring_buffer_align(offset, lttng_alignof(unsigned long));
	size += sizeof(unsigned long) * trace->nr_entries;
	return size;
}

static
void lttng_callstack_record(struct lttng_ctx_field *field,
			    struct lib_ring_buffer_ctx *ctx,
			    struct lttng_channel *chan)
{
	int zero = 0;
	struct cs_def *def = &cs_table[field->u.mode];
	struct stack_trace *trace = stack_trace_context(def, ctx->cpu);

	/* write length */
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(unsigned int));
	if (!trace) {
		chan->ops->event_write(ctx, &zero, sizeof(unsigned int));
		return;
	}
	chan->ops->event_write(ctx, &trace->nr_entries, sizeof(unsigned int));

	/* write entries */
	lib_ring_buffer_align_ctx(ctx, lttng_alignof(unsigned long));
	chan->ops->event_write(ctx, trace->entries,
			sizeof(unsigned long) * trace->nr_entries);
}

/*
 * Initialize the callstack global definition. Increment reference count if the
 * callstack is already initialized.
 */
static
int cs_data_init(struct cs_def *def)
{
	int i, cpu;
	struct cs_set *cs;
	struct stack_trace *item;

	mutex_lock(&cs_table_mutex);
	printk("CALLSTACK refcount=%d\n", def->ref.refcount.counter);
	if (kref_get_unless_zero(&def->ref)) {
		/* refcount >= 1 means the structure is already ready */
		mutex_unlock(&cs_table_mutex);
		return 0;
	}

	/* find the save_func */
	if (!def->save_func) {
		def->save_func = (void *) kallsyms_lookup_funcptr(def->save_func_name);
		if (!def->save_func) {
			printk(KERN_WARNING "LTTng: symbol lookup failed: %s\n",
					def->save_func_name);
			mutex_unlock(&cs_table_mutex);
			return -EINVAL;
		}
	}
	printk("CALLSTACK OK save_func %s\n", def->save_func_name);

	/* alloc stack_trace data */
	def->items = alloc_percpu(struct cs_set);
	if (!def->items)
		goto error_alloc_items;
	for_each_possible_cpu(cpu) {
		cs = per_cpu_ptr(def->items, cpu);
		cs->entries_buf = kzalloc(sizeof(unsigned long) * MAX_ENTRIES *
				RING_BUFFER_MAX_NESTING, GFP_KERNEL);
		if (!cs->entries_buf)
			goto error_alloc_entries;
		for (i = 0; i < RING_BUFFER_MAX_NESTING; i++) {
			item = &cs->st[i];
			item->entries = cs->entries_buf + i * MAX_ENTRIES;
			item->max_entries = MAX_ENTRIES;
		}
	}
	printk("CALLSTACK PASS alloc entries\n");

	/* initialization completed */
	kref_init(&def->ref);
	mutex_unlock(&cs_table_mutex);
	return 0;

error_alloc_entries:
	for_each_possible_cpu(cpu) {
		cs = per_cpu_ptr(def->items, cpu);
		kfree(cs->entries_buf);
	}
error_alloc_items:
	free_percpu(def->items);
	def->save_func = NULL;
	mutex_unlock(&cs_table_mutex);
	return -ENOMEM;
}

/*
 * Free memory when refcount reaches zero
 */
static
void cs_data_release(struct kref *kref)
{
	int cpu;
	struct cs_set *cs;
	struct cs_def *def = container_of(kref, struct cs_def, ref);

	for_each_possible_cpu(cpu) {
		cs = per_cpu_ptr(def->items, cpu);
		kfree(cs->entries_buf);
	}
	free_percpu(def->items);
	mutex_unlock(&cs_table_mutex);
	printk("CALLSTACK release\n");
}

static
void lttng_callstack_destroy(struct lttng_ctx_field *field)
{
	struct cs_def *def = &cs_table[field->u.mode];
	kref_put_mutex(&def->ref, cs_data_release, &cs_table_mutex);
}

static
int __lttng_add_callstack_generic(struct lttng_ctx **ctx, int mode)
{
	struct cs_def *def = &cs_table[mode];
	struct lttng_ctx_field *field;
	int ret;

	field = lttng_append_context(ctx);
	if (!field)
		return -ENOMEM;
	if (lttng_find_context(*ctx, def->name)) {
		printk("%s lttng_find_context failed\n", def->name);
		ret = -EEXIST;
		goto error_find;
	}

	ret = cs_data_init(def);
	if (ret < 0)
		goto error_find;

	/* field declaration */
	field->u.mode = mode;
	field->event_field.name = def->name;
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

	field->get_size_arg = lttng_callstack_get_size;
	field->record = lttng_callstack_record;
	field->destroy = lttng_callstack_destroy;
	wrapper_vmalloc_sync_all();
	return 0;

error_find:
	lttng_remove_context_field(ctx, field);
	return ret;
}

/**
 *	lttng_add_callstack_to_ctx - add callstack event context
 *
 *	@ctx: the lttng_ctx pointer to initialize
 *	@type: the context type
 *
 *	Supported callstack type supported:
 *	LTTNG_KERNEL_CONTEXT_CALLSTACK_KERNEL
 *		Records the callstack of the kernel
 *	LTTNG_KERNEL_CONTEXT_CALLSTACK_USER
 *		Records the callstack of the userspace program (from the kernel)
 *
 * Return 0 for success, or error code.
 */
int lttng_add_callstack_to_ctx(struct lttng_ctx **ctx, int type)
{
	switch (type) {
	case LTTNG_KERNEL_CONTEXT_CALLSTACK_KERNEL:
		return __lttng_add_callstack_generic(ctx, CALLSTACK_KERNEL);
	case LTTNG_KERNEL_CONTEXT_CALLSTACK_USER:
		return __lttng_add_callstack_generic(ctx, CALLSTACK_USER);
	default:
		return -EINVAL;
	}
}
EXPORT_SYMBOL_GPL(lttng_add_callstack_to_ctx);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau");
MODULE_DESCRIPTION("Linux Trace Toolkit Callstack Support");

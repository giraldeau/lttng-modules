/*
 * lttng-ftrace.c
 *
 * LTTng function graph
 *
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
 */

#include <linux/module.h>
#include <linux/ftrace.h>
#include <linux/printk.h>
#include <wrapper/kallsyms.h>
#include <wrapper/ftrace.h>
#include <wrapper/tracepoint.h>
#include <wrapper/vmalloc.h>
#include <lttng-tracer.h>
#include <linux/types.h>

static int (*register_ftrace_graph_sym)(trace_func_graph_ret_t retfunc,
			trace_func_graph_ent_t entryfunc);
static void (*unregister_ftrace_graph_sym)(void);
static unsigned long root_func_sym;

static atomic_t entries = ATOMIC_INIT(0);
static atomic_t returns = ATOMIC_INIT(0);

// called by prepare_ftrace_return()
// The corresponding return hook is called only when this function returns 1
int notrace lttng_fgraph_hook_entry(struct ftrace_graph_ent *trace)
{
	/*
	 * If trace->depth is greater than zero, it means we are within
	 * the root function and its children.
	 *
	 * If trace->depth is zero, we check if the current function is a root
	 * function. In this case, we start tracing.
	 */
	barrier();
	if (trace->depth == 0 && trace->func != root_func_sym) {
		return 0;
	}

	atomic_inc(&entries);
	return 1;
}

// called by ftrace_return_to_handler()
void notrace lttng_fgraph_hook_return(struct ftrace_graph_ret *trace)
{
	atomic_inc(&returns);
}

static int __init lttng_fgraph_init(void)
{
	int ret = 0;

	(void) wrapper_lttng_fixup_sig(THIS_MODULE);

	register_ftrace_graph_sym = (void *) kallsyms_lookup_funcptr("register_ftrace_graph");
	unregister_ftrace_graph_sym = (void *) kallsyms_lookup_funcptr("unregister_ftrace_graph");
	root_func_sym = kallsyms_lookup_funcptr("vfs_fstat");
	barrier();
	printk("register=%p unregister=%p root_func=%p\n",
			register_ftrace_graph_sym,
			unregister_ftrace_graph_sym,
			(void *) root_func_sym);
	if (!register_ftrace_graph_sym ||
	    !unregister_ftrace_graph_sym ||
	    !root_func_sym) {
		ret = -1;
		goto out;
	}

	if (register_ftrace_graph_sym) {
		ret = register_ftrace_graph_sym(lttng_fgraph_hook_return, lttng_fgraph_hook_entry);
		printk("register fgraph hooks ret=%d\n", ret);
	}

	printk("lttng-fgraph loaded\n");
out:
	return ret;
}
module_init(lttng_fgraph_init);

static void __exit lttng_fgraph_exit(void)
{
	if (unregister_ftrace_graph_sym) {
		unregister_ftrace_graph_sym();
		printk("unregister fgraph hooks\n");
	}

	printk("lttng-fgraph removed\n");
	printk("entries=%d returns=%d\n", atomic_read(&entries),
			atomic_read(&returns));
}
module_exit(lttng_fgraph_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng function graph");
MODULE_VERSION(__stringify(LTTNG_MODULES_MAJOR_VERSION) "."
	__stringify(LTTNG_MODULES_MINOR_VERSION) "."
	__stringify(LTTNG_MODULES_PATCHLEVEL_VERSION)
	LTTNG_MODULES_EXTRAVERSION);

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
#include <wrapper/kallsyms.h>
#include <wrapper/tracepoint.h>
#include <wrapper/vmalloc.h>
#include <lttng-tracer.h>

// "register_ftrace_graph"
// "unregister_ftrace_graph"

static int (*register_ftrace_graph_sym)(trace_func_graph_ret_t retfunc,
			trace_func_graph_ent_t entryfunc);
static void (*unregister_ftrace_graph_sym)(void);

static int __init lttng_fgraph_init(void)
{
	int ret = 0;

	(void) wrapper_lttng_fixup_sig(THIS_MODULE);

	register_ftrace_graph_sym = (void *) kallsyms_lookup_funcptr("register_ftrace_graph");
	unregister_ftrace_graph_sym = (void *) kallsyms_lookup_funcptr("unregister_ftrace_graph");

	printk("register %p unregister %p\n", register_ftrace_graph_sym, unregister_ftrace_graph_sym );
	printk("lttng-fgraph loaded\n");
	goto out;
out:
	return ret;
}
module_init(lttng_fgraph_init);

static void __exit lttng_fgraph_exit(void)
{
	printk("lttng-fgraph removed\n");
}
module_exit(lttng_fgraph_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng function graph");
MODULE_VERSION(__stringify(LTTNG_MODULES_MAJOR_VERSION) "."
	__stringify(LTTNG_MODULES_MINOR_VERSION) "."
	__stringify(LTTNG_MODULES_PATCHLEVEL_VERSION)
	LTTNG_MODULES_EXTRAVERSION);

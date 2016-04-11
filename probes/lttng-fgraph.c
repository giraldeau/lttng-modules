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
#include <wrapper/tracepoint.h>
#include <wrapper/vmalloc.h>
#include <lttng-tracer.h>

static int (*register_ftrace_graph_sym)(trace_func_graph_ret_t retfunc,
			trace_func_graph_ent_t entryfunc);
static void (*unregister_ftrace_graph_sym)(void);

// called by prepare_ftrace_return()
int lttng_fgraph_hook_entry(struct ftrace_graph_ent *ent)
{
	if (printk_ratelimit()) {
		printk("lttng_fgraph_hook_return\n");
	}

	return 1;
}

// called by ftrace_return_to_handler()
void lttng_fgraph_hook_return(struct ftrace_graph_ret *ret)
{
	if (printk_ratelimit()) {
		printk("lttng_fgraph_hook_return\n");
	}
}

static int __init lttng_fgraph_init(void)
{
	int ret = 0;

	(void) wrapper_lttng_fixup_sig(THIS_MODULE);

	register_ftrace_graph_sym = (void *) kallsyms_lookup_funcptr("register_ftrace_graph");
	unregister_ftrace_graph_sym = (void *) kallsyms_lookup_funcptr("unregister_ftrace_graph");

	printk("register %p unregister %p\n", register_ftrace_graph_sym, unregister_ftrace_graph_sym );
	if (!register_ftrace_graph_sym || !unregister_ftrace_graph_sym) {
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
}
module_exit(lttng_fgraph_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng function graph");
MODULE_VERSION(__stringify(LTTNG_MODULES_MAJOR_VERSION) "."
	__stringify(LTTNG_MODULES_MINOR_VERSION) "."
	__stringify(LTTNG_MODULES_PATCHLEVEL_VERSION)
	LTTNG_MODULES_EXTRAVERSION);

/*
 * probes/lttng-net.c
 *
 * Record network events
 *
 * Copyright (C) 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include "../lttng-abi.h"

/* include our own uevent tracepoint */
#include "../instrumentation/events/lttng-module/net.h"

DEFINE_TRACE(lttng_net);

static int __init lttng_probe_net_init(void)
{

	printk("lttng_probe_net loaded\n");
	return 0;
}

static void __exit lttng_probe_net_exit(void)
{
	printk("lttng_probe_net unloaded\n");
	return;
}

module_init(lttng_probe_net_init);
module_exit(lttng_probe_net_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng network tracer");

/*
 * probes/lttng-uevent.c
 *
 * Expose kernel tracer to user-space through /proc/lttng
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

#include <linux/module.h>
#include "../lttng-abi.h"

/* include our own uevent tracepoint */
#include "../instrumentation/events/lttng-module/uevent.h"
DEFINE_TRACE(lttng_uevent);

ssize_t uevent_write_handler(struct file *file, const char __user *ubuf,
		size_t count, loff_t *fpos)
{
	trace_lttng_uevent(ubuf, count);
	return count;
}

static int __init lttng_probe_uevent_init(void)
{
	lttng_uevent_set_handler(uevent_write_handler);
	return 0;
}

static void __exit lttng_probe_uevent_exit(void)
{
	lttng_uevent_set_handler(NULL);
}

module_init(lttng_probe_uevent_init);
module_exit(lttng_probe_uevent_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Mathieu Desnoyers <mathieu.desnoyers@efficios.com>");
MODULE_DESCRIPTION("LTTng kernel event from user-space");

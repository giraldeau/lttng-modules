/*
 * addons/lttng-syscall-entry.c
 *
 * Record system call entry
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
#include <asm/ptrace.h>
#include <asm/syscall.h>

#include "../wrapper/tracepoint.h"
#include "../lttng-abi.h"
#include "../instrumentation/events/lttng-module/addons.h"

DEFINE_TRACE(sys_entry);

static void syscall_entry_handler(void *__data, struct pt_regs *regs, long id)
{
	trace_sys_entry(id);
}

static int __init lttng_addons_syscall_init(void)
{
	int ret;

	ret = kabi_2635_tracepoint_probe_register("sys_enter",
			syscall_entry_handler, NULL);
	if (ret)
		return -1;
	printk("lttng_addons syscall loaded\n");
	return 0;
}
module_init(lttng_addons_syscall_init);

static void __exit lttng_addons_syscall_exit(void)
{

	kabi_2635_tracepoint_probe_unregister("sys_enter",
			syscall_entry_handler, NULL);
	printk("lttng_addons syscall removed\n");
}
module_exit(lttng_addons_syscall_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng syscall events");

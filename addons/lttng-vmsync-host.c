/*
 * addons/lttng-vmsync-host.c
 *
 * Periodic hypercall for VM trace synchronization - host component
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

#include "../wrapper/tracepoint.h"
#include "../wrapper/kallsyms.h"
#include "../lttng-abi.h"
#include "../instrumentation/events/lttng-module/addons.h"

#include "lttng-vmsync.h"

DEFINE_TRACE(vmsync_host);

static void kvm_hypercall_handler(void *__data, unsigned long nr,
		unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3)
{
	if (nr == VMSYNC_HYPERCALL_NR)
		trace_vmsync_host(a0);
}

static int __init lttng_addons_vmsync_init(void)
{
	int ret;
	ret = kabi_2635_tracepoint_probe_register("kvm_hypercall",
			kvm_hypercall_handler, NULL);
	if (ret) {
		printk(VMSYNC_INFO "tracepoint_probe_register failed\n");
		return -1;
	}
	printk(VMSYNC_INFO "loaded\n");
	return 0;
}
module_init(lttng_addons_vmsync_init);

static void __exit lttng_addons_vmsync_exit(void)
{

	kabi_2635_tracepoint_probe_unregister("kvm_hypercall",
			kvm_hypercall_handler, NULL);
	/*
	 * make sure any currently running probe
	 * has finished before freeing memory
	 */
	synchronize_sched();
	printk(VMSYNC_INFO "removed\n");
}
module_exit(lttng_addons_vmsync_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng syscall events");

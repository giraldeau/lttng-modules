/*
 * addons/lttng-vmsync-guest.c
 *
 * Periodic hypercall for VM trace synchronization - guest component
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
#include <linux/hrtimer.h>
#include <linux/random.h>
#include <linux/time.h>

#include "../wrapper/tracepoint.h"
#include "../lttng-abi.h"
#define LTTNG_INSTRUMENTATION
#include "../instrumentation/events/lttng-module/addons.h"
#include "../wrapper/tracepoint.h"

#include "lttng-vmsync.h"

DEFINE_TRACE(vmsync_hg_guest);
DEFINE_TRACE(vmsync_gh_guest);

#define VMSYNC_HRTIMER_INTERVAL (10LL * NSEC_PER_MSEC)
#define RATE_LIMIT 3

static unsigned int count = 0;
static unsigned int rate_count = 0;
static unsigned long vm_uid = 0;
static int cpu = -1;

static inline void do_hypercall(unsigned int hypercall_nr, int payload, unsigned long uid)
{
	// FIXME: should use kvm_x86_ops
	asm volatile(".byte 0x0F,0x01,0xC1\n"::"a"(hypercall_nr), "b"(payload), "c"(uid));
}

static void softirq_exit_handler(unsigned int vec_nr)
{
	// FIXME find a better way of doing this please!
	if(cpu != smp_processor_id()) {
			return;
	}

	// FIXME use kernel rate limit instead of this homemade version
	rate_count++;
	count++;
	if((rate_count % RATE_LIMIT) == 0) {
		trace_vmsync_gh_guest(count, vm_uid);
		do_hypercall(VMSYNC_HYPERCALL_NR, count, vm_uid);
		count++; // because it was incremented in the host as well
		trace_vmsync_hg_guest(count, vm_uid);
	}
}

static int __init lttng_addons_vmsync_init(void)
{
	int ret;
	count = 0;
	rate_count = 0;

	get_random_bytes(&vm_uid, sizeof(vm_uid));

	(void) wrapper_lttng_fixup_sig(THIS_MODULE);
	ret = lttng_wrapper_tracepoint_probe_register("softirq_exit",
			softirq_exit_handler, NULL);
	if (ret) {
			printk(VMSYNC_INFO "tracepoint_probe_register softirq_exit failed\n");
			return -1;
	}

	cpu = smp_processor_id();

	printk(VMSYNC_INFO "loaded on cpu %d with vm_uid %lu\n", cpu, vm_uid);
	return 0;
}
module_init(lttng_addons_vmsync_init);

static void __exit lttng_addons_vmsync_exit(void)
{
	lttng_wrapper_tracepoint_probe_unregister("softirq_exit",
			softirq_exit_handler, NULL);

	/*
	 * make sure any currently running probe
	 * has finished before freeing memory
	 */
	synchronize_sched();
	printk(VMSYNC_INFO "removed count=%d for vm_uid %lu\n", count, vm_uid);
}
module_exit(lttng_addons_vmsync_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Mohamad Gebai <mohamad.gebai@polymtl.ca>");
MODULE_DESCRIPTION("LTTng vmsync guest events");

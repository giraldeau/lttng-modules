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
#include <linux/time.h>

#include "lttng-packet.h"
#include "../lttng-abi.h"
#include "../instrumentation/events/lttng-module/addons.h"

#include "lttng-vmsync.h"

DEFINE_TRACE(vmsync_guest);

#define VMSYNC_HRTIMER_INTERVAL (10LL * NSEC_PER_MSEC)

static struct hrtimer hr_timer;
static ktime_t ktime;
static int count = 0;

enum hrtimer_restart hrtimer_handler(struct hrtimer *timer)
{
	trace_vmsync_guest(count++);
	// FIXME: should use kvm_x86_ops
	asm volatile(".byte 0x0F,0x01,0xC1\n"::"a"(VMSYNC_HYPERCALL_NR), "b"(count));

	hrtimer_forward_now(&hr_timer, ns_to_ktime(VMSYNC_HRTIMER_INTERVAL));
	return HRTIMER_RESTART;
}

static int __init lttng_addons_vmsync_init(void)
{
	ktime = ktime_set(0, VMSYNC_HRTIMER_INTERVAL);
	hrtimer_init(&hr_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hr_timer.function = &hrtimer_handler;
	hrtimer_start(&hr_timer, ktime, HRTIMER_MODE_REL);

	printk(VMSYNC_INFO "loaded\n");
	return 0;
}
module_init(lttng_addons_vmsync_init);

static void __exit lttng_addons_vmsync_exit(void)
{
	hrtimer_cancel(&hr_timer);
	printk(VMSYNC_INFO "removed count=%d\n", count);
}
module_exit(lttng_addons_vmsync_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Mohamad Gebai <mohamad.gebai@gmail.com>");
MODULE_DESCRIPTION("LTTng VM trace synchronization");

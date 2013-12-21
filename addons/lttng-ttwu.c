/*
 * addons/lttng-deps.c
 *
 * Try to wake up event
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
#include <linux/sched.h>
#include <linux/kprobes.h>

#include "../wrapper/tracepoint.h"
#include "../lttng-abi.h"
#include "../instrumentation/events/lttng-module/addons.h"

DEFINE_TRACE(sched_ttwu);

/* static int
 * try_to_wake_up(struct task_struct *p, unsigned int state, int wake_flags)
 */

static int
ttwu_probe(struct task_struct *p, unsigned int state, int wake_flags)
{
	if (printk_ratelimit())
		printk("ttwu %d\n", p->pid);
	trace_sched_ttwu(p->pid);
	jprobe_return();
	return 0;
}

static struct jprobe ttwu_jprobe = {
		.entry = ttwu_probe,
		.kp = {
			.symbol_name = "try_to_wake_up",
		},
};

static int __init lttng_addons_ttwu_init(void)
{
	int ret;

	ret = register_jprobe(&ttwu_jprobe);
	if (ret < 0) {
		printk("register_jprobe failed, returned %d\n", ret);
		return -1;
	}

	printk("lttng-ttwu loaded\n");
	return 0;
}
module_init(lttng_addons_ttwu_init);

static void __exit lttng_addons_ttwu_exit(void)
{
	unregister_jprobe(&ttwu_jprobe);
	printk("lttng-ttwu removed\n");
}
module_exit(lttng_addons_ttwu_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng ttwu event");


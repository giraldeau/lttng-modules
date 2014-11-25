/*
 * addons/lttng-ttwu.c
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
#include <linux/spinlock.h>

#include "../wrapper/tracepoint.h"
#include "../lttng-abi.h"
#define LTTNG_INSTRUMENTATION
#include "../instrumentation/events/lttng-module/addons.h"

DEFINE_TRACE(sched_ttwu);

#define SCHED_WAKEUP_TP "sched_wakeup"
#define SCHED_WAKEUP_NEW_TP "sched_wakeup_new"

static void ttwu_probe(void *__data, struct task_struct *p, int success)
{
	trace_sched_ttwu(p->pid);
}

/*
 * The sched_wakeup event in Linux > 3.8.0 occurs on the target CPU inside IPI
 * instead of the source context. It screws the task execution flow.
 *
 * We define the event sched_ttwu in two ways. For prior version, a probe is
 * registered to the sched_wakeup tracepoint. For newer version, we use kprobe
 * on try_to_wake_up, that occurs before IPI in the source context.
 */

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,8,0))

/* static int
 * try_to_wake_up(struct task_struct *p, unsigned int state, int wake_flags)
 */

static int
ttwu_jprobe_handler(struct task_struct *p, unsigned int state, int wake_flags)
{
	unsigned long flags;
	/*
	 * Check if state is about to change (avoid recording spurious wakeup)
	 * Use the same memory barrier than original function to compare p->state
	 */
	smp_mb__before_spinlock();
	raw_spin_lock_irqsave(&p->pi_lock, flags);
	if (!(p->state & state))
		goto out;

	trace_sched_ttwu(p->pid);
out:
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);
	jprobe_return();
	return 0;
}

static struct jprobe ttwu_jprobe = {
		.entry = ttwu_jprobe_handler,
		.kp = {
			.symbol_name = "try_to_wake_up",
		},
};

static int __init lttng_addons_ttwu_init(void)
{
	int ret;

	(void) wrapper_lttng_fixup_sig(THIS_MODULE);
	ret = lttng_wrapper_tracepoint_probe_register(SCHED_WAKEUP_NEW_TP, ttwu_probe, NULL);
	if (ret < 0) {
		printk("tracepoint_probe_register failed, returned %d\n", ret);
		goto out;
	}
	ret = register_jprobe(&ttwu_jprobe);
	if (ret < 0) {
		printk("register_jprobe failed, returned %d\n", ret);
		goto err;
	}

	printk("lttng-ttwu loaded (kprobe)\n");
out:
	return ret;
err:
	lttng_wrapper_tracepoint_probe_unregister(SCHED_WAKEUP_NEW_TP, ttwu_probe, NULL);
	goto out;
}
module_init(lttng_addons_ttwu_init);

static void __exit lttng_addons_ttwu_exit(void)
{
	lttng_wrapper_tracepoint_probe_unregister(SCHED_WAKEUP_NEW_TP, ttwu_probe, NULL);
	unregister_jprobe(&ttwu_jprobe);
	printk("lttng-ttwu removed\n");
}
module_exit(lttng_addons_ttwu_exit);

#else

static int __init lttng_addons_ttwu_init(void)
{
	int ret;

	(void) wrapper_lttng_fixup_sig(THIS_MODULE);
	ret = lttng_wrapper_tracepoint_probe_register(SCHED_WAKEUP_TP, ttwu_probe, NULL);
	if (ret) {
		printk("Failed to register probe, returned %d\n", ret);
	}
	ret = lttng_wrapper_tracepoint_probe_register(SCHED_WAKEUP_NEW_TP, ttwu_probe, NULL);
	if (ret) {
		printk("Failed to register probe, returned %d\n", ret);
		goto err;
	}
	printk("lttng-ttwu loaded (tracepoint)\n");
	return 0;
err:
	lttng_wrapper_tracepoint_probe_unregister(SCHED_WAKEUP_NEW_TP, ttwu_probe, NULL);
	return -1;
}
module_init(lttng_addons_ttwu_init);

static void __exit lttng_addons_ttwu_exit(void)
{
	lttng_wrapper_tracepoint_probe_unregister(SCHED_WAKEUP_TP, ttwu_probe, NULL);
	lttng_wrapper_tracepoint_probe_unregister(SCHED_WAKEUP_NEW_TP, ttwu_probe, NULL);
	printk("lttng-ttwu removed\n");
}
module_exit(lttng_addons_ttwu_exit);
#endif

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng sched_ttwu event");


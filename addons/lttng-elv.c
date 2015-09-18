/*
 * addons/lttng-elv.c
 *
 * Missing tracepoint for recovering the block device request chain
 *
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
#include <linux/kprobes.h>
#include <linux/blkdev.h>
#include <linux/spinlock.h>

#include "../wrapper/tracepoint.h"
#include "../lttng-abi.h"
#define LTTNG_INSTRUMENTATION
#include "../instrumentation/events/lttng-module/addons.h"

DEFINE_TRACE(addons_elv_merge_requests);

static int x;
DEFINE_SPINLOCK(lock);

static int
lttng_elv_probe(struct request_queue *q, struct request *rq,
        struct request *next)
{
    int count;

    spin_lock(&lock);
    count = x++;
    spin_unlock(&lock);
    printk("elv_merge_requests\n %d", count);
    trace_addons_elv_merge_requests(q, rq, next);
	jprobe_return();
	return 0;
}

static struct jprobe elv_jprobe = {
		.entry = lttng_elv_probe,
		.kp = {
			.symbol_name = "elv_merge_requests",
		},
};

static int __init lttng_addons_elv_init(void)
{
	int ret;

	(void) wrapper_lttng_fixup_sig(THIS_MODULE);
	ret = register_jprobe(&elv_jprobe);
	if (ret < 0) {
		printk("register_jprobe failed, returned %d\n", ret);
		goto out;
	}

	printk("lttng-elv loaded\n");
out:
	return ret;
}
module_init(lttng_addons_elv_init);

static void __exit lttng_addons_elv_exit(void)
{
	unregister_jprobe(&elv_jprobe);
	printk("lttng-elv removed\n");
}
module_exit(lttng_addons_elv_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng block elevator event");


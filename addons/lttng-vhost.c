/*
 * addons/lttng-vhost.c
 *
 * FIXME: Random experiment
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
#include <net/sock.h>
#include <linux/spinlock.h>

#include "../wrapper/tracepoint.h"
#include "../lttng-abi.h"
#define LTTNG_INSTRUMENTATION
#include "../instrumentation/events/lttng-module/addons.h"

DEFINE_TRACE(addons_icmp_send);

static int
lttng_vhost_probe(struct sk_buff *skb_in, int type, int code, __be32 info)
{
    printk("lttng_vhost_probe\n");
    trace_addons_icmp_send(skb_in, type, code, info);
	jprobe_return();
	return 0;
}

static struct jprobe vhost_jprobe = {
		.entry = lttng_vhost_probe,
		.kp = {
			.symbol_name = "icmp_send",
		},
};

static int __init lttng_addons_vhost_init(void)
{
	int ret;

	(void) wrapper_lttng_fixup_sig(THIS_MODULE);
	ret = register_jprobe(&vhost_jprobe);
	if (ret < 0) {
		printk("register_jprobe failed, returned %d\n", ret);
		goto out;
	}

	printk("lttng-vhost loaded\n");
out:
	return ret;
}
module_init(lttng_addons_vhost_init);

static void __exit lttng_addons_vhost_exit(void)
{
	unregister_jprobe(&vhost_jprobe);
	printk("lttng-vhost removed\n");
}
module_exit(lttng_addons_vhost_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng block elevator event");


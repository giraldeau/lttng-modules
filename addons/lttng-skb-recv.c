/*
 * addons/lttng-skb-recv.c
 *
 * A filtered version of netif_receive_skb
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
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/uaccess.h>

#include "../wrapper/tracepoint.h"
#include "../instrumentation/events/lttng-module/addons.h"

DEFINE_TRACE(netif_receive_skb_filter);

unsigned int filter_dev_probe_handler(void* __data, struct sk_buff *skb)
{
    char dev_name[] = "lo";
	struct net_device *dev;
    void *unsafe_ptr = (void *) (long) &skb->dev;
    void *ptr = NULL;
    
    probe_kernel_read(&ptr, unsafe_ptr, sizeof(ptr));
    dev = (struct net_device*) ptr;
    
    if (dev != NULL && (memcmp(dev->name, dev_name, 2) == 0)){
        printk("name : %s\n", dev->name);
	    trace_netif_receive_skb_filter(skb);
    } else {
        printk("No device found! \n");
        return 0;
    }
    return 0;
}

static int __init lttng_addons_netif_receive_skb_filter_init(void)
{
	int ret;

	(void) wrapper_lttng_fixup_sig(THIS_MODULE);

	ret = lttng_wrapper_tracepoint_probe_register("netif_receive_skb",
			filter_dev_probe_handler, NULL);
	if (ret)
		goto error;

	printk("lttng_addons_netif_receive_skb_filter loaded\n");
	return 0;

error:
	return ret;
}

static void __exit lttng_addons_netif_receive_skb_filter_exit(void)
{
	int ret;

    ret = lttng_wrapper_tracepoint_probe_unregister("netif_receive_skb",
			filter_dev_probe_handler, NULL);
	
    printk("lttng_addons_netif_receive_skb_filter unloaded\n");
	return;
}

module_init(lttng_addons_netif_receive_skb_filter_init);
module_exit(lttng_addons_netif_receive_skb_filter_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Suchakra Sharma <suchakrapani.sharma@polymtl.com>");
MODULE_DESCRIPTION("LTTng filtered skb tracer");

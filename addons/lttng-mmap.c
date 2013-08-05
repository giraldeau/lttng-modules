/*
 * addons/lttng-mmap.c
 *
 * Record vma events
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

#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mm_types.h>
#include <linux/printk.h>

void vma_probe_handler(struct vm_area_struct *vma)
{
	if (printk_ratelimit())
		printk("vma_probe_handler\n");
	jprobe_return();
}

static struct jprobe vma_probe;

static int __init lttng_addons_mmap_init(void)
{
	int ret;

	vma_probe.kp.addr = (void *) kallsyms_lookup_name("perf_event_mmap");
	vma_probe.entry = vma_probe_handler;

	ret = register_jprobe(&vma_probe);
	if (ret < 0) {
		printk(KERN_INFO "Error loading jprobe %d\n", ret);
		goto error;
	}

	printk("lttng_addons_mmap loaded\n");
	return 0;

error:
	unregister_jprobe(&vma_probe);
	return -1;
}
module_init(lttng_addons_mmap_init);

static void __exit lttng_addons_mmap_exit(void)
{
	unregister_jprobe(&vma_probe);
	printk("lttng_addons_mmap removed\n");
}
module_exit(lttng_addons_mmap_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng vma events");


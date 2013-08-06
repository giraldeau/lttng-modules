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
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/kallsyms.h>

#include "../lttng-abi.h"
#include "../instrumentation/events/lttng-module/addons.h"

DEFINE_TRACE(mmap_exec_file);

static struct jprobe vma_probe;

/*
 * Inspired from kernel/events/core.c
 */
void vma_probe_handler(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;
	int size;
	char *buf = NULL;
	const char *name;

	/*
	 * We log only executable VMAs that are file backed
	 */
	if (!file || !(vma->vm_flags & VM_EXEC))
		goto out;

	buf = kzalloc(PATH_MAX + sizeof(u64), GFP_KERNEL);
	if (!buf)
		goto out;
	name = d_path(&file->f_path, buf, PATH_MAX);
	if (!name)
		goto out;
	printk("vma->vm_file %s\n", name);
	trace_mmap_exec_file(name,
						 vma->vm_start,
						 vma->vm_end - vma->vm_start,
						 (u64)vma->vm_pgoff << PAGE_SHIFT);

out:
	if (printk_ratelimit())
		printk("vma_probe_handler\n");
	kfree(buf);
	jprobe_return();
}

static int init_probe(void)
{
	int ret;

	vma_probe.kp.addr = (void *) kallsyms_lookup_name("perf_event_mmap");
	vma_probe.entry = vma_probe_handler;
	ret = register_jprobe(&vma_probe);
	if (ret < 0) {
		printk(KERN_INFO "Error loading jprobe %d\n", ret);
		goto error;
	}
	return 0;
error:
	unregister_jprobe(&vma_probe);
	return -1;
}

static int __init lttng_addons_mmap_init(void)
{
	int ret;

	if (init_probe())
		return -1;
	printk("lttng_addons_mmap loaded\n");
	return 0;
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


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

#include <linux/list.h>

#include "../wrapper/tracepoint.h"
#include "../wrapper/kallsyms.h"
#include "../lttng-abi.h"
#define LTTNG_INSTRUMENTATION
#include "../instrumentation/events/lttng-module/addons.h"

#include "lttng-vmsync.h"

DEFINE_TRACE(vmsync_gh_host);
DEFINE_TRACE(vmsync_hg_host);

static LIST_HEAD(nodes_list);

struct sync_node {
	u8 in_sync;
	u64 counter;
	unsigned long vm_uid;
	pid_t pid;
	struct list_head list;
};


static void free_list(void)
{
	struct sync_node *node;

redo:
	list_for_each_entry(node, &nodes_list, list) {
		list_del(&node->list);
		kfree(node);
		goto redo;
	}
}

static struct sync_node *find(pid_t pid)
{
	struct sync_node *node;

	list_for_each_entry(node, &nodes_list, list) {
		if(node->pid == pid) {
			return node;
		}
	}
	return NULL;
}

static struct sync_node *find_or_add(pid_t pid)
{
	struct sync_node *node = find(pid);

	if (node) {
		return node;
	}

	node = kmalloc(sizeof(struct sync_node), GFP_KERNEL);
	node->pid = pid;
	node->counter = 0;
	node->in_sync = 0;
	INIT_LIST_HEAD(&node->list);

	list_add(&node->list, &nodes_list);
	return node;
}

static void kvm_hypercall_handler(void *__data, unsigned long nr,
		unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3)
{
	struct sync_node *node;

	if (nr == VMSYNC_HYPERCALL_NR) {
		node = find_or_add(current->pid);
		node->counter = a0;
		node->vm_uid = a1;
		trace_vmsync_gh_host(node->counter, node->vm_uid);
		node->in_sync = 1;
	}
}

static void kvm_entry_handler(unsigned int vcpu_id)
{
	struct sync_node *node = find(current->pid);

	if(!node) {
		return;
	}

	if(node->in_sync == 1) {
		node->counter++; // the guest knows about this. It is incrementing it as well
		trace_vmsync_hg_host(node->counter, node->vm_uid);
		node->in_sync = 0;
	}
}

static int __init lttng_addons_vmsync_init(void)
{
	int ret;

	(void) wrapper_lttng_fixup_sig(THIS_MODULE);
	ret = lttng_wrapper_tracepoint_probe_register("kvm_hypercall",
			kvm_hypercall_handler, NULL);
	if (ret) {
		printk(VMSYNC_INFO "tracepoint_probe_register kvm_hypercall failed\n");
		return -1;
	}

	ret = lttng_wrapper_tracepoint_probe_register("kvm_entry",
			kvm_entry_handler, NULL);
	if (ret) {
		printk(VMSYNC_INFO "tracepoint_probe_register kvm_entry failed\n");
		return -1;
	}

	printk(VMSYNC_INFO "loaded\n");
	return 0;
}
module_init(lttng_addons_vmsync_init);

static void __exit lttng_addons_vmsync_exit(void)
{

	lttng_wrapper_tracepoint_probe_unregister("kvm_hypercall",
			kvm_hypercall_handler, NULL);
	lttng_wrapper_tracepoint_probe_unregister("kvm_entry",
			kvm_entry_handler, NULL);
	/*
	 * make sure any currently running probe
	 * has finished before freeing memory
	 */
	synchronize_sched();
	free_list();
	printk(VMSYNC_INFO "removed\n");
}
module_exit(lttng_addons_vmsync_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Mohamad Gebai <mohamad.gebai@polymtl.ca>"
		"Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng vmsync host events");

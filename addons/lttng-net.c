/*
 * addons/lttng-net.c
 *
 * Record network events
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

/*
 * This code uses some of the instrumentation technique from Linux-Sensors
 */

#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/inet_hashtables.h>

#include "lttng-packet.h"
#include "../wrapper/tracepoint.h"
#include "../lttng-abi.h"
#include "../instrumentation/events/lttng-module/addons.h"

DEFINE_TRACE(inet_sock_create);
DEFINE_TRACE(inet_sock_delete);
DEFINE_TRACE(inet_sock_clone);
DEFINE_TRACE(inet_accept);
DEFINE_TRACE(inet_connect);

/* tcp_hashinfo contains both ipv4 and ipv6 socks */
extern struct inet_hashinfo tcp_hashinfo;
extern const struct net_proto_family inet_family_ops;

typedef void (sk_destruct_t)(struct sock *);
static void inet_sock_destruct_hook(struct sock *sk);
static int inet_create_hook(struct net *net, struct socket *sock, int protocol, int kern);
static const struct net_proto_family hooked_inet_family_ops = {
	.family = PF_INET,
	.create = inet_create_hook,
	.owner = THIS_MODULE,
};

static void tcp_sock_override_destruct(sk_destruct_t *oldfn, sk_destruct_t *newfn)
{
	struct sock *sk;
	struct hlist_nulls_node *nnode;
	struct inet_listen_hashbucket *ilb;
	struct inet_ehash_bucket *ehb;
	spinlock_t *ehash_lock;
	int count = 0;
	int i;

	for (i = 0; i < INET_LHTABLE_SIZE; i++) {
		ilb = &tcp_hashinfo.listening_hash[i];
		spin_lock(&ilb->lock);
		sk_nulls_for_each(sk, nnode, &ilb->head) {
			BUG_ON(sk->sk_destruct != oldfn);
			sk->sk_destruct = newfn;
			count++;
		}
		spin_unlock(&ilb->lock);
	}
	for (i = 0; i <= tcp_hashinfo.ehash_mask; i++) {
		ehb = &tcp_hashinfo.ehash[i];
		ehash_lock = inet_ehash_lockp(&tcp_hashinfo, i);
		spin_lock(ehash_lock);
		sk_nulls_for_each(sk, nnode, &ehb->chain) {
			BUG_ON(sk->sk_destruct != oldfn);
			sk->sk_destruct = newfn;
			count++;
		}
		// Nothing to do for time_wait: they are already destroyed?
		/*
		struct inet_timewait_sock *tw;
		inet_twsk_for_each(tw, nnode, &ehb->twchain) {
			count++;
		}
		*/
		spin_unlock(ehash_lock);
	}
	printk("tcp_ipv4_sock_override_destruct count=%d\n", count);
}

static void inet_sock_destruct_hook(struct sock *sk)
{
	trace_inet_sock_delete(sk);
	sk->sk_destruct = inet_sock_destruct;
	inet_sock_destruct(sk);
}

static int inet_create_hook(struct net *net, struct socket *sock, int protocol, int kern)
{
	int err;

	err = inet_family_ops.create(net, sock, protocol, kern);
	if (err < 0)
		return err;
	BUG_ON(sock->sk->sk_destruct != inet_sock_destruct);
	sock->sk->sk_destruct = inet_sock_destruct_hook;
	trace_inet_sock_create(sock->sk);
	return err;
}

static int reinstall_family(const char *name,
		const struct net_proto_family *family_ops)
{
	int err;

	if ((err = sock_register(family_ops))) {
		printk(KERN_ERR "%s: unable to re-register %s family (error %d); "
				"The system will probably require a reboot to fix networking.\n",
				THIS_MODULE->name, name, err);
		return err;
	}
	module_put(family_ops->owner);
	return 0;
}

static int install_hook(const char *name,
		const struct net_proto_family *family_ops,
		const struct net_proto_family *hooked_ops) {
	int err;

	if (family_ops->family != hooked_ops->family)
		return -EINVAL;
	if (!try_module_get(family_ops->owner)) {
		printk(KERN_ERR "%s: failed to get reference to %s family ops\n",
				THIS_MODULE->name, name);
		return -ENOENT;
	}
	sock_unregister(family_ops->family);
	if ((err = sock_register(hooked_ops))) {
		printk(KERN_ERR "%s: %s hook registration failed (error %d)\n",
				THIS_MODULE->name, name, err);
		reinstall_family(name, family_ops);
		return err;
	}
	return 0;
}

struct sock_probe_data {
	struct sock *sk;
};

/*
 * Calling convention to access function arguments
 * http://stackoverflow.com/questions/10563635/getting-function-arguments-using-kprobes
 */

static int sk_clone_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sock_probe_data *data = (struct sock_probe_data *)ri->data;
	// FIXME: non-portable pt_regs usage
	data->sk = (struct sock *)regs->di;
	return 0;
}

static int sk_clone_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sock *nsk = (struct sock *)regs_return_value(regs);
	struct sock_probe_data *data = (struct sock_probe_data *)ri->data;
	trace_inet_sock_clone(data->sk, nsk);
	return 0;
}

static int fault_handler(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	printk(KERN_WARNING "%s: fault %d occured in kprobe for %s\n",
			THIS_MODULE->name, trapnr, p->symbol_name);
	return 0;
}

static struct kretprobe sk_clone_probe = {
	.kp.symbol_name = "sk_clone_lock",
	.kp.fault_handler = fault_handler,
	.entry_handler = sk_clone_entry,
	.handler = sk_clone_ret,
	.data_size = sizeof(struct sock_probe_data),
	.maxactive = 32, // FIXME: should be set at runtime to the number of CPUs
};

static int inet_accept_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sock *nsk = (struct sock *)regs_return_value(regs);
	if (nsk != NULL) {
		struct inet_sock *isk = inet_sk(nsk);
		trace_inet_accept(nsk, isk->inet_saddr, isk->inet_daddr, isk->inet_sport, isk->inet_dport);
	}
	return 0;
}

static struct kretprobe inet_accept_probe = {
	.kp.symbol_name = "inet_csk_accept",
	.kp.fault_handler = fault_handler,
	.handler = inet_accept_ret,
	.maxactive = 32,
};

static int tcp_v4_connect_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct sock_probe_data *data = (struct sock_probe_data *)ri->data;
	// FIXME: non-portable pt_regs usage
	data->sk = (struct sock *)regs->di;
	return 0;
}

static int tcp_v4_connect_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int ret = (int)regs_return_value(regs);
	struct sock_probe_data *data = (struct sock_probe_data *)ri->data;
	printk("tcp_v4_connect ret=%d sk=0x%p\n", ret, data->sk);
	if (data->sk != NULL) {
		struct inet_sock *isk = inet_sk(data->sk);
		trace_inet_connect(data->sk, isk->inet_saddr, isk->inet_daddr, isk->inet_sport, isk->inet_dport);
	}
	return 0;
}

static struct kretprobe inet_connect_probe = {
	.kp.symbol_name = "tcp_v4_connect",
	.kp.fault_handler = fault_handler,
	.entry_handler = tcp_v4_connect_entry,
	.handler = tcp_v4_connect_ret,
	.data_size = sizeof(struct sock_probe_data),
	.maxactive = 32,
};

static int __init lttng_addons_net_init(void)
{
	int ret;

	(void) wrapper_lttng_fixup_sig(THIS_MODULE);
	tcp_sock_override_destruct(inet_sock_destruct, inet_sock_destruct_hook);

	ret = install_hook("IPv4", &inet_family_ops, &hooked_inet_family_ops);
	if (ret < 0) {
		printk(KERN_INFO "Error install_hook IPv4 %d\n", ret);
		goto error;
	}

	ret = register_kretprobe(&sk_clone_probe);
	if (ret < 0) {
		printk(KERN_INFO "Error loading kretprobe %d\n", ret);
		goto error;
	}

	ret = register_kretprobe(&inet_accept_probe);
	if (ret < 0) {
		printk(KERN_INFO "Error loading kretprobe %d\n", ret);
		goto error;
	}

	ret = register_kretprobe(&inet_connect_probe);
	if (ret < 0) {
		printk(KERN_INFO "Error loading kretprobe %d\n", ret);
		goto error;
	}

	ret = nfhook_init();
	if (ret < 0) {
		printk(KERN_INFO "Error loading nfhook %d\n", ret);
		goto error;
	}

	printk("lttng_addons_net loaded\n");
	return 0;

error:
	nfhook_exit();
	sock_unregister(hooked_inet_family_ops.family);
	reinstall_family("IPv4", &inet_family_ops);
	unregister_kretprobe(&sk_clone_probe);
	unregister_kretprobe(&inet_accept_probe);
	unregister_kretprobe(&inet_connect_probe);
	synchronize_net();

	tcp_sock_override_destruct(inet_sock_destruct_hook, inet_sock_destruct);
	synchronize_net();
	return ret;
}

static void __exit lttng_addons_net_exit(void)
{
	/* The module exit is performed in two phases to prevent any dangling
	 * references to module's code:
	 *   1. Prevent any further overload of sk_destruct by removing the
	 *      inet_family, wait one RCU period to allow
	 *   2. Cleanup all existing sockets to remove reference to this
	 *      module's code
	 */

	// Remove instrumentation
	nfhook_exit();
	sock_unregister(hooked_inet_family_ops.family);
	reinstall_family("IPv4", &inet_family_ops);
	unregister_kretprobe(&sk_clone_probe);
	unregister_kretprobe(&inet_accept_probe);
	unregister_kretprobe(&inet_connect_probe);
	synchronize_net();

	// Cleanup any reference to this module
	tcp_sock_override_destruct(inet_sock_destruct_hook, inet_sock_destruct);
	synchronize_net();

	printk("lttng_addons_net unloaded\n");
	return;
}

module_init(lttng_addons_net_init);
module_exit(lttng_addons_net_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("LTTng network tracer");

/*
 * addons/lttng-packet.c
 *
 * Record local packets events with netfilter
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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/inet_hashtables.h>

#include "../instrumentation/events/lttng-module/addons.h"
#include "lttng-packet.h"

DEFINE_TRACE(inet_sock_local_in);
DEFINE_TRACE(inet_sock_local_out);

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define NIP6(addr) \
    ntohs((addr).s6_addr16[0]), \
    ntohs((addr).s6_addr16[1]), \
    ntohs((addr).s6_addr16[2]), \
    ntohs((addr).s6_addr16[3]), \
    ntohs((addr).s6_addr16[4]), \
    ntohs((addr).s6_addr16[5]), \
    ntohs((addr).s6_addr16[6]), \
    ntohs((addr).s6_addr16[7])

extern struct inet_hashinfo tcp_hashinfo;

unsigned int nf_hookfn_inet_local_in(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct tcphdr *tcph;
	struct sock *sk;
	struct iphdr *iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_TCP) {
		/* tcp_hdr macro doesn't return correct offset into skb->data, doing it ourselves */
		//tcph = tcp_hdr(skb);
		tcph = (struct tcphdr *)(skb->data + (iph->ihl << 2 ));
		sk = __inet_lookup_skb(&tcp_hashinfo, skb, tcph->source, tcph->dest);
		trace_inet_sock_local_in(sk, tcph);
	}
	return NF_ACCEPT;
}

unsigned int nf_hookfn_inet_local_out(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct tcphdr *tcph;
	struct iphdr *iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_TCP) {
		tcph = (struct tcphdr *)(skb->data + (iph->ihl << 2 ));
		trace_inet_sock_local_out(skb->sk, tcph);
	}
	return NF_ACCEPT;
}

static struct nf_hook_ops nf_inet_hooks[] = {
	{
		.list = {NULL, NULL},
		.hook = nf_hookfn_inet_local_in,
		.owner = THIS_MODULE,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = INT_MAX,
	},
	{
		.list = {NULL, NULL},
		.hook = nf_hookfn_inet_local_out,
		.owner = THIS_MODULE,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = INT_MAX,
	},
};

int nf_register(void)
{
	int err;

	if ((err = nf_register_hooks(nf_inet_hooks, ARRAY_SIZE(nf_inet_hooks)))) {
		printk(KERN_ERR "%s: netfilter hook registration failed (error %d)\n",
				THIS_MODULE->name, err);
		return -1;
	}
	return 0;
}

int nfhook_init(void)
{
	if (nf_register() < 0) {
		return -1;
	}
	printk("nfhook init\n");
	return 0;
}

void nfhook_exit(void)
{
	nf_unregister_hooks(nf_inet_hooks, ARRAY_SIZE(nf_inet_hooks));
	printk("nfhook exit\n");
	return;
}

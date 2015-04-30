#ifndef _TP_NET_FILT_H
#define _TP_NET_FILT_H

/*
 * net_filt_tp.h
 * 
 */

#include <linux/tracepoint.h>
#include <linux/skbuff.h>

DECLARE_TRACE(netif_receive_skb,
        TP_PROTO(struct sk_buff *skb),
        TP_ARGS(skb));

#endif /* _TP_NET_FILT_H */

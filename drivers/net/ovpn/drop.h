/* SPDX-License-Identifier: GPL-2.0-only */
/* OpenVPN data channel offload
 *
 *  Copyright (C) 2026 OpenVPN, Inc.
 *  Author: Marco Baffo <marco@mandelbit.com>
 *          Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_DROP_H_
#define _NET_OVPN_DROP_H_

#include <linux/skbuff.h>
#include <net/dropreason.h>

#include "stats.h"

enum ovpn_drop_reason {
	__OVPN_DROP_REASON = SKB_DROP_REASON_SUBSYS_OVPN <<
			     SKB_DROP_REASON_SUBSYS_SHIFT,
#define OVPN_DROP_REASON_ENUM(_counter, _name) OVPN_DROP_##_name,
	OVPN_PEER_DROP_ESTATS(OVPN_DROP_REASON_ENUM)
	OVPN_DEV_DROP_ESTATS(OVPN_DROP_REASON_ENUM)
#undef OVPN_DROP_REASON_ENUM
	OVPN_DROP_MAX,
};

static inline void ovpn_kfree_skb_reason(struct sk_buff *skb,
					 enum ovpn_drop_reason reason)
{
	kfree_skb_reason(skb, (u32)reason);
}

static inline void ovpn_kfree_skb_list_reason(struct sk_buff *skb,
					      enum ovpn_drop_reason reason)
{
	kfree_skb_list_reason(skb, (u32)reason);
}

#endif /* _NET_OVPN_DROP_H_ */

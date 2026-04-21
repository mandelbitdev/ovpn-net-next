/* SPDX-License-Identifier: GPL-2.0-only */
/* OpenVPN data channel offload
 *
 * Copyright (C) 2020-2026 OpenVPN, Inc.
 */

#ifndef _NET_OVPN_MCAST_H_
#define _NET_OVPN_MCAST_H_

struct ovpn_priv;
struct ovpn_peer;
struct in6_addr;
struct llist_head;
struct sk_buff;

void ovpn_mcast_cleanup(struct ovpn_priv *ovpn);
void ovpn_mcast_join(struct ovpn_priv *ovpn, struct ovpn_peer *peer,
		     const struct in6_addr *group_addr);
void ovpn_mcast_leave(struct ovpn_priv *ovpn, struct ovpn_peer *peer,
		      const struct in6_addr *group_addr);
void ovpn_mcast_leave_all(struct ovpn_peer *peer);
bool ovpn_peer_list_get_by_mcast_group(struct ovpn_priv *ovpn,
				       const struct in6_addr *group_addr,
				       struct llist_head *list);
bool ovpn_mcast_snoop_skb(struct ovpn_peer *peer, struct sk_buff *skb);

#endif /* _NET_OVPN_MCAST_H_ */

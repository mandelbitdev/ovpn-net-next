// SPDX-License-Identifier: GPL-2.0
/* OpenVPN data channel offload
 *
 * Copyright (C) 2020-2026 OpenVPN, Inc.
 */

#include <linux/igmp.h>
#include <net/mld.h>

#include "ovpnpriv.h"
#include "peer.h"
#include "mcast.h"

struct ovpn_mcast_group {
	struct hlist_node hash_entry;
	struct in6_addr addr;
	struct list_head subs;
};

struct ovpn_mcast_sub {
	struct list_head list;
	struct ovpn_peer *peer;
};

static inline u32 ovpn_mcast_hash(const struct in6_addr *group_addr)
{
	return jhash(group_addr, sizeof(*group_addr), 0);
}

static bool ovpn_mcast_addr_valid(const struct in6_addr *group_addr)
{
	if (ipv6_addr_v4mapped(group_addr))
		return ipv4_is_multicast(group_addr->s6_addr32[3]);
	return ipv6_addr_is_multicast(group_addr);
}

static struct ovpn_mcast_group *
ovpn_mcast_group_find(const struct ovpn_priv *ovpn, const struct in6_addr *group_addr)
{
	struct ovpn_mcast_group *group;
	u32 hash = ovpn_mcast_hash(group_addr);

	hash_for_each_possible(ovpn->mcast_table, group, hash_entry, hash) {
		if (ipv6_addr_equal(&group->addr, group_addr))
			return group;
	}
	return NULL;
}

static struct ovpn_peer *ovpn_mcast_sub_del(struct ovpn_mcast_sub *sub)
{
	struct ovpn_peer *peer = sub->peer;

	list_del(&sub->list);
	kfree(sub);
	return peer;
}

static void ovpn_mcast_group_try_del(struct ovpn_mcast_group *group)
{
	if (!list_empty(&group->subs))
		return;
	hash_del(&group->hash_entry);
	kfree(group);
}

/**
 * ovpn_mcast_cleanup - tear down all multicast state
 * @ovpn: the ovpn instance
 *
 * Walks the multicast hash table and frees every group and subscription.
 * Called at instance destruction time.
 */
void ovpn_mcast_cleanup(struct ovpn_priv *ovpn)
{
	struct ovpn_mcast_group *group;
	struct hlist_node *tmp;
	struct ovpn_mcast_sub *sub, *next;
	unsigned int bkt;

	hash_for_each_safe(ovpn->mcast_table, bkt, tmp, group, hash_entry) {
		list_for_each_entry_safe(sub, next, &group->subs, list)
			ovpn_peer_put(ovpn_mcast_sub_del(sub));
		ovpn_mcast_group_try_del(group);
	}
}

/**
 * ovpn_mcast_join - add a peer to a multicast group
 * @ovpn: the ovpn instance
 * @peer: the peer joining the group
 * @group_addr: the multicast group address (IPv4-mapped IPv6 for IPv4 groups)
 *
 * Creates the group if it does not exist and adds a subscription for @peer.
 * If the peer is already subscribed, returns success without doing anything.
 */
void ovpn_mcast_join(struct ovpn_priv *ovpn, struct ovpn_peer *peer,
		     const struct in6_addr *group_addr)
{
	struct ovpn_mcast_group *group;
	struct ovpn_mcast_sub *sub;

	if (!ovpn_mcast_addr_valid(group_addr))
		return;

	spin_lock_bh(&ovpn->lock);

	group = ovpn_mcast_group_find(ovpn, group_addr);
	if (!group) {
		group = kzalloc_obj(*group, GFP_ATOMIC);
		if (unlikely(!group))
			goto end;
		group->addr = *group_addr;
		INIT_LIST_HEAD(&group->subs);
		hash_add(ovpn->mcast_table, &group->hash_entry,
			 ovpn_mcast_hash(group_addr));
	}

	list_for_each_entry(sub, &group->subs, list) {
		if (sub->peer == peer)
			goto end;
	}

	sub = kzalloc_obj(*sub, GFP_ATOMIC);
	if (unlikely(!sub))
		goto end;

	sub->peer = peer;
	ovpn_peer_hold(peer);
	list_add_tail(&sub->list, &group->subs);
end:
	spin_unlock_bh(&ovpn->lock);
}

/**
 * ovpn_mcast_leave - remove a peer from a multicast group
 * @ovpn: the ovpn instance
 * @peer: the peer leaving the group
 * @group_addr: the multicast group address
 *
 * Removes @peer's subscription for @group_addr. If the group has no remaining
 * subscribers it is destroyed.
 */
void ovpn_mcast_leave(struct ovpn_priv *ovpn, struct ovpn_peer *peer,
		      const struct in6_addr *group_addr)
{
	struct ovpn_mcast_group *group;
	struct ovpn_mcast_sub *sub, *next;
	struct ovpn_peer *peer_to_put = NULL;

	spin_lock_bh(&ovpn->lock);

	group = ovpn_mcast_group_find(ovpn, group_addr);
	if (!group)
		goto end;

	list_for_each_entry_safe(sub, next, &group->subs, list) {
		if (sub->peer != peer)
			continue;
		peer_to_put = ovpn_mcast_sub_del(sub);
		ovpn_mcast_group_try_del(group);
		goto end;
	}
end:
	spin_unlock_bh(&ovpn->lock);

	if (peer_to_put)
		ovpn_peer_put(peer_to_put);
}

/**
 * ovpn_mcast_leave_all - remove a peer from all multicast groups
 * @peer: the peer to remove
 *
 * Called when a peer disconnects. Removes the peer from every group it
 * was subscribed to and destroys any groups that become empty.
 */
void ovpn_mcast_leave_all(struct ovpn_peer *peer)
{
	struct ovpn_priv *ovpn = peer->ovpn;
	struct ovpn_mcast_group *group;
	struct hlist_node *tmp;
	struct ovpn_mcast_sub *sub, *next;
	unsigned int bkt, nput = 0;

	spin_lock_bh(&ovpn->lock);

	hash_for_each_safe(ovpn->mcast_table, bkt, tmp, group, hash_entry) {
		list_for_each_entry_safe(sub, next, &group->subs, list) {
			if (sub->peer != peer)
				continue;
			ovpn_mcast_sub_del(sub);
			nput++;
			ovpn_mcast_group_try_del(group);
			break;
		}
	}

	spin_unlock_bh(&ovpn->lock);

	while (nput--)
		ovpn_peer_put(peer);
}

/**
 * ovpn_peer_list_get_by_mcast_group - retrieve peers subscribed to a multicast group
 * @ovpn: the ovpn instance to search
 * @group_addr: the multicast group address to look up
 * @list: the lockless list to append matching peers to
 *
 * Searches for the multicast group identified by @group_addr and appends all
 * subscribed peers to @list, acquiring a reference on each one.
 *
 * Return: false if no peer was found, true otherwise
 */
bool ovpn_peer_list_get_by_mcast_group(struct ovpn_priv *ovpn,
				       const struct in6_addr *group_addr,
				       struct llist_head *list)
{
	struct ovpn_mcast_group *group;
	struct ovpn_mcast_sub *sub;

	spin_lock_bh(&ovpn->lock);

	group = ovpn_mcast_group_find(ovpn, group_addr);
	if (group) {
		list_for_each_entry(sub, &group->subs, list) {
			if (ovpn_peer_hold(sub->peer))
				llist_add(&sub->peer->mcast_entry, list);
		}
	}

	spin_unlock_bh(&ovpn->lock);
	return !(llist_empty(list));
}

/**
 * ovpn_mcast_mld_offset - compute the offset to the MLD payload in an IPv6 packet
 * @skb: the packet to inspect
 * @offsetp: pointer to store the computed offset
 *
 * MLD packets may be preceded by a Hop-by-Hop options header containing
 * the Router Alert option.  Calculate the actual payload offset and
 * verify that the next header is ICMPv6.
 *
 * Return: true if the offset was computed successfully, false otherwise
 */
static bool ovpn_mcast_mld_offset(struct sk_buff *skb, unsigned int *offsetp)
{
	unsigned int offset = sizeof(struct ipv6hdr);
	u8 nexthdr = ipv6_hdr(skb)->nexthdr;

	if (nexthdr == IPPROTO_HOPOPTS) {
		struct ipv6_opt_hdr *hopopt;

		if (!pskb_may_pull(skb, offset + sizeof(*hopopt)))
			return false;

		hopopt = (struct ipv6_opt_hdr *)(skb_network_header(skb) + offset);
		nexthdr = hopopt->nexthdr;
		offset += ipv6_optlen(hopopt);
	}

	if (nexthdr != IPPROTO_ICMPV6)
		return false;

	*offsetp = offset;
	return true;
}

/**
 * ovpn_mcast_snoop_mld - inspect an IPv6 packet for MLD join/leave messages
 * @peer: the peer this packet was received from
 * @skb: the packet to inspect
 *
 * Parse the MLD header and update the multicast subscription table on
 * MLDv1 reports and done messages.
 *
 * Return: true if the packet was a recognized MLD join/leave and was
 *         consumed, false otherwise
 */
static bool ovpn_mcast_snoop_mld(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct mld_msg *mld;
	unsigned int offset;

	if (!ovpn_mcast_mld_offset(skb, &offset))
		return false;

	if (!pskb_may_pull(skb, offset + sizeof(*mld)))
		return false;

	mld = (struct mld_msg *)(skb_network_header(skb) + offset);

	switch (mld->mld_type) {
	case ICMPV6_MGM_REPORT:
		ovpn_mcast_join(peer->ovpn, peer, &mld->mld_mca);
		return true;
	case ICMPV6_MGM_REDUCTION:
		ovpn_mcast_leave(peer->ovpn, peer, &mld->mld_mca);
		return true;
	case ICMPV6_MGM_QUERY:
		return true;
	}
	return false;
}

/**
 * ovpn_mcast_snoop_igmp - inspect an IPv4 packet for IGMP join/leave messages
 * @peer: the peer this packet was received from
 * @skb: the packet to inspect
 *
 * Parse the IGMP header and update the multicast subscription table on
 * IGMPv2 membership reports and leave messages.
 *
 * Return: true if the packet was a recognized IGMP join/leave and was
 *         consumed, false otherwise
 */
static bool ovpn_mcast_snoop_igmp(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct igmphdr *ih;
	struct in6_addr addr6;
	unsigned int ihl;

	ihl = ip_hdr(skb)->ihl * 4;
	if (!pskb_may_pull(skb, ihl + sizeof(struct igmphdr)))
		return false;

	ih = (struct igmphdr *)(skb_network_header(skb) + ihl);

	switch (ih->type) {
	case IGMPV2_HOST_MEMBERSHIP_REPORT:
		ipv6_addr_set_v4mapped(ih->group, &addr6);
		ovpn_mcast_join(peer->ovpn, peer, &addr6);
		return true;
	case IGMP_HOST_LEAVE_MESSAGE:
		ipv6_addr_set_v4mapped(ih->group, &addr6);
		ovpn_mcast_leave(peer->ovpn, peer, &addr6);
		return true;
	}
	return true;
}

/**
 * ovpn_mcast_snoop_skb - snoop IGMP/MLD control packets from a peer
 * @peer: the peer this packet was received from
 * @skb: the packet to inspect
 *
 * Check whether @skb contains an IGMP or MLD membership report/leave message.
 * If so, update the multicast forwarding table and report that the packet was
 * consumed. Snooping is only performed in multi-peer (server) mode; in P2P
 * mode the function returns false immediately since there is only one peer.
 *
 * Return: true if the packet was a recognized IGMP/MLD join/leave and was
 *         consumed, false otherwise
 */
bool ovpn_mcast_snoop_skb(struct ovpn_peer *peer, struct sk_buff *skb)
{
	if (peer->ovpn->mode != OVPN_MODE_MP)
		return false;
	if (skb->protocol == htons(ETH_P_IP)) {
		if (ip_hdr(skb)->protocol == IPPROTO_IGMP)
			return ovpn_mcast_snoop_igmp(peer, skb);
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		if (ipv6_hdr(skb)->nexthdr == IPPROTO_ICMPV6)
			return ovpn_mcast_snoop_mld(peer, skb);
	}
	return false;
}

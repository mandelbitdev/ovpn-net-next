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

struct ovpn_mcast_source {
	struct list_head list;
	struct in6_addr addr;
};

struct ovpn_mcast_sub {
	struct list_head list;
	struct ovpn_peer *peer;
	enum ovpn_mcast_filter_mode filter_mode;
	struct list_head sources;
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

static void ovpn_mcast_srcs_del_all(struct list_head *srcs)
{
	struct ovpn_mcast_source *src, *next;

	list_for_each_entry_safe(src, next, srcs, list) {
		list_del(&src->list);
		kfree(src);
	}
}

static struct ovpn_peer *ovpn_mcast_sub_del(struct ovpn_mcast_sub *sub)
{
	struct ovpn_peer *peer = sub->peer;

	ovpn_mcast_srcs_del_all(&sub->sources);
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

static void ovpn_mcast_srcs_del(struct ovpn_mcast_sub *sub,
				const struct in6_addr *sources,
				const unsigned int nsrcs)
{
	struct ovpn_mcast_source *src, *next;
	unsigned int i;

	for (i = 0; i < nsrcs; i++) {
		list_for_each_entry_safe(src, next, &sub->sources, list) {
			if (ipv6_addr_equal(&src->addr, &sources[i])) {
				list_del(&src->list);
				kfree(src);
				break;
			}
		}
	}
}

static bool ovpn_mcast_source_exists(const struct ovpn_mcast_sub *sub,
				     const struct in6_addr *addr)
{
	struct ovpn_mcast_source *src;

	list_for_each_entry(src, &sub->sources, list) {
		if (ipv6_addr_equal(&src->addr, addr))
			return true;
	}
	return false;
}

static void ovpn_mcast_srcs_add(struct ovpn_mcast_sub *sub,
				const struct in6_addr *sources,
				const unsigned int nsrcs)
{
	struct ovpn_mcast_source *src;
	unsigned int i;

	for (i = 0; i < nsrcs; i++) {
		if (ovpn_mcast_source_exists(sub, &sources[i]))
			continue;

		src = kzalloc_obj(*src, GFP_ATOMIC);
		if (!src)
			break;
		src->addr = sources[i];
		list_add_tail(&src->list, &sub->sources);
	}
}

static struct ovpn_peer *ovpn_mcast_srcs_update(struct ovpn_mcast_sub *sub,
						const enum ovpn_mcast_filter_mode msg_mode,
						const struct in6_addr *sources,
						const unsigned int nsrcs)
{
	if (!sources || !nsrcs)
		return NULL;

	/* ALLOW_NEW: add in INCLUDE, del in EXCLUDE.
	 * BLOCK_OLD: del in INCLUDE, add in EXCLUDE.
	 */
	if (sub->filter_mode == msg_mode) {
		ovpn_mcast_srcs_add(sub, sources, nsrcs);
	} else {
		ovpn_mcast_srcs_del(sub, sources, nsrcs);
		if (sub->filter_mode == OVPN_MCAST_INCLUDE &&
		    list_empty(&sub->sources))
			return ovpn_mcast_sub_del(sub);
	}
	return NULL;
}

static bool ovpn_mcast_sub_init(struct ovpn_mcast_sub **subp,
				struct ovpn_peer *peer,
				const enum ovpn_mcast_filter_mode mode,
				struct ovpn_mcast_group *group)
{
	struct ovpn_mcast_sub *sub;

	sub = kzalloc_obj(*sub, GFP_ATOMIC);
	if (unlikely(!sub))
		return false;

	if (!ovpn_peer_hold(peer)) {
		kfree(sub);
		return false;
	}

	sub->peer = peer;
	sub->filter_mode = mode;
	INIT_LIST_HEAD(&sub->sources);
	list_add_tail(&sub->list, &group->subs);
	*subp = sub;
	return true;
}

/**
 * ovpn_mcast_sub_update - create, replace, or incrementally update a multicast subscription
 * @ovpn: the ovpn instance
 * @peer: the peer whose subscription is being updated
 * @group_addr: the multicast group address
 * @mode: the filter mode (INCLUDE or EXCLUDE)
 * @sources: array of source addresses to add or remove
 * @nsrcs: number of sources in @sources
 * @incremental_update: if true, merge sources into existing state;
 *			if false, replace state entirely
 *
 * When @incremental_update is false the subscription is fully replaced with
 * the given @mode and @sources. An empty source list with INCLUDE mode is
 * equivalent to leaving the group; with EXCLUDE mode it is an ASM join
 * (receive all sources).
 *
 * When @incremental_update is true the sources are merged: they are added
 * to the list when @mode matches the current filter mode, or removed when
 * it differs. ALLOW_NEW maps to INCLUDE; BLOCK_OLD maps to EXCLUDE. If a
 * BLOCK_OLD operation removes the last source from an INCLUDE subscription,
 * the subscription is destroyed.
 *
 * If no subscription exists for @peer on @group_addr one is created. If the
 * group does not exist it is created.
 *
 * All updates are atomic under @ovpn->lock.
 */
void ovpn_mcast_sub_update(struct ovpn_priv *ovpn, struct ovpn_peer *peer,
			   const struct in6_addr *group_addr,
			   const enum ovpn_mcast_filter_mode mode,
			   const struct in6_addr *sources,
			   const unsigned int nsrcs,
			   const bool incremental_update)
{
	struct ovpn_mcast_group *group;
	struct ovpn_mcast_sub *sub;
	struct ovpn_peer *peer_to_put = NULL;

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
		if (sub->peer != peer)
			continue;
		if (incremental_update) {
			peer_to_put = ovpn_mcast_srcs_update(sub, mode, sources, nsrcs);
			ovpn_mcast_group_try_del(group);
			goto end;
		} else {
			sub->filter_mode = mode;
			ovpn_mcast_srcs_del_all(&sub->sources);
			goto add_sources;
		}
	}

	if (!ovpn_mcast_sub_init(&sub, peer, mode, group)) {
		ovpn_mcast_group_try_del(group);
		goto end;
	}
add_sources:
	if (sources && nsrcs)
		ovpn_mcast_srcs_add(sub, sources, nsrcs);
end:
	spin_unlock_bh(&ovpn->lock);

	if (peer_to_put)
		ovpn_peer_put(peer_to_put);
}

/**
 * ovpn_mcast_join - add a peer to a multicast group
 * @ovpn: the ovpn instance
 * @peer: the peer joining the group
 * @group_addr: the multicast group address (IPv4-mapped IPv6 for IPv4 groups)
 *
 * Creates the group if it does not exist and adds a subscription for @peer.
 * If the peer is already subscribed, returns without doing anything.
 */
void ovpn_mcast_join(struct ovpn_priv *ovpn, struct ovpn_peer *peer,
		     const struct in6_addr *group_addr)
{
	ovpn_mcast_sub_update(ovpn, peer, group_addr, OVPN_MCAST_EXCLUDE,
			      NULL, 0, false);
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

static bool ovpn_mcast_src_allowed(const struct ovpn_mcast_sub *sub,
				   const struct in6_addr *src_addr)
{
	struct ovpn_mcast_source *src;

	list_for_each_entry(src, &sub->sources, list) {
		if (ipv6_addr_equal(&src->addr, src_addr))
			return sub->filter_mode == OVPN_MCAST_INCLUDE;
	}
	return sub->filter_mode == OVPN_MCAST_EXCLUDE;
}

/**
 * ovpn_peer_list_get_by_mcast_group - retrieve peers subscribed to a multicast group
 * @ovpn: the ovpn instance to search
 * @group_addr: the multicast group address to look up
 * @list: the lockless list to append matching peers to
 *
 * @src: the source address to match against per-peer source filters
 *
 * Searches for the multicast group identified by @group_addr and appends
 * subscribed peers whose source filter allows @src to @list, acquiring a
 * reference on each one.
 *
 * Return: false if no peer was found, true otherwise
 */
bool ovpn_peer_list_get_by_mcast_group(struct ovpn_priv *ovpn,
				       const struct in6_addr *group_addr,
				       struct llist_head *list,
				       const struct in6_addr *src)
{
	struct ovpn_mcast_group *group;
	struct ovpn_mcast_sub *sub;

	spin_lock_bh(&ovpn->lock);

	group = ovpn_mcast_group_find(ovpn, group_addr);
	if (group) {
		list_for_each_entry(sub, &group->subs, list) {
			if (ovpn_mcast_src_allowed(sub, src) &&
			    ovpn_peer_hold(sub->peer))
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
 * ovpn_mcast_snoop_mldv2 - inspect an MLDv2 report message
 * @peer: the peer this packet was received from
 * @skb: the packet to inspect
 * @offset: bytes from the start of the network header to the start of the MLD group records
 * @ngrec: number of group records
 *
 * Parse the MLDv2 report and update the multicast subscription table.
 *
 * Return: true if the packet was a recognized MLDv2 join/leave and was
 *         consumed, false otherwise
 */
static bool ovpn_mcast_snoop_mldv2(struct ovpn_peer *peer, struct sk_buff *skb,
				   unsigned int offset, const int ngrec)
{
	struct mld2_grec *grec;
	int i;
	__u16 nsrcs;
	unsigned int rec_len;

	for (i = 0; i < ngrec; i++) {
		if (!pskb_may_pull(skb, offset + sizeof(*grec)))
			return true;

		grec = (struct mld2_grec *)(skb_network_header(skb) + offset);
		nsrcs = ntohs(grec->grec_nsrcs);

		rec_len = sizeof(*grec) + nsrcs * sizeof(struct in6_addr) +
			  grec->grec_auxwords * 4;
		offset += rec_len;

		if (!pskb_may_pull(skb, offset))
			return true;

		/* recompute grec after potential head reallocation */
		grec = (struct mld2_grec *)(skb_network_header(skb) + offset - rec_len);

		switch (grec->grec_type) {
		case MLD2_MODE_IS_INCLUDE:
		case MLD2_CHANGE_TO_INCLUDE:
			if (nsrcs == 0)
				ovpn_mcast_leave(peer->ovpn, peer,
						 &grec->grec_mca);
			else
				ovpn_mcast_sub_update(peer->ovpn, peer,
						      &grec->grec_mca,
						      OVPN_MCAST_INCLUDE,
						      grec->grec_src, nsrcs,
						      false);
			break;
		case MLD2_MODE_IS_EXCLUDE:
		case MLD2_CHANGE_TO_EXCLUDE:
			if (nsrcs == 0)
				ovpn_mcast_join(peer->ovpn, peer,
						&grec->grec_mca);
			else
				ovpn_mcast_sub_update(peer->ovpn, peer,
						      &grec->grec_mca,
						      OVPN_MCAST_EXCLUDE,
						      grec->grec_src, nsrcs,
						      false);
			break;
		case MLD2_ALLOW_NEW_SOURCES:
			if (nsrcs)
				ovpn_mcast_sub_update(peer->ovpn, peer,
						      &grec->grec_mca,
						      OVPN_MCAST_INCLUDE,
						      grec->grec_src, nsrcs,
						      true);
			break;
		case MLD2_BLOCK_OLD_SOURCES:
			if (nsrcs)
				ovpn_mcast_sub_update(peer->ovpn, peer,
						      &grec->grec_mca,
						      OVPN_MCAST_EXCLUDE,
						      grec->grec_src, nsrcs,
						      true);
			break;
		}
	}

	return true;
}

/**
 * ovpn_mcast_snoop_mld - inspect an IPv6 packet for MLD join/leave messages
 * @peer: the peer this packet was received from
 * @skb: the packet to inspect
 *
 * Parse the MLD header and update the multicast subscription table on
 * MLDv1/v2 reports and done messages.
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
	case ICMPV6_MLD2_REPORT:
		return ovpn_mcast_snoop_mldv2(peer, skb,
			offset + sizeof(struct mld2_report),
			ntohs(((struct mld2_report *)mld)->mld2r_ngrec)
		);
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
 * ovpn_mcast_snoop_igmpv3 - inspect an IGMPv3 report message
 * @peer: the peer this packet was received from
 * @skb: the packet to inspect
 * @offset: bytes from the start of the network header to the start of the IGMP group records
 * @ngrec: number of group records
 *
 * Parse the IGMPv3 report and update the multicast subscription table.
 *
 * Return: true if the packet was a recognized IGMPv3 join/leave and was
 *         consumed, false otherwise
 */
static bool ovpn_mcast_snoop_igmpv3(struct ovpn_peer *peer, struct sk_buff *skb,
				    unsigned int offset, const int ngrec)
{
	struct igmpv3_grec *grec;
	struct in6_addr addr6, *srcs = NULL;
	int i;
	unsigned int j, rec_len;
	__u16 nsrcs;

	for (i = 0; i < ngrec; i++) {
		if (!pskb_may_pull(skb, offset + sizeof(*grec)))
			return true;

		grec = (struct igmpv3_grec *)(skb_network_header(skb) + offset);
		nsrcs = ntohs(grec->grec_nsrcs);

		rec_len = sizeof(*grec) + nsrcs * sizeof(__be32) +
			  grec->grec_auxwords * 4;
		offset += rec_len;

		if (!pskb_may_pull(skb, offset))
			return true;

		/* recompute grec after potential head reallocation */
		grec = (struct igmpv3_grec *)(skb_network_header(skb) + offset - rec_len);

		ipv6_addr_set_v4mapped(grec->grec_mca, &addr6);

		if (nsrcs > 0) {
			srcs = kcalloc(nsrcs, sizeof(*srcs), GFP_ATOMIC);
			if (!srcs)
				return false;

			for (j = 0; j < nsrcs; j++)
				ipv6_addr_set_v4mapped(grec->grec_src[j],
						       &srcs[j]);
		}

		switch (grec->grec_type) {
		case IGMPV3_MODE_IS_INCLUDE:
		case IGMPV3_CHANGE_TO_INCLUDE:
			if (nsrcs == 0)
				ovpn_mcast_leave(peer->ovpn, peer, &addr6);
			else
				ovpn_mcast_sub_update(peer->ovpn, peer, &addr6,
						      OVPN_MCAST_INCLUDE, srcs,
						      nsrcs, false);
			break;
		case IGMPV3_MODE_IS_EXCLUDE:
		case IGMPV3_CHANGE_TO_EXCLUDE:
			if (nsrcs == 0)
				ovpn_mcast_join(peer->ovpn, peer, &addr6);
			else
				ovpn_mcast_sub_update(peer->ovpn, peer, &addr6,
						      OVPN_MCAST_EXCLUDE, srcs,
						      nsrcs, false);
			break;
		case IGMPV3_ALLOW_NEW_SOURCES:
			if (nsrcs)
				ovpn_mcast_sub_update(peer->ovpn, peer, &addr6,
						      OVPN_MCAST_INCLUDE, srcs,
						      nsrcs, true);
			break;
		case IGMPV3_BLOCK_OLD_SOURCES:
			if (nsrcs)
				ovpn_mcast_sub_update(peer->ovpn, peer, &addr6,
						      OVPN_MCAST_EXCLUDE, srcs,
						      nsrcs, true);
			break;
		}

		kfree(srcs);
		srcs = NULL;
	}

	return true;
}

/**
 * ovpn_mcast_snoop_igmp - inspect an IPv4 packet for IGMP join/leave messages
 * @peer: the peer this packet was received from
 * @skb: the packet to inspect
 *
 * Parse the IGMP header and update the multicast subscription table on
 * IGMPv2/v3 membership reports and leave messages.
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
	case IGMPV3_HOST_MEMBERSHIP_REPORT:
		return ovpn_mcast_snoop_igmpv3(peer, skb,
			ihl + sizeof(struct igmpv3_report),
			ntohs(((struct igmpv3_report *)ih)->ngrec)
		);
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
		return ovpn_mcast_snoop_mld(peer, skb);
	}

	return false;
}

/**
 * ovpn_mcast_is_control - determine whether an skb is multicast control traffic
 * @skb: the packet to inspect
 *
 * Return: true if the skb contains IGMP or MLD control traffic,
 *         false otherwise
 */
bool ovpn_mcast_is_control(struct sk_buff *skb)
{
	unsigned int offset;
	struct icmp6hdr *ih;

	if (skb->protocol == htons(ETH_P_IP))
		return ip_hdr(skb)->protocol == IPPROTO_IGMP;

	if (skb->protocol != htons(ETH_P_IPV6))
		return false;

	if (!ovpn_mcast_mld_offset(skb, &offset))
		return false;

	if (!pskb_may_pull(skb, offset + sizeof(*ih)))
		return false;

	ih = (struct icmp6hdr *)(skb_network_header(skb) + offset);
	switch (ih->icmp6_type) {
	case ICMPV6_MGM_QUERY:
	case ICMPV6_MGM_REPORT:
	case ICMPV6_MGM_REDUCTION:
	case ICMPV6_MLD2_REPORT:
		return true;
	}

	return false;
}

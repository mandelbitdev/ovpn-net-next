// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2019-2025 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#include <linux/cache.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/if_vlan.h>
#include <linux/prefetch.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/udp.h>
#include <linux/unaligned.h>
#include <net/addrconf.h>
#include <net/dst_cache.h>
#include <net/gro.h>
#include <net/route.h>
#include <net/transp_v6.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>

#include "ovpnpriv.h"
#include "main.h"
#include "bind.h"
#include "io.h"
#include "peer.h"
#include "proto.h"
#include "socket.h"
#include "udp.h"

/* like UDP and TCP frag-list GRO */
#define OVPN_UDP_GRO_CNT_MAX 64

/* leave enough work between a cache hint and the record which consumes it */
#define OVPN_UDP_GRO_PREFETCH_DISTANCE 2

static void ovpn_udp_prefetchw_linear(const struct sk_buff *skb)
{
	unsigned long addr = (unsigned long)skb->data;
	unsigned long end = addr + skb_headlen(skb);

	/* crypto overwrites data in place, so request write ownership of each
	 * linear cache line before the AEAD implementation reaches it
	 */
	for (; addr < end; addr = ALIGN(addr + 1, L1_CACHE_BYTES))
		prefetchw((void *)addr);
}

static bool ovpn_udp_gro_header(struct sk_buff *skb, u32 *header)
{
	const unsigned int offset = skb_gro_offset(skb);

	/* GRO replaces its frag0 pointer after holding an skb, so keep the
	 * openvpn header linear for later candidate comparisons
	 */
	if (!pskb_may_pull(skb, offset + OVPN_OPCODE_SIZE))
		return false;

	*header = get_unaligned_be32(skb->data + offset);
	return true;
}

static struct sk_buff *ovpn_udp_gro_receive_fraglist(struct sock *sk,
						     struct list_head *head,
						     struct sk_buff *skb)
{
	const unsigned int gso_size = skb_gro_len(skb);
	struct sk_buff *p, *pp = NULL;
	int ret = 0, nhoff;
	bool ip_flush;
	u32 header;

	/* FOU and GUE clear encap_mark and set is_fou before passing the inner
	 * UDP packet to GRO, so frag-list completion would run on their outer
	 * UDP header and skip their own completion
	 */
	if (unlikely(NAPI_GRO_CB(skb)->flush || NAPI_GRO_CB(skb)->is_fou ||
		     skb->encapsulation || skb_is_gso(skb)))
		goto flush;

	if (!ovpn_udp_gro_header(skb, &header) ||
	    FIELD_GET(OVPN_OPCODE_PKTTYPE_MASK, header) != OVPN_DATA_V2)
		goto flush;

	/* udp_gro_receive sets encap_mark before invoking a tunnel callback,
	 * normally because the callback recurses into an inner protocol. ovpn
	 * retains complete outer UDP records instead, so clear it and use
	 * ordinary UDP frag-list completion.
	 */
	NAPI_GRO_CB(skb)->encap_mark = 0;
	NAPI_GRO_CB(skb)->is_flist = 1;

	list_for_each_entry(p, head, list) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		/* A different representation, opcode, key or peer ID completes
		 * the held aggregate; this record can start the next one.
		 * Read the held header without pulling which might change the
		 * skb shape.
		 */
		if (NAPI_GRO_CB(p)->encap_mark || !NAPI_GRO_CB(p)->is_flist ||
		    skb_headlen(p) < skb_gro_offset(p) + OVPN_OPCODE_SIZE ||
		    get_unaligned_be32(p->data + skb_gro_offset(p)) != header)
			return p;

		/* GRO has already matched the outer addresses and UDP ports;
		 * check the remaining outer IP fields
		 */
		ip_flush = gro_receive_network_flush(udp_hdr(skb),
						     udp_hdr(p), p);

		/* The first record determines the nominal GSO size. A shorter
		 * final record may follow it, but a larger record cannot.
		 * Checksum metadata must also be uniform because the aggregate
		 * exposes only one checksum state.
		 */
		if (gso_size > skb_shinfo(p)->gso_size || ip_flush ||
		    skb->ip_summed != p->ip_summed ||
		    skb->csum_level != p->csum_level) {
			pp = p;
		} else {
			/* skb_gro_receive_list pulls the headers already
			 * processed by GRO before linking this skb to the
			 * record list so we have to manually preserve the
			 * outer network header location for later handling
			 */
			nhoff = NAPI_GRO_CB(skb)->network_offset;
			skb_set_network_header(skb, nhoff);
			ret = skb_gro_receive_list(p, skb);
		}

		/* complete the aggregate if the append failed, or after
		 * appending a shorter final record, or after reaching the
		 * record-count limit
		 */
		if (ret || gso_size != skb_shinfo(p)->gso_size ||
		    NAPI_GRO_CB(p)->count >= OVPN_UDP_GRO_CNT_MAX)
			pp = p;

		return pp;
	}

	return NULL;

flush:
	/* A packet which cannot join an aggregate must not overtake records of
	 * the same flow which GRO is still holding. Complete those first, as
	 * the other GRO handlers do.
	 */
	NAPI_GRO_CB(skb)->flush = 1;
	list_for_each_entry(p, head, list)
		if (NAPI_GRO_CB(p)->same_flow)
			return p;
	return NULL;
}

static bool ovpn_udp_outer_match(const struct sk_buff *head,
				 const struct sk_buff *frag)
{
	const struct udphdr *uhf = udp_hdr(frag);
	const struct udphdr *uhh = udp_hdr(head);

	/* NAT might have rewritten endpoints after GRO */
	if (unlikely(uhh->source != uhf->source || uhh->dest != uhf->dest))
		return false;

	switch (head->protocol) {
	case htons(ETH_P_IP):
		return ip_hdr(head)->saddr == ip_hdr(frag)->saddr &&
		       ip_hdr(head)->daddr == ip_hdr(frag)->daddr;
	case htons(ETH_P_IPV6):
		return ipv6_addr_equal(&ipv6_hdr(head)->saddr,
				       &ipv6_hdr(frag)->saddr) &&
		       ipv6_addr_equal(&ipv6_hdr(head)->daddr,
				       &ipv6_hdr(frag)->daddr);
	default:
		return false;
	}
}

/* validate an skb and turn it into a list of uniform OpenVPN records or return
 * NULL without modifying an aggregate which UDP must segment
 */
static struct sk_buff *ovpn_udp_gso_prepare(struct sk_buff *skb, u32 header)
{
	unsigned int len = 0, truesize = 0;
	struct sk_buff *list, *record;

	if (!skb_is_gso(skb)) {
		skb_mark_not_on_list(skb);
		goto out;
	}

	list = skb_shinfo(skb)->frag_list;
	if (unlikely(!list))
		return NULL;

	/* if any of the skbs is not private, ask the stack to segment */
	if (unlikely(skb_shared(skb) || skb_cloned(skb)))
		return NULL;

	/* transformations after GRO only update the aggregate head: if its
	 * outer tuple changed, ask UDP to propagate it while segmenting
	 */
	if (unlikely(skb_pagelen(skb) != sizeof(struct udphdr) +
					 skb_shinfo(skb)->gso_size ||
		     !ovpn_udp_outer_match(skb, list)))
		return NULL;

	skb_walk_frags(skb, record) {
		/* if the OpenVPN header is not uniform (batch created by
		 * generic GRO by coalescing unrelated packets) ask the stack
		 * to segment and handle each segment independently
		 */
		if (unlikely(skb_shared(record) || skb_cloned(record) ||
			     skb_headlen(record) < OVPN_OPCODE_SIZE ||
			     get_unaligned_be32(record->data) != header))
			return NULL;

		len += record->len;
		truesize += record->truesize;
	}

	if (unlikely(skb->data_len < len || skb->len < len ||
		     skb->truesize < truesize))
		return NULL;

	/* detach the exclusively owned fraglist */
	skb_shinfo(skb)->frag_list = NULL;
	skb->data_len -= len;
	skb->truesize -= truesize;
	skb->len -= len;
	skb->next = list;
	skb_gso_reset(skb);

out:
	/* skb_gro_receive_list has already pulled the UDP headers from child
	 * records, while the aggregate head still starts at UDP, so pull its
	 * header too before returning the list
	 */
	__skb_pull(skb, sizeof(struct udphdr));
	return skb;
}

static void ovpn_udp_recv(struct ovpn_peer *peer, struct sk_buff *list)
{
	struct sk_buff *skb, *next, *prefetch;
	const __be16 proto = list->protocol;
	const u32 priority = list->priority;
#ifdef CONFIG_NET_SCHED
	const u16 tc_index = list->tc_index;
#endif
#ifdef CONFIG_NETWORK_SECMARK
	const u32 secmark = list->secmark;
#endif
	const int skb_iif = list->skb_iif;
	int i;

	/* a fraglist GRO aggregate makes later ciphertext visible before the
	 * current record is decrypted, so we prime the first two records, then
	 * keep the cache hints the same distance ahead while draining the list
	 */
	prefetch = list->next ? list : NULL;
	for (i = 0; i < OVPN_UDP_GRO_PREFETCH_DISTANCE && prefetch; i++) {
		ovpn_udp_prefetchw_linear(prefetch);
		prefetch = prefetch->next;
	}

	skb_list_walk_safe(list, skb, next) {
		if (prefetch) {
			ovpn_udp_prefetchw_linear(prefetch);
			prefetch = prefetch->next;
		}
		/* propagate post-GRO metadata from the list head, and clear
		 * the state which the receive stack consumed on the head only
		 */
		skb->protocol = proto;
		skb->skb_iif = skb_iif;
		skb->priority = priority;
#ifdef CONFIG_NETWORK_SECMARK
		skb->secmark = secmark;
#endif
#ifdef CONFIG_NET_SCHED
		skb->tc_index = tc_index;
#endif
		__vlan_hwaccel_clear_tag(skb);
		skb_reset_redirect(skb);
#ifdef CONFIG_NET_XGRESS
		skb->tc_skip_classify = 0;
#endif
		skb_clear_delivery_time(skb);
		skb_mark_not_on_list(skb);

		/* keep the current reference alive for the next record before
		 * handing this one to crypto
		 */
		if (next && unlikely(!ovpn_peer_hold(peer))) {
			DEBUG_NET_WARN_ON_ONCE(1);
			kfree_skb_list(next);
			next = NULL;
		}
		ovpn_recv(peer, skb);
	}
}

/* Retrieve the corresponding ovpn object from a UDP socket
 * rcu_read_lock must be held on entry
 */
static struct ovpn_socket *ovpn_socket_from_udp_sock(struct sock *sk)
{
	struct ovpn_socket *ovpn_sock;

	if (unlikely(READ_ONCE(udp_sk(sk)->encap_type) != UDP_ENCAP_OVPNINUDP))
		return NULL;

	ovpn_sock = rcu_dereference_sk_user_data(sk);
	if (unlikely(!ovpn_sock))
		return NULL;

	/* make sure that sk matches our stored transport socket */
	if (unlikely(!ovpn_sock->sk || sk != ovpn_sock->sk))
		return NULL;

	return ovpn_sock;
}

/**
 * ovpn_udp_encap_recv - Start processing a received UDP packet.
 * @sk: socket over which the packet was received
 * @skb: the received packet
 *
 * If the first byte of the payload is:
 * - DATA_V2 the packet is accepted for further processing,
 * - DATA_V1 the packet is dropped as not supported,
 * - anything else the packet is forwarded to the UDP stack for
 *   delivery to user space.
 *
 * Return:
 *  0 if skb was consumed or dropped
 * >0 if skb should be passed up to userspace as UDP (packet not consumed)
 * <0 if skb should be resubmitted as proto -N (packet not consumed)
 */
static int ovpn_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct ovpn_socket *ovpn_sock;
	struct ovpn_priv *ovpn;
	struct ovpn_peer *peer;
	bool aggregate = false;
	struct sk_buff *list;
	u32 header, peer_id;
	u8 opcode;

	ovpn_sock = ovpn_socket_from_udp_sock(sk);
	if (unlikely(!ovpn_sock)) {
		net_err_ratelimited("ovpn: %s invoked on non ovpn socket\n",
				    __func__);
		goto drop_noovpn;
	}

	ovpn = ovpn_sock->ovpn;
	if (unlikely(!ovpn)) {
		net_err_ratelimited("ovpn: cannot obtain ovpn object from UDP socket\n");
		goto drop_noovpn;
	}

	/* Make sure the first 4 bytes of the skb data buffer after the UDP
	 * header are accessible.
	 * They are required to fetch the OP code, the key ID and the peer ID.
	 */
	if (skb_is_gso(skb)) {
		/* Only an accepted frag-list aggregate can carry OpenVPN
		 * records. It is checked without pulling, since one which we
		 * decline must reach UDP unmodified so that it can segment it.
		 */
		if (unlikely(skb_shinfo(skb)->gso_type !=
			     (SKB_GSO_UDP_L4 | SKB_GSO_FRAGLIST)))
			goto drop;
		aggregate = true;

		if (unlikely(skb_headlen(skb) <
			     sizeof(struct udphdr) + OVPN_OPCODE_SIZE))
			goto drop;
	} else if (unlikely(!pskb_may_pull(skb, sizeof(struct udphdr) +
					   OVPN_OPCODE_SIZE))) {
		net_dbg_ratelimited("%s: packet too small from UDP socket\n",
				    netdev_name(ovpn->dev));
		goto drop;
	}

	header = get_unaligned_be32(skb->data + sizeof(struct udphdr));
	opcode = FIELD_GET(OVPN_OPCODE_PKTTYPE_MASK, header);
	if (unlikely(opcode != OVPN_DATA_V2)) {
		/* DATA_V1 is not supported */
		if (opcode == OVPN_DATA_V1)
			goto drop;

		/* unknown or control packet: let it bubble up to userspace */
		return 1;
	}

	peer_id = FIELD_GET(OVPN_OPCODE_PEERID_MASK, header);
	/* some OpenVPN server implementations send data packets with the
	 * peer-id set to UNDEF. In this case we skip the peer lookup by peer-id
	 * and we try with the transport address
	 */
	if (peer_id == OVPN_PEER_ID_UNDEF)
		peer = ovpn_peer_get_by_transp_addr(ovpn, skb);
	else
		peer = ovpn_peer_get_by_id(ovpn, peer_id);

	if (unlikely(!peer))
		goto drop;

	/* A generic aggregate may contain records for different consumers and
	 * post-GRO transformations may have changed only its head. Prepare
	 * only a private, unmodified aggregate with uniform opcode, key ID and
	 * peer ID; otherwise return it to UDP for segmentation.
	 */
	list = ovpn_udp_gso_prepare(skb, header);
	if (unlikely(!list)) {
		ovpn_peer_put(peer);
		return 1;
	}

	ovpn_udp_recv(peer, list);
	return 0;

drop:
	/* let UDP segment an accepted aggregate so that every datagram gets
	 * its own verdict
	 */
	if (aggregate)
		return 1;

	ovpn_dev_dstats_rx_dropped(ovpn->dev);
drop_noovpn:
	kfree_skb(skb);
	return 0;
}

static bool ovpn_route_key_equal(const struct ovpn_route_key *a,
				 const struct ovpn_route_key *b)
{
	return a->mark == b->mark && a->sport == b->sport;
}

/**
 * ovpn_dst_cache_check_key - reset peer dst cache after key changes
 * @peer: the peer owning the dst cache
 * @cache: the cache that might need to be reset
 * @key: the route key for the packet being transmitted
 *
 * Reset the peer dst cache if it was populated for a different route key.
 */
static void ovpn_dst_cache_check_key(struct ovpn_peer *peer,
				     struct dst_cache *cache,
				     const struct ovpn_route_key *key)
{
	struct ovpn_route_key old_key;
	unsigned int seq;

	/* snapshot the saved key before deciding whether the cache matches */
	do {
		seq = read_seqcount_begin(&peer->route_key_seq);
		old_key = peer->route_key;
	} while (read_seqcount_retry(&peer->route_key_seq, seq));

	/* nothing changed: the current cache can be reused */
	if (likely(ovpn_route_key_equal(&old_key, key)))
		return;

	/* recheck under lock because another path may have updated the key */
	spin_lock_bh(&peer->lock);
	if (!ovpn_route_key_equal(&peer->route_key, key)) {
		write_seqcount_begin(&peer->route_key_seq);
		peer->route_key = *key;
		dst_cache_reset(cache);
		write_seqcount_end(&peer->route_key_seq);
	}
	spin_unlock_bh(&peer->lock);
}

/**
 * ovpn_dst_cache_current - check whether a route lookup matches peer state
 * @peer: the peer owning the bind and dst cache
 * @bind: the RCU bind used for the route lookup
 * @key: the route key used for the route lookup
 *
 * Check that @bind is still the current peer bind and that @key still matches
 * the peer route key. The caller must hold @peer->lock. The TX path keeps
 * @bind inside an RCU read-side critical section, so pointer identity is enough
 * to detect whether the bind was replaced while the route lookup was running.
 *
 * Return: true if the lookup result still matches the current peer state and
 * may update the dst cache or replace the bind.
 */
static bool ovpn_dst_cache_current(const struct ovpn_peer *peer,
				   const struct ovpn_bind *bind,
				   const struct ovpn_route_key *key)
{
	const struct ovpn_bind *curr_bind;

	lockdep_assert_held(&peer->lock);

	curr_bind = rcu_dereference_protected(peer->bind,
					      lockdep_is_held(&peer->lock));

	return curr_bind == bind &&
	       ovpn_route_key_equal(key, &peer->route_key);
}

/**
 * ovpn_udp4_output - send IPv4 packet over udp socket
 * @peer: the destination peer
 * @bind: the binding related to the destination peer
 * @cache: dst cache
 * @sk: the socket to send the packet over
 * @skb: the packet to send
 * @key: the route key snapshot used for cache validation and flow lookup
 *
 * Return: 0 on success or a negative error code otherwise
 */
static int ovpn_udp4_output(struct ovpn_peer *peer, struct ovpn_bind *bind,
			    struct dst_cache *cache, struct sock *sk,
			    struct sk_buff *skb,
			    const struct ovpn_route_key *key)
{
	struct sockaddr_storage remote;
	struct in_addr local = {};
	bool reset_local = false;
	struct rtable *rt;
	struct flowi4 fl = {
		.saddr = bind->local.ipv4.s_addr,
		.daddr = bind->remote.in4.sin_addr.s_addr,
		.fl4_sport = key->sport,
		.fl4_dport = bind->remote.in4.sin_port,
		.flowi4_proto = sk->sk_protocol,
		.flowi4_mark = key->mark,
	};
	int ret;

	local_bh_disable();
	rt = dst_cache_get_ip4(cache, &fl.saddr);
	if (rt)
		goto transmit;

	if (fl.saddr && unlikely(!inet_confirm_addr(sock_net(sk), NULL, 0,
						    fl.saddr, RT_SCOPE_HOST))) {
		/* The learned local address is not usable anymore.
		 * Retry with source address autoselection.
		 */
		fl.saddr = 0;
		reset_local = true;
	}

	rt = ip_route_output_flow(sock_net(sk), &fl, sk);
	if (IS_ERR(rt) && PTR_ERR(rt) == -EINVAL) {
		fl.saddr = 0;
		reset_local = true;

		rt = ip_route_output_flow(sock_net(sk), &fl, sk);
	}

	if (IS_ERR(rt)) {
		ret = PTR_ERR(rt);
		net_dbg_ratelimited("%s: no route to host %pISpc: %d\n",
				    netdev_name(peer->ovpn->dev),
				    &bind->remote.in4,
				    ret);
		goto err;
	}

	/* avoid storing a stale cache or local address */
	spin_lock_bh(&peer->lock);
	if (likely(ovpn_dst_cache_current(peer, bind, key))) {
		if (!reset_local) {
			dst_cache_set_ip4(cache, &rt->dst, fl.saddr);
			spin_unlock_bh(&peer->lock);
			goto transmit;
		}

		/* invalidate per-CPU dst entries that may still carry
		 * the stale source
		 */
		dst_cache_reset(cache);

		/* preserve the current remote */
		memcpy(&remote, &bind->remote, sizeof(struct sockaddr_in));
		/* The current packet already has a valid wildcard-source route.
		 * If replacing the bind fails, leave the stale local in place;
		 * a later cache miss will retry the repair.
		 */
		ovpn_peer_reset_sockaddr(peer, &remote, &local);
	}
	spin_unlock_bh(&peer->lock);

transmit:
	/* an already-built UDP GSO needs a checksum seed even if the socket's
	 * no-check option changed while encryption was in flight
	 */
	udp_tunnel_xmit_skb(rt, sk, skb, fl.saddr, fl.daddr, 0,
			    ip4_dst_hoplimit(&rt->dst), 0, fl.fl4_sport,
			    fl.fl4_dport, false,
			    !skb_is_gso(skb) && sk->sk_no_check_tx, 0);
	ret = 0;
err:
	local_bh_enable();
	return ret;
}

#if IS_ENABLED(CONFIG_IPV6)
/**
 * ovpn_udp6_output - send IPv6 packet over udp socket
 * @peer: the destination peer
 * @bind: the binding related to the destination peer
 * @cache: dst cache
 * @sk: the socket to send the packet over
 * @skb: the packet to send
 * @key: the route key snapshot used for cache validation and flow lookup
 *
 * Return: 0 on success or a negative error code otherwise
 */
static int ovpn_udp6_output(struct ovpn_peer *peer, struct ovpn_bind *bind,
			    struct dst_cache *cache, struct sock *sk,
			    struct sk_buff *skb,
			    const struct ovpn_route_key *key)
{
	struct in6_addr local = in6addr_any;
	struct sockaddr_storage remote;
	bool reset_local = false;
	struct dst_entry *dst;
	int ret;

	struct flowi6 fl = {
		.saddr = bind->local.ipv6,
		.daddr = bind->remote.in6.sin6_addr,
		.fl6_sport = key->sport,
		.fl6_dport = bind->remote.in6.sin6_port,
		.flowi6_proto = sk->sk_protocol,
		.flowi6_mark = key->mark,
		.flowi6_oif = bind->remote.in6.sin6_scope_id,
	};

	local_bh_disable();
	dst = dst_cache_get_ip6(cache, &fl.saddr);
	if (dst)
		goto transmit;

	if (!ipv6_addr_any(&fl.saddr) &&
	    unlikely(!ipv6_chk_addr(sock_net(sk), &fl.saddr, NULL, 0))) {
		/* The learned local address is not usable anymore.
		 * Retry with source address autoselection.
		 */
		fl.saddr = in6addr_any;
		reset_local = true;
	}

	dst = ip6_dst_lookup_flow(sock_net(sk), sk, &fl, NULL);
	if (IS_ERR(dst)) {
		ret = PTR_ERR(dst);
		net_dbg_ratelimited("%s: no route to host %pISpc: %d\n",
				    netdev_name(peer->ovpn->dev),
				    &bind->remote.in6, ret);
		goto err;
	}

	/* avoid storing a stale cache or local address */
	spin_lock_bh(&peer->lock);
	if (likely(ovpn_dst_cache_current(peer, bind, key))) {
		if (!reset_local) {
			dst_cache_set_ip6(cache, dst, &fl.saddr);
			spin_unlock_bh(&peer->lock);
			goto transmit;
		}

		/* invalidate per-CPU dst entries that may still carry
		 * the stale source
		 */
		dst_cache_reset(cache);

		/* preserve the current remote */
		memcpy(&remote, &bind->remote, sizeof(struct sockaddr_in6));
		/* The current packet already has a valid wildcard-source route.
		 * If replacing the bind fails, leave the stale local in place;
		 * a later cache miss will retry the repair.
		 */
		ovpn_peer_reset_sockaddr(peer, &remote, &local);
	}
	spin_unlock_bh(&peer->lock);

transmit:
	/* user IPv6 packets may be larger than the transport interface
	 * MTU (after encapsulation), however, since they are locally
	 * generated we should ensure they get fragmented.
	 * Setting the ignore_df flag to 1 will instruct ip6_fragment() to
	 * fragment packets if needed.
	 *
	 * NOTE: this is not needed for IPv4 because we pass df=0 to
	 * udp_tunnel_xmit_skb()
	 */
	skb->ignore_df = 1;
	/* keep checksum offload enabled for an in-flight UDP GSO batch even if
	 * the socket's no-check option has changed since batch creation
	 */
	udp_tunnel6_xmit_skb(dst, sk, skb, skb->dev, &fl.saddr, &fl.daddr, 0,
			     ip6_dst_hoplimit(dst), 0, fl.fl6_sport,
			     fl.fl6_dport,
			     !skb_is_gso(skb) && udp_get_no_check6_tx(sk), 0);
	ret = 0;
err:
	local_bh_enable();
	return ret;
}
#endif

/**
 * ovpn_udp_output - transmit skb using udp-tunnel
 * @peer: the destination peer
 * @cache: dst cache
 * @sk: the socket to send the packet over
 * @skb: the packet to send
 * @key: route key snapshot used for cache validation and flow lookup
 *
 * rcu_read_lock should be held on entry.
 * On return, the skb is consumed.
 *
 * Return: 0 on success or a negative error code otherwise
 */
static int ovpn_udp_output(struct ovpn_peer *peer, struct dst_cache *cache,
			   struct sock *sk, struct sk_buff *skb,
			   struct ovpn_route_key *key)
{
	struct ovpn_bind *bind;
	int ret;

	/* set sk to null if skb is already orphaned */
	if (!skb->destructor)
		skb->sk = NULL;

	rcu_read_lock();
	bind = rcu_dereference(peer->bind);
	if (unlikely(!bind)) {
		net_warn_ratelimited("%s: no bind for remote peer %u\n",
				     netdev_name(peer->ovpn->dev), peer->id);
		ret = -ENODEV;
		goto out;
	}

	switch (bind->remote.in4.sin_family) {
	case AF_INET:
		ret = ovpn_udp4_output(peer, bind, cache, sk, skb, key);
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		ret = ovpn_udp6_output(peer, bind, cache, sk, skb, key);
		break;
#endif
	default:
		ret = -EAFNOSUPPORT;
		break;
	}

out:
	rcu_read_unlock();
	return ret;
}

/**
 * ovpn_udp_send_skb - prepare skb and send it over via UDP
 * @peer: the destination peer
 * @sk: peer socket
 * @skb: the packet to send
 */
void ovpn_udp_send_skb(struct ovpn_peer *peer, struct sock *sk,
		       struct sk_buff *skb)
{
	struct ovpn_route_key key = {
		.mark = READ_ONCE(sk->sk_mark),
		.sport = READ_ONCE(inet_sk(sk)->inet_sport),
	};
	int ret;

	skb->dev = peer->ovpn->dev;
	skb->mark = key.mark;
	if (skb_is_gso(skb)) {
		/* udp_tunnel_xmit_skb installs the outer UDP header after this
		 * function returns: point CHECKSUM_PARTIAL at that future
		 * header so both hw and sw UDP GSO can complete the checksum.
		 */
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_headroom(skb) - sizeof(struct udphdr);
		skb->csum_offset = offsetof(struct udphdr, check);
	} else {
		/* no checksum performed at this layer */
		skb->ip_summed = CHECKSUM_NONE;
	}

	ovpn_dst_cache_check_key(peer, &peer->dst_cache, &key);

	/* crypto layer -> transport (UDP) */
	ret = ovpn_udp_output(peer, &peer->dst_cache, sk, skb, &key);
	if (unlikely(ret < 0))
		kfree_skb(skb);
}

static void ovpn_udp_encap_destroy(struct sock *sk)
{
	struct ovpn_socket *sock;
	struct ovpn_priv *ovpn;

	rcu_read_lock();
	sock = rcu_dereference_sk_user_data(sk);
	if (!sock || !sock->ovpn) {
		rcu_read_unlock();
		return;
	}
	ovpn = sock->ovpn;
	rcu_read_unlock();

	ovpn_peers_free(ovpn, sk, OVPN_DEL_PEER_REASON_TRANSPORT_DISCONNECT);
}

/**
 * ovpn_udp_socket_attach - set udp-tunnel CBs on socket and link it to ovpn
 * @ovpn_sock: socket to configure
 * @sock: the socket container to be passed to setup_udp_tunnel_sock()
 * @ovpn: the openvp instance to link
 *
 * After invoking this function, the sock will be controlled by ovpn so that
 * any incoming packet may be processed by ovpn first.
 *
 * Return: 0 on success or a negative error code otherwise
 */
int ovpn_udp_socket_attach(struct ovpn_socket *ovpn_sock, struct socket *sock,
			   struct ovpn_priv *ovpn)
{
	struct udp_tunnel_sock_cfg cfg = {
		.sk_user_data = ovpn_sock,
		.encap_type = UDP_ENCAP_OVPNINUDP,
		.udp_flags = BIT(UDP_FLAGS_GRO_RCV_DETACHABLE) |
			     BIT(UDP_FLAGS_ENCAP_ACCEPT_FRAGLIST),
		.encap_rcv = ovpn_udp_encap_recv,
		.encap_destroy = ovpn_udp_encap_destroy,
		.gro_receive = ovpn_udp_gro_receive_fraglist,
	};
	struct ovpn_socket *old_data;
	int ret;

	/* make sure no pre-existing encapsulation handler exists */
	rcu_read_lock();
	old_data = rcu_dereference_sk_user_data(ovpn_sock->sk);
	if (!old_data) {
		/* another encapsulation (such as ESP-in-UDP) may own the
		 * socket without setting sk_user_data, and the GRO callback
		 * which it may have registered cannot be replaced
		 */
		if (READ_ONCE(udp_sk(ovpn_sock->sk)->encap_type) ||
		    READ_ONCE(udp_sk(ovpn_sock->sk)->gro_receive)) {
			rcu_read_unlock();
			netdev_dbg(ovpn->dev,
				   "provided socket already taken by other user\n");
			return -EBUSY;
		}

		/* socket is currently unused - we can take it */
		rcu_read_unlock();
		setup_udp_tunnel_sock(sock_net(ovpn_sock->sk), sock->sk, &cfg);
		return 0;
	}

	/* socket is in use. We need to understand if it's owned by this ovpn
	 * instance or by something else.
	 * In the former case, we can increase the refcounter and happily
	 * use it, because the same UDP socket is expected to be shared among
	 * different peers.
	 *
	 * Unlikely TCP, a single UDP socket can be used to talk to many remote
	 * hosts and therefore openvpn instantiates one only for all its peers
	 */
	if ((READ_ONCE(udp_sk(ovpn_sock->sk)->encap_type) == UDP_ENCAP_OVPNINUDP) &&
	    old_data->ovpn == ovpn) {
		netdev_dbg(ovpn->dev,
			   "provided socket already owned by this interface\n");
		ret = -EALREADY;
	} else {
		netdev_dbg(ovpn->dev,
			   "provided socket already taken by other user\n");
		ret = -EBUSY;
	}
	rcu_read_unlock();

	return ret;
}

/**
 * ovpn_udp_socket_detach - clean udp-tunnel status for this socket
 * @ovpn_sock: the socket to clean
 */
void ovpn_udp_socket_detach(struct ovpn_socket *ovpn_sock)
{
	struct udp_sock *up = udp_sk(ovpn_sock->sk);
	struct sock *sk = ovpn_sock->sk;

	/* Stop accepting aggregates while encap_rcv is still available. A
	 * reader which sampled acceptance before it was cleared can either be
	 * consumed by ovpn or fall back to UDP segmentation.
	 */
	if (udp_test_bit(GRO_RCV_DETACHABLE, sk) &&
	    READ_ONCE(up->gro_receive) == ovpn_udp_gro_receive_fraglist)
		udp_tunnel_detach_gro(sk);

	/* UDP_ENCAP may have replaced encap_rcv while leaving other ovpn state
	 * attached. Clear only callbacks still owned by ovpn. The final RCU
	 * grace period in ovpn_socket_release drains readers which captured
	 * encap_rcv before this point.
	 */
	if (READ_ONCE(up->encap_rcv) == ovpn_udp_encap_recv)
		WRITE_ONCE(up->encap_rcv, NULL);
	if (READ_ONCE(up->encap_destroy) == ovpn_udp_encap_destroy)
		WRITE_ONCE(up->encap_destroy, NULL);

	/* Re-enable multicast loopback */
	inet_set_bit(MC_LOOP, sk);
	/* Disable CHECKSUM_UNNECESSARY to CHECKSUM_COMPLETE conversion */
	inet_dec_convert_csum(sk);

	/* UDP_ENCAP might have rewritten the encap_type */
	if (READ_ONCE(up->encap_type) == UDP_ENCAP_OVPNINUDP)
		WRITE_ONCE(up->encap_type, 0);

	rcu_assign_sk_user_data(sk, NULL);
}

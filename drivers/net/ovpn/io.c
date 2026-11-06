// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2019-2025 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include <crypto/aead.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/gro_cells.h>
#include <net/gso.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/udp.h>

#include "ovpnpriv.h"
#include "peer.h"
#include "io.h"
#include "bind.h"
#include "crypto.h"
#include "crypto_aead.h"
#include "netlink.h"
#include "proto.h"
#include "tcp.h"
#include "udp.h"
#include "skb.h"
#include "socket.h"

const unsigned char ovpn_keepalive_message[OVPN_KEEPALIVE_SIZE] = {
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

/* gso_within_dev_limits() requires skb->len, which by then includes the
 * link-layer and outer network headers, to stay below gso_max_size
 */
#define OVPN_UDP_GSO_MAX_PAYLOAD	(GSO_LEGACY_MAX_SIZE -		\
					 LL_MAX_HEADER -		\
					 sizeof(struct ipv6hdr) -	\
					 sizeof(struct udphdr) - 1)

/**
 * ovpn_is_keepalive - check if skb contains a keepalive message
 * @skb: packet to check
 *
 * Assumes that the first byte of skb->data is defined.
 *
 * Return: true if skb contains a keepalive or false otherwise
 */
static bool ovpn_is_keepalive(struct sk_buff *skb)
{
	if (*skb->data != ovpn_keepalive_message[0])
		return false;

	if (skb->len != OVPN_KEEPALIVE_SIZE)
		return false;

	if (!pskb_may_pull(skb, OVPN_KEEPALIVE_SIZE))
		return false;

	return !memcmp(skb->data, ovpn_keepalive_message, OVPN_KEEPALIVE_SIZE);
}

/* Called after decrypt to write the IP packet to the device.
 * This method is expected to manage/free the skb.
 */
static void ovpn_netdev_write(struct ovpn_peer *peer, struct sk_buff *skb)
{
	unsigned int pkt_len;
	int ret;

	/*
	 * GSO state from the transport layer is not valid for the tunnel/data
	 * path. Reset all GSO fields to prevent any further GSO processing
	 * from entering an inconsistent state.
	 */
	skb_gso_reset(skb);

	/* we can't guarantee the packet wasn't corrupted before entering the
	 * VPN, therefore we give other layers a chance to check that
	 */
	skb->ip_summed = CHECKSUM_NONE;

	/* skb hash for transport packet no longer valid after decapsulation */
	skb_clear_hash(skb);

	/* post-decrypt scrub -- prepare to inject encapsulated packet onto the
	 * interface, based on __skb_tunnel_rx() in dst.h
	 */
	skb->dev = peer->ovpn->dev;
	skb_set_queue_mapping(skb, 0);
	skb_scrub_packet(skb, true);

	/* network header reset in ovpn_decrypt_post() */
	skb_reset_mac_header(skb);
	skb_reset_transport_header(skb);
	skb_reset_inner_headers(skb);

	/* cause packet to be "received" by the interface */
	pkt_len = skb->len;
	/* we may get here in process context in case of TCP connections,
	 * therefore we have to disable BHs to ensure gro_cells_receive()
	 * and dev_dstats_rx_add() do not get corrupted or enter deadlock
	 */
	local_bh_disable();
	ret = gro_cells_receive(&peer->ovpn->gro_cells, skb);
	if (likely(ret == NET_RX_SUCCESS)) {
		/* update RX stats with the size of decrypted packet */
		ovpn_peer_stats_increment_rx(&peer->vpn_stats, pkt_len);
		dev_dstats_rx_add(peer->ovpn->dev, pkt_len);
	}
	local_bh_enable();
}

void ovpn_decrypt_post(void *data, int ret)
{
	struct ovpn_crypto_key_slot *ks;
	unsigned int payload_offset = 0;
	struct sk_buff *skb = data;
	struct ovpn_socket *sock;
	struct ovpn_peer *peer;
	__be16 proto;
	__be32 *pid;

	/* crypto is happening asynchronously. this function will be called
	 * again later by the crypto callback with a proper return code
	 */
	if (unlikely(ret == -EINPROGRESS))
		return;

	payload_offset = ovpn_skb_cb(skb)->payload_offset;
	ks = ovpn_skb_cb(skb)->ks;
	peer = ovpn_skb_cb(skb)->peer;

	/* crypto is done, cleanup skb CB and its members */
	kfree(ovpn_skb_cb(skb)->crypto_tmp);

	if (unlikely(ret < 0))
		goto drop;

	/* PID sits after the op */
	pid = (__force __be32 *)(skb->data + OVPN_OPCODE_SIZE);
	ret = ovpn_pktid_recv(&ks->pid_recv, ntohl(*pid), 0);
	if (unlikely(ret < 0)) {
		net_err_ratelimited("%s: PKT ID RX error for peer %u: %d\n",
				    netdev_name(peer->ovpn->dev), peer->id,
				    ret);
		goto drop;
	}

	/* keep track of last received authenticated packet for keepalive */
	WRITE_ONCE(peer->last_recv, ktime_get_boottime_seconds());

	rcu_read_lock();
	sock = rcu_dereference(peer->sock);
	if (sock && sock->sk->sk_protocol == IPPROTO_UDP)
		/* check if this peer changed local or remote endpoint */
		ovpn_peer_endpoints_update(peer, skb);
	rcu_read_unlock();

	/* point to encapsulated IP packet */
	__skb_pull(skb, payload_offset);

	/* check if this is a valid datapacket that has to be delivered to the
	 * ovpn interface
	 */
	skb_reset_network_header(skb);
	proto = ovpn_ip_check_protocol(skb);
	if (unlikely(!proto)) {
		/* check if null packet */
		if (unlikely(!pskb_may_pull(skb, 1))) {
			net_info_ratelimited("%s: NULL packet received from peer %u\n",
					     netdev_name(peer->ovpn->dev),
					     peer->id);
			goto drop;
		}

		if (ovpn_is_keepalive(skb)) {
			net_dbg_ratelimited("%s: ping received from peer %u\n",
					    netdev_name(peer->ovpn->dev),
					    peer->id);
			/* we drop the packet, but this is not a failure */
			consume_skb(skb);
			goto drop_nocount;
		}

		net_info_ratelimited("%s: unsupported protocol received from peer %u\n",
				     netdev_name(peer->ovpn->dev), peer->id);
		goto drop;
	}
	skb->protocol = proto;

	/* perform Reverse Path Filtering (RPF) */
	if (unlikely(!ovpn_peer_check_by_src(peer->ovpn, skb, peer))) {
		if (skb->protocol == htons(ETH_P_IPV6))
			net_dbg_ratelimited("%s: RPF dropped packet from peer %u, src: %pI6c\n",
					    netdev_name(peer->ovpn->dev),
					    peer->id, &ipv6_hdr(skb)->saddr);
		else
			net_dbg_ratelimited("%s: RPF dropped packet from peer %u, src: %pI4\n",
					    netdev_name(peer->ovpn->dev),
					    peer->id, &ip_hdr(skb)->saddr);
		goto drop;
	}

	ovpn_netdev_write(peer, skb);
	/* skb is passed to upper layer - don't free it */
	skb = NULL;
drop:
	if (unlikely(skb))
		ovpn_dev_dstats_rx_dropped(peer->ovpn->dev);
	kfree_skb(skb);
drop_nocount:
	if (likely(ks))
		ovpn_crypto_key_slot_put(ks);
	ovpn_peer_put(peer);
}

/* RX path entry point: decrypt packet and forward it to the device */
void ovpn_recv(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_crypto_key_slot *ks;
	u8 key_id;

	ovpn_peer_stats_increment_rx(&peer->link_stats, skb->len);

	/* get the key slot matching the key ID in the received packet */
	key_id = ovpn_key_id_from_skb(skb);
	ks = ovpn_crypto_key_id_to_slot(&peer->crypto, key_id);
	if (unlikely(!ks)) {
		net_info_ratelimited("%s: no available key for peer %u, key-id: %u\n",
				     netdev_name(peer->ovpn->dev), peer->id,
				     key_id);
		ovpn_dev_dstats_rx_dropped(peer->ovpn->dev);
		kfree_skb(skb);
		ovpn_peer_put(peer);
		return;
	}

	memset(ovpn_skb_cb(skb), 0, sizeof(struct ovpn_cb));
	ovpn_decrypt_post(skb, ovpn_aead_decrypt(peer, ks, skb));
}

static void ovpn_encrypt_key_exhausted(struct ovpn_peer *peer,
				       struct ovpn_crypto_key_slot *ks)
{
	netdev_warn(peer->ovpn->dev, "killing key %u for peer %u\n",
		    ks->key_id, peer->id);
	if (ovpn_crypto_kill_key(&peer->crypto, ks->key_id))
		/* let userspace know so that a new key must be negotiated */
		ovpn_nl_key_swap_notify(peer, ks->key_id);
}

static void ovpn_encrypt_send(struct ovpn_peer *peer,
			      struct ovpn_crypto_key_slot *ks,
			      struct sk_buff *skb, unsigned int packets)
{
	struct ovpn_socket *sock;
	unsigned int orig_len;

	skb_mark_not_on_list(skb);
	orig_len = skb->len;

	rcu_read_lock();
	sock = rcu_dereference(peer->sock);
	if (unlikely(!sock))
		goto err_unlock;

	switch (sock->sk->sk_protocol) {
	case IPPROTO_UDP:
		ovpn_udp_send_skb(peer, sock->sk, skb);
		break;
	case IPPROTO_TCP:
		ovpn_tcp_send_skb(peer, sock->sk, skb);
		break;
	default:
		/* no transport configured yet */
		goto err_unlock;
	}

	ovpn_peer_stats_add_tx(&peer->link_stats, orig_len, packets);
	/* keep track of last sent packet for keepalive */
	WRITE_ONCE(peer->last_sent, ktime_get_boottime_seconds());
	/* skb passed down the stack - don't free it */
	skb = NULL;
err_unlock:
	rcu_read_unlock();
	if (unlikely(skb))
		ovpn_dev_dstats_tx_dropped(peer->ovpn->dev, packets);
	kfree_skb(skb);
	ovpn_crypto_key_slot_put(ks);
	ovpn_peer_put(peer);
}

void ovpn_encrypt_post(void *data, int ret)
{
	struct sk_buff *skb = data;
	struct ovpn_crypto_key_slot *ks;
	struct ovpn_peer *peer;

	/* encryption is happening asynchronously. This function will be
	 * called later by the crypto callback with a proper return value
	 */
	if (unlikely(ret == -EINPROGRESS))
		return;

	peer = ovpn_skb_cb(skb)->peer;
	ks = ovpn_skb_cb(skb)->ks;

	/* crypto is done, cleanup skb CB and its members */
	kfree(ovpn_skb_cb(skb)->crypto_tmp);

	if (unlikely(ret == -ERANGE)) {
		ovpn_encrypt_key_exhausted(peer, ks);
		goto err;
	}

	if (unlikely(ret < 0))
		goto err;

	ovpn_encrypt_send(peer, ks, skb, 1);
	return;
err:
	ovpn_dev_dstats_tx_dropped(peer->ovpn->dev, 1);
	kfree_skb(skb);
	ovpn_crypto_key_slot_put(ks);
	ovpn_peer_put(peer);
}

/* Hold the peer and its primary key for one encryption operation.
 * The returned key and the peer each carry one reference which the caller must
 * release or pass to the completion path.
 */
static struct ovpn_crypto_key_slot *
ovpn_encrypt_refs_get(struct ovpn_peer *peer)
{
	struct ovpn_crypto_key_slot *ks;

	/* get primary key to be used for encrypting data */
	ks = ovpn_crypto_key_slot_primary(&peer->crypto);
	if (unlikely(!ks))
		return NULL;

	/* the caller already owns a peer reference, so failure indicates a
	 * broken reference lifetime elsewhere
	 */
	if (unlikely(!ovpn_peer_hold(peer))) {
		DEBUG_NET_WARN_ON_ONCE(1);
		ovpn_crypto_key_slot_put(ks);
		return NULL;
	}

	return ks;
}

static bool ovpn_encrypt_one(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_crypto_key_slot *ks;

	ks = ovpn_encrypt_refs_get(peer);
	if (unlikely(!ks))
		return false;

	memset(ovpn_skb_cb(skb), 0, sizeof(struct ovpn_cb));
	ovpn_encrypt_post(skb, ovpn_aead_encrypt(peer, ks, skb));
	return true;
}

static bool ovpn_encrypt_gso_queue(struct sk_buff_head *skbs,
				   struct ovpn_peer *peer,
				   struct ovpn_crypto_key_slot *ks,
				   struct sk_buff *batch,
				   unsigned int segments)
{
	unsigned int offset = 0, moved = 0, i, len;
	struct sk_buff *skb;
	int ret;

	for (i = 0; i < segments; i++) {
		skb = __skb_dequeue(skbs);
		len = skb->len + OVPN_DATA_V2_OVERHEAD;

		memset(ovpn_skb_cb(skb), 0, sizeof(struct ovpn_cb));
		ret = ovpn_aead_encrypt_gso(peer, ks, skb, batch, offset);
		kfree(ovpn_skb_cb(skb)->crypto_tmp);
		if (unlikely(ret < 0)) {
			DEBUG_NET_WARN_ON_ONCE(ret == -EINPROGRESS ||
					       ret == -EBUSY);
			if (ret == -ERANGE)
				ovpn_encrypt_key_exhausted(peer, ks);
			ovpn_dev_dstats_tx_dropped(peer->ovpn->dev, i + 1);
			kfree_skb(skb);
			break;
		}

		/* pass on the TX timestamp request, which GSO segmentation
		 * attached to the segment holding the timestamped byte
		 */
		if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_ANY_TSTAMP)) {
			skb_shinfo(batch)->tx_flags |=
				skb_shinfo(skb)->tx_flags & SKBTX_ANY_TSTAMP;
			skb_shinfo(batch)->tskey = skb_shinfo(skb)->tskey;
		}

		/* the encrypted data now lives in the aggregate, which already
		 * carries the write charge, so free the segment without its
		 * destructor, which for TCP would wake TSQ before the batch has
		 * left the host
		 */
		if (batch->sk) {
			moved += skb->truesize;
			skb->destructor = NULL;
			skb->sk = NULL;
		}
		consume_skb(skb);
		offset += len;
	}

	/* the aggregate's own charge keeps sk_wmem_alloc above zero */
	if (moved)
		WARN_ON_ONCE(refcount_sub_and_test(moved,
						   &batch->sk->sk_wmem_alloc));
	if (unlikely(i < segments))
		goto err;

	ovpn_encrypt_send(peer, ks, batch, segments);
	return true;
err:
	ovpn_crypto_key_slot_put(ks);
	ovpn_peer_put(peer);
	return false;
}

static struct sk_buff *ovpn_udp_gso_alloc(const struct sk_buff *first_segment,
					  unsigned int batch_len,
					  unsigned int segments)
{
	struct sk_buff *gso_skb;
	int ret;

	gso_skb = alloc_skb_with_frags(OVPN_HEAD_ROOM, batch_len,
				       SKB_FRAG_PAGE_ORDER, &ret, GFP_ATOMIC);
	if (unlikely(!gso_skb))
		return NULL;

	skb_reserve(gso_skb, OVPN_HEAD_ROOM);
	skb_reset_inner_network_header(gso_skb);
	gso_skb->len = batch_len;
	gso_skb->data_len = batch_len;

	/* take over the input's write ownership with its own destructor, as
	 * GSO segmentation does, so that freeing the aggregate releases the
	 * charge and, for TCP, runs tcp_wfree to wake TSQ once the batch has
	 * left the host
	 */
	if (first_segment->sk && is_skb_wmem(first_segment)) {
		gso_skb->sk = first_segment->sk;
		gso_skb->destructor = first_segment->destructor;
		refcount_add(gso_skb->truesize,
			     &gso_skb->sk->sk_wmem_alloc);
	}

	/* keep the metadata retained by the in-place path, which reuses the
	 * input skb
	 */
	gso_skb->priority = first_segment->priority;
	skb_set_delivery_time(gso_skb, first_segment->tstamp,
			      first_segment->tstamp_type);
	gso_skb->ooo_okay = first_segment->ooo_okay;
	skb_set_dst_pending_confirm(gso_skb,
				    skb_get_dst_pending_confirm(first_segment));
	skb_copy_hash(gso_skb, first_segment);
	skb_copy_secmark(gso_skb, first_segment);
#ifdef CONFIG_XPS
	gso_skb->sender_cpu = first_segment->sender_cpu;
#endif

	skb_shinfo(gso_skb)->gso_type = SKB_GSO_UDP_L4;
	skb_shinfo(gso_skb)->gso_size = first_segment->len +
					OVPN_DATA_V2_OVERHEAD;
	skb_shinfo(gso_skb)->gso_segs = segments;

	return gso_skb;
}

/* send skb to connected peer, if any */
static void ovpn_send(struct ovpn_priv *ovpn, struct sk_buff *skb,
		      struct ovpn_peer *peer)
{
	struct sk_buff *curr, *next;

	/* this might be a GSO-segmented skb list: process each skb
	 * independently
	 */
	skb_list_walk_safe(skb, curr, next) {
		if (unlikely(!ovpn_encrypt_one(peer, curr))) {
			ovpn_dev_dstats_tx_dropped(ovpn->dev, 1);
			kfree_skb(curr);
		}
	}

	ovpn_peer_put(peer);
}

/* encrypt fixed-size input segments into one or more UDP GSO aggregates */
static void ovpn_send_gso(struct sk_buff_head *skbs, struct ovpn_peer *peer)
{
	unsigned int max_segs, seg_len, batch_len, segs;
	struct ovpn_crypto_key_slot *ks;
	struct sk_buff *batch;

	seg_len = skb_peek(skbs)->len + OVPN_DATA_V2_OVERHEAD;
	max_segs = min_t(unsigned int, UDP_MAX_SEGMENTS,
			 OVPN_UDP_GSO_MAX_PAYLOAD / seg_len);

	/* if even two encrypted skbs cannot fit, leave the whole queue for the
	 * ordinary transmit path
	 */
	if (max_segs < 2)
		return;

	/* An input GSO skb might produce more than max_segs segments, so we
	 * consume as many as we can for each iteration. A final single skb, or
	 * any remainder left after batching stops, stays queued and falls back
	 * to the ordinary transmit path.
	 */
	while (skb_queue_len(skbs) > 1) {
		segs = min_t(unsigned int, skb_queue_len(skbs), max_segs);
		/* acquire shared state before allocating/consuming anything */
		ks = ovpn_encrypt_refs_get(peer);
		if (unlikely(!ks))
			return;
		/* recheck in case the key was swapped */
		if (unlikely(ks->async)) {
			ovpn_crypto_key_slot_put(ks);
			ovpn_peer_put(peer);
			return;
		}

		/* all but the final input skb have the same length, so start
		 * with the full-size calculation and adjust only the final
		 * group below
		 */
		batch_len = segs * (skb_peek(skbs)->len +
				    OVPN_DATA_V2_OVERHEAD);
		if (segs == skb_queue_len(skbs))
			batch_len -= skb_peek(skbs)->len -
				     skb_peek_tail(skbs)->len;

		batch = ovpn_udp_gso_alloc(skb_peek(skbs), batch_len, segs);
		if (unlikely(!batch)) {
			ovpn_crypto_key_slot_put(ks);
			ovpn_peer_put(peer);
			return;
		}

		if (unlikely(!ovpn_encrypt_gso_queue(skbs, peer, ks,
						     batch, segs))) {
			kfree_skb(batch);
			return;
		}
	}
}

static bool ovpn_peer_supports_udp_gso(struct ovpn_peer *peer)
{
	struct ovpn_crypto_key_slot *ks;
	struct ovpn_socket *sock;
	bool udp_gso;
	u8 idx;

	rcu_read_lock();
	idx = READ_ONCE(peer->crypto.primary_idx);
	ks = rcu_dereference(peer->crypto.slots[idx]);
	sock = rcu_dereference(peer->sock);
	/* UDP GSO requires checksums. These socket settings can change after
	 * we decide to batch, but an already-built batch remains checksummed.
	 * Linux's ordinary UDP GSO path makes the same choice.
	 */
	udp_gso = ks && !ks->async && sock &&
		  sock->sk->sk_protocol == IPPROTO_UDP &&
		  !sock->sk->sk_no_check_tx && !udp_get_no_check6_tx(sock->sk);
	rcu_read_unlock();

	return udp_gso;
}

/* Send user data to the network
 */
netdev_tx_t ovpn_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ovpn_priv *ovpn = netdev_priv(dev);
	struct sk_buff *segments, *curr, *next;
	const bool gso_in = skb_is_gso(skb);
	struct sk_buff_head skb_list;
	netdev_features_t features;
	unsigned int tx_bytes = 0;
	struct ovpn_peer *peer;
	bool gso_out;
	__be16 proto;
	int ret;

	/* GSO_BY_FRAGS input remains on the in-place path because its variable
	 * segment sizes cannot be represented by one UDP GSO output size
	 */
	gso_out = gso_in && skb_shinfo(skb)->gso_size != GSO_BY_FRAGS;

	/* reset netfilter state */
	nf_reset_ct(skb);

	/* verify IP header size in network packet */
	proto = ovpn_ip_check_protocol(skb);
	if (unlikely(!proto || skb->protocol != proto))
		goto drop_no_peer;

	/* retrieve peer serving the destination IP of this packet */
	peer = ovpn_peer_get_by_dst(ovpn, skb);
	if (unlikely(!peer)) {
		switch (skb->protocol) {
		case htons(ETH_P_IP):
			net_dbg_ratelimited("%s: no peer to send data to dst=%pI4\n",
					    netdev_name(ovpn->dev),
					    &ip_hdr(skb)->daddr);
			break;
		case htons(ETH_P_IPV6):
			net_dbg_ratelimited("%s: no peer to send data to dst=%pI6c\n",
					    netdev_name(ovpn->dev),
					    &ipv6_hdr(skb)->daddr);
			break;
		}
		goto drop_no_peer;
	}
	/* dst was needed for peer selection - it can now be dropped */
	skb_dst_drop(skb);

	if (gso_in) {
		/* force software segmentation and calculate each checksum
		 * while allowing safe page-backed payload fragments to remain
		 * non-linear
		 */
		features = netif_skb_features(skb);
		features &= ~(NETIF_F_GSO_MASK | NETIF_F_CSUM_MASK);
		segments = skb_gso_segment(skb, features);
		if (IS_ERR_OR_NULL(segments)) {
			ret = PTR_ERR(segments);
			net_err_ratelimited("%s: cannot segment payload packet: %d\n",
					    netdev_name(dev), ret);
			goto drop;
		}

		consume_skb(skb);
		skb = segments;
	}

	/* from this moment on, "skb" might be a list */

	__skb_queue_head_init(&skb_list);
	skb_list_walk_safe(skb, curr, next) {
		skb_mark_not_on_list(curr);

		curr = skb_share_check(curr, GFP_ATOMIC);
		if (unlikely(!curr)) {
			net_err_ratelimited("%s: skb_share_check failed for payload packet\n",
					    netdev_name(dev));
			ovpn_dev_dstats_tx_dropped(ovpn->dev, 1);
			gso_out = false;
			continue;
		}

		/* NETIF_F_HW_CSUM requires completing partial checksums */
		if (unlikely(curr->ip_summed == CHECKSUM_PARTIAL &&
			     skb_checksum_help(curr) < 0)) {
			net_err_ratelimited("%s: skb_checksum_help failed for payload packet\n",
					    netdev_name(dev));
			ovpn_dev_dstats_tx_dropped(ovpn->dev, 1);
			kfree_skb(curr);
			gso_out = false;
			continue;
		}

		/* one aggregate can carry only one write owner, so batch only
		 * segments that share it
		 */
		if (gso_out && !skb_queue_empty(&skb_list)) {
			struct sk_buff *prev = skb_peek_tail(&skb_list);

			if (unlikely(prev->sk != curr->sk ||
				     prev->destructor != curr->destructor))
				gso_out = false;
		}

		/* only count what we actually send */
		tx_bytes += curr->len;
		__skb_queue_tail(&skb_list, curr);
	}

	/* no segments survived: don't jump to 'drop' because we already
	 * incremented the counter for each failure in the loop
	 */
	if (unlikely(skb_queue_empty(&skb_list))) {
		ovpn_peer_put(peer);
		return NETDEV_TX_OK;
	}

	ovpn_peer_stats_add_tx(&peer->vpn_stats, tx_bytes,
			       skb_queue_len(&skb_list));

	if (gso_out && skb_queue_len(&skb_list) > 1 &&
	    ovpn_peer_supports_udp_gso(peer))
		ovpn_send_gso(&skb_list, peer);

	skb_list.prev->next = NULL;
	ovpn_send(ovpn, skb_list.next, peer);

	return NETDEV_TX_OK;

drop:
	ovpn_peer_put(peer);
drop_no_peer:
	ovpn_dev_dstats_tx_dropped(ovpn->dev, 1);
	skb_tx_error(skb);
	kfree_skb_list(skb);
	return NETDEV_TX_OK;
}

/**
 * ovpn_xmit_special - encrypt and transmit an out-of-band message to peer
 * @peer: peer to send the message to
 * @data: message content
 * @len: message length
 *
 * Assumes that caller holds a reference to peer, which will be
 * passed to ovpn_send()
 */
void ovpn_xmit_special(struct ovpn_peer *peer, const void *data,
		       const unsigned int len)
{
	struct ovpn_priv *ovpn;
	struct sk_buff *skb;

	ovpn = peer->ovpn;
	if (unlikely(!ovpn)) {
		ovpn_peer_put(peer);
		return;
	}

	skb = alloc_skb(256 + len, GFP_ATOMIC);
	if (unlikely(!skb)) {
		ovpn_peer_put(peer);
		return;
	}

	skb_reserve(skb, 128);
	skb->priority = TC_PRIO_BESTEFFORT;
	__skb_put_data(skb, data, len);

	ovpn_send(ovpn, skb, peer);
}

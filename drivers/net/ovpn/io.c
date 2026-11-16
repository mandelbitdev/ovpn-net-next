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
#include <net/ip6_checksum.h>
#include <net/sock.h>
#include <net/udp.h>

#include "ovpnpriv.h"
#include "peer.h"
#include "io.h"
#include "gso.h"
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

/**
 * ovpn_partial_csum_prepare - set up a partial checksum for the skb
 * @skb: skb whose checksum has to be converted
 *
 * Turn a trusted or validated inner TCP/UDP checksum into the canonical
 * CHECKSUM_PARTIAL representation sent to partial-csum peers.
 *
 * Return: 1 when the checksum was prepared, 0 when this packet is not eligible
 * and a negative error when an eligible checksum failed validation.
 */
static int ovpn_partial_csum_prepare(struct sk_buff *skb)
{
	bool csum_complete_sw, csum_not_inet, csum_valid;
	unsigned int transport_offset, transport_header;
	u8 ip_summed, csum_level, proto;
	__sum16 check, ret;
	__wsum csum;
	int err;

	/* Parsing the checksum target also pulls the complete transport header
	 * into the linear area. Save the original checksum state because setup
	 * temporarily replaces it with CHECKSUM_PARTIAL.
	 */
	ip_summed = skb->ip_summed;
	csum = skb->csum;
	csum_level = skb->csum_level;
	csum_valid = skb->csum_valid;
	csum_complete_sw = skb->csum_complete_sw;
	csum_not_inet = skb->csum_not_inet;
	transport_header = skb->transport_header;

	err = skb_checksum_setup(skb, false);
	if (unlikely(err)) {
		skb->transport_header = transport_header;
		return err == -EPROTO ? 0 : err;
	}

	transport_offset = skb_checksum_start_offset(skb);
	if (skb->csum_offset == offsetof(struct tcphdr, check)) {
		proto = IPPROTO_TCP;
		check = tcp_hdr(skb)->check;
	} else {
		proto = IPPROTO_UDP;
		check = udp_hdr(skb)->check;
	}

	/* PARTIAL is a request from the originating stack and UNNECESSARY or
	 * csum_valid means that an earlier layer already verified the checksum
	 */
	if (likely(ip_summed == CHECKSUM_PARTIAL ||
		   ip_summed == CHECKSUM_UNNECESSARY || csum_valid))
		goto setup;

	/* COMPLETE can normally be validated from its accumulated sum while
	 * NONE has no such evidence and therefore takes the full walk
	 */
	skb->ip_summed = ip_summed;
	skb->csum = csum;
	skb->csum_level = csum_level;
	skb->csum_valid = csum_valid;
	skb->csum_complete_sw = csum_complete_sw;
	skb->csum_not_inet = csum_not_inet;

	if (unlikely(!skb_pull_rcsum(skb, transport_offset)))
		return -EPROTO;

	if (skb->protocol == htons(ETH_P_IP)) {
		if (proto == IPPROTO_UDP)
			ret = skb_checksum_validate_zero_check(skb, proto, check,
							       inet_compute_pseudo);
		else
			ret = skb_checksum_validate(skb, proto,
						    inet_compute_pseudo);
	} else {
		if (proto == IPPROTO_UDP)
			ret = skb_checksum_validate_zero_check(skb, proto, check,
							       ip6_compute_pseudo);
		else
			ret = skb_checksum_validate(skb, proto,
						    ip6_compute_pseudo);
	}

	skb_push(skb, transport_offset);
	if (unlikely(ret))
		return -EBADMSG;

setup:
	/* replace any complete csum with a freshly calculated pseudo-header
	 * seed, so every offloaded record has one unambiguous representation
	 */
	skb->csum_valid = 0;
	skb->csum_complete_sw = 0;
	skb->csum_level = 0;
	skb->csum_not_inet = 0;
	err = skb_checksum_setup(skb, true);
	return unlikely(err) ? err : 1;
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

	if (peer->partial_csum && !skb_checksum_setup(skb, true)) {
		/* the authenticated peer left the checksum for this host and
		 * skb_checksum_setup reconstructed both its pseudo-header seed
		 * and the CHECKSUM_PARTIAL metadata from the inner IP headers
		 */
		skb->csum_level = 0;
	} else {
		/* we can't guarantee the packet wasn't corrupted before
		 * entering the VPN, therefore we give other layers a chance to
		 * check that, and csum_valid still refers to the outer header
		 */
		skb->ip_summed = CHECKSUM_NONE;
		skb->csum_valid = 0;
	}

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

void ovpn_encrypt_key_exhausted(struct ovpn_peer *peer,
				struct ovpn_crypto_key_slot *ks)
{
	netdev_warn(peer->ovpn->dev, "killing key %u for peer %u\n",
		    ks->key_id, peer->id);
	if (ovpn_crypto_kill_key(&peer->crypto, ks->key_id))
		/* let userspace know so that a new key must be negotiated */
		ovpn_nl_key_swap_notify(peer, ks->key_id);
}

void ovpn_encrypt_send(struct ovpn_peer *peer,
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
struct ovpn_crypto_key_slot *
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

/* Send user data to the network
 */
netdev_tx_t ovpn_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ovpn_priv *ovpn = netdev_priv(dev);
	struct sk_buff *segments, *curr, *next;
	unsigned int tx_bytes = 0, tx_packets;
	const bool gso_in = skb_is_gso(skb);
	struct sk_buff_head skb_list;
	netdev_features_t features;
	struct ovpn_peer *peer;
	bool gso_out, partial_csum;
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

	/* the receiver rebuilds only the outermost inner L4 checksum, while an
	 * encapsulated packet may need one further in
	 */
	partial_csum = peer->partial_csum && !skb->encapsulation;
	if (partial_csum && gso_in) {
		/* a GSO checksum is a template for the future segments, which
		 * the record builder sets up when the state is trusted
		 */
		partial_csum = skb_csum_unnecessary(skb);
	} else if (partial_csum) {
		/* validate the checksum before any bytes are encrypted */
		ret = ovpn_partial_csum_prepare(skb);
		if (unlikely(ret < 0)) {
			net_err_ratelimited("%s: invalid inner checksum: %d\n",
					    netdev_name(dev), ret);
			goto drop;
		}
		partial_csum = ret > 0;
	}

	gso_out = gso_out && ovpn_gso_supported(peer);
	if (gso_out && ovpn_gso_send_tso(skb, peer, partial_csum))
		return NETDEV_TX_OK;

	if (gso_in) {
		/* force software segmentation while allowing safe page-backed
		 * payload fragments to remain non-linear. Batching normally
		 * completes the L4 checksums while copying the segments. For
		 * partial-csum peers, the receiver does it instead.
		 */
		features = netif_skb_features(skb);
		features &= ~NETIF_F_GSO_MASK;
		if (!gso_out && !partial_csum)
			features &= ~NETIF_F_CSUM_MASK;
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

		/* batching copies only the linear area and page frags */
		if (unlikely(skb_has_frag_list(curr)))
			gso_out = false;

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

	tx_packets = skb_queue_len(&skb_list);
	if (gso_out && tx_packets > 1)
		ovpn_gso_send(&skb_list, peer, partial_csum);

	/* NETIF_F_HW_CSUM requires completing partial checksums, which batching
	 * does while copying. Complete packets left for the ordinary path too,
	 * unless the peer negotiated doing so after authentication.
	 */
	skb_queue_walk_safe(&skb_list, curr, next) {
		if (partial_csum ||
		    curr->ip_summed != CHECKSUM_PARTIAL ||
		    likely(skb_checksum_help(curr) >= 0))
			continue;

		net_err_ratelimited("%s: skb_checksum_help failed for payload packet\n",
				    netdev_name(dev));
		__skb_unlink(curr, &skb_list);
		ovpn_dev_dstats_tx_dropped(ovpn->dev, 1);
		tx_bytes -= curr->len;
		tx_packets--;
		kfree_skb(curr);
	}

	ovpn_peer_stats_add_tx(&peer->vpn_stats, tx_bytes, tx_packets);

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

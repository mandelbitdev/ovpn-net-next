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
#include <net/ipv6.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/tso.h>
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

/* Reconstruct inner offload state only from authenticated, bounded headers.
 * The segment size comes from the wire; derive the count from the payload.
 */
static int ovpn_tcp_gso_restore(struct sk_buff *skb, u16 gso_size)
{
	unsigned int thoff = 0, hdr_len, payload_len, gso_type;
	struct tcphdr *th;

	if (skb->protocol == htons(ETH_P_IP)) {
		const struct iphdr *iph = ip_hdr(skb);

		thoff = iph->ihl * 4;
		if (thoff < sizeof(*iph) || iph->protocol != IPPROTO_TCP ||
		    ip_is_fragment(iph) || ntohs(iph->tot_len) != skb->len)
			return -EINVAL;
		gso_type = SKB_GSO_TCPV4;
	} else {
		const struct ipv6hdr *iph = ipv6_hdr(skb);
		int flags = IP6_FH_F_AUTH;

		if (ntohs(iph->payload_len) + sizeof(*iph) != skb->len ||
		    ipv6_find_hdr(skb, &thoff, -1, NULL, &flags) != IPPROTO_TCP ||
		    (flags & IP6_FH_F_FRAG))
			return -EINVAL;
		gso_type = SKB_GSO_TCPV6;
	}

	if (!pskb_may_pull(skb, thoff + sizeof(*th)))
		return -EINVAL;
	skb_set_transport_header(skb, thoff);
	th = tcp_hdr(skb);
	if (th->doff < sizeof(*th) / 4 || th->syn || th->rst || th->urg)
		return -EINVAL;
	hdr_len = thoff + th->doff * 4;
	if (!pskb_may_pull(skb, hdr_len) || skb->len <= hdr_len)
		return -EINVAL;

	/* Match TCP GRO completion: restore the pseudo-header checksum seed
	 * and let the stack complete per-segment checksums when needed.
	 */
	th = tcp_hdr(skb);
	if (skb->protocol == htons(ETH_P_IP))
		th->check = ~tcp_v4_check(skb->len - thoff, ip_hdr(skb)->saddr,
					  ip_hdr(skb)->daddr, 0);
	else
		th->check = ~tcp_v6_check(skb->len - thoff, &ipv6_hdr(skb)->saddr,
					  &ipv6_hdr(skb)->daddr, 0);
	skb->csum_start = skb_headroom(skb) + thoff;
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb->ip_summed = CHECKSUM_PARTIAL;

	/* A short, single-segment input only needs checksum completion. */
	payload_len = skb->len - hdr_len;
	if (payload_len > gso_size) {
		skb_shinfo(skb)->gso_type = gso_type | SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_size = gso_size;
		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(payload_len, gso_size);
	}

	return 0;
}

/* RX bookkeeping of the records a CPU delivers from one GRO list: the peer's
 * stats and references are updated once per batch instead of with atomics on
 * every record. The records of a GRO list share the outer addresses and the
 * key ID (ovpn's GRO handler compares them) and usually the inner source
 * address, so the batch also holds one key slot reference for the records
 * decrypted synchronously, checks the peer endpoints once and remembers the
 * last inner source that passed RPF.
 */
struct ovpn_rx_batch {
	struct ovpn_peer *peer;
	struct ovpn_crypto_key_slot *ks;
	unsigned int bytes;
	unsigned int packets;
	unsigned int puts;
	bool authenticated;
	bool endpoints_checked;
	bool src4_ok;
	bool src6_ok;
	__be32 src4;
	struct in6_addr src6;
};

static DEFINE_PER_CPU(struct ovpn_rx_batch, ovpn_rx_batches);

/**
 * ovpn_rx_batch_begin - start batching the RX bookkeeping of a peer
 * @peer: the peer the following records belong to
 *
 * Must be called with BHs disabled, which must stay disabled until
 * ovpn_rx_batch_end().
 */
void ovpn_rx_batch_begin(struct ovpn_peer *peer)
{
	struct ovpn_rx_batch *b = this_cpu_ptr(&ovpn_rx_batches);

	DEBUG_NET_WARN_ON_ONCE(!in_softirq() || b->peer);
	b->peer = peer;
	b->ks = NULL;
	b->bytes = 0;
	b->packets = 0;
	b->puts = 0;
	b->authenticated = false;
	b->endpoints_checked = false;
	b->src4_ok = false;
	b->src6_ok = false;
}

/**
 * ovpn_rx_batch_end - flush the batched RX bookkeeping
 *
 * Must be called with BHs still disabled since ovpn_rx_batch_begin(). The
 * batched peer references are released last: the peer may be gone once this
 * returns.
 */
void ovpn_rx_batch_end(void)
{
	struct ovpn_rx_batch *b = this_cpu_ptr(&ovpn_rx_batches);
	struct ovpn_peer *peer = b->peer;

	b->peer = NULL;
	if (b->ks)
		ovpn_crypto_key_slot_put(b->ks);
	if (b->authenticated)
		ovpn_peer_touch(&peer->last_recv);
	if (b->packets)
		ovpn_peer_stats_add_rx(&peer->vpn_stats, b->bytes, b->packets);
	if (b->puts)
		ovpn_peer_put_many(peer, b->puts);
}

/* the batch open for @peer on this CPU, if any. A batch is only open while
 * its owner keeps BHs disabled, so any other context that sees it with BHs
 * disabled (in_softirq() is also true then) is the owner's own call chain;
 * a hard IRQ completing crypto must not use it
 */
static struct ovpn_rx_batch *ovpn_rx_batch_get(struct ovpn_peer *peer)
{
	struct ovpn_rx_batch *b;

	if (!in_softirq() || in_hardirq())
		return NULL;

	b = this_cpu_ptr(&ovpn_rx_batches);
	return b->peer == peer ? b : NULL;
}

/* Called after decrypt to write the IP packet to the device.
 * This method is expected to manage/free the skb.
 */
static void ovpn_netdev_write(struct ovpn_peer *peer, struct sk_buff *skb,
			      struct ovpn_rx_batch *b)
{
	unsigned int pkt_len, packets = 1;
	int ret;

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
	skb_reset_inner_headers(skb);

	/* cause packet to be "received" by the interface */
	pkt_len = skb->len;
	if (skb_is_gso(skb)) {
		packets = skb_shinfo(skb)->gso_segs;
		pkt_len += (packets - 1) * skb_tcp_all_headers(skb);
	}
	/* we may get here in process context in case of TCP connections,
	 * therefore we have to disable BHs to ensure gro_cells_receive()
	 * and dev_dstats_rx_add() do not get corrupted or enter deadlock.
	 * An open batch means they are disabled already.
	 */
	if (!b)
		local_bh_disable();
	ret = gro_cells_receive(&peer->ovpn->gro_cells, skb);
	if (likely(ret == NET_RX_SUCCESS)) {
		/* update RX stats with the size of decrypted packet */
		if (b) {
			b->bytes += pkt_len;
			b->packets += packets;
		} else {
			ovpn_peer_stats_add_rx(&peer->vpn_stats, pkt_len,
					       packets);
		}
		ovpn_dev_dstats_rx_add(peer->ovpn->dev, pkt_len, packets);
	}
	if (!b)
		local_bh_enable();
}

/* RPF check, skipped for the inner source of the previous record if that
 * passed it in this batch
 */
static bool ovpn_rx_check_src(struct ovpn_peer *peer, struct sk_buff *skb,
			      struct ovpn_rx_batch *b)
{
	bool v4 = skb->protocol == htons(ETH_P_IP);

	if (b) {
		if (v4 && b->src4_ok && ip_hdr(skb)->saddr == b->src4)
			return true;
		if (!v4 && b->src6_ok &&
		    ipv6_addr_equal(&ipv6_hdr(skb)->saddr, &b->src6))
			return true;
	}

	if (!ovpn_peer_check_by_src(peer->ovpn, skb, peer))
		return false;

	if (b) {
		if (v4) {
			b->src4 = ip_hdr(skb)->saddr;
			b->src4_ok = true;
		} else {
			b->src6 = ipv6_hdr(skb)->saddr;
			b->src6_ok = true;
		}
	}
	return true;
}

void ovpn_decrypt_post(void *data, int ret)
{
	struct ovpn_crypto_key_slot *ks;
	unsigned int payload_offset = 0;
	struct sk_buff *skb = data;
	struct ovpn_socket *sock;
	struct ovpn_rx_batch *b;
	struct ovpn_peer *peer;
	u16 gso_size;
	__be16 proto;
	__be32 *pid;

	/* crypto is happening asynchronously. this function will be called
	 * again later by the crypto callback with a proper return code
	 */
	if (unlikely(ret == -EINPROGRESS))
		return;

	payload_offset = ovpn_skb_cb(skb)->payload_offset;
	gso_size = ovpn_skb_cb(skb)->gso_size;
	ks = ovpn_skb_cb(skb)->ks;
	peer = ovpn_skb_cb(skb)->peer;
	b = ovpn_rx_batch_get(peer);

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
	if (b)
		b->authenticated = true;
	else
		ovpn_peer_touch(&peer->last_recv);

	/* the records of a batch share their outer addresses: check them once */
	if (!b || !b->endpoints_checked) {
		rcu_read_lock();
		sock = rcu_dereference(peer->sock);
		if (sock && sock->sk->sk_protocol == IPPROTO_UDP)
			/* check if this peer changed local or remote endpoint */
			ovpn_peer_endpoints_update(peer, skb);
		rcu_read_unlock();
		if (b)
			b->endpoints_checked = true;
	}

	/* point to encapsulated IP packet */
	__skb_pull(skb, payload_offset);

	/* Discard outer offload state before reconstructing the inner packet.
	 * The packet was authenticated by the AEAD decryption, therefore it
	 * can't have been corrupted while travelling between the peers: skip
	 * the software checksum verification of all its layers, like
	 * wireguard does. A reconstructed GSO packet switches to
	 * CHECKSUM_PARTIAL below.
	 */
	skb->encapsulation = 0;
	skb_gso_reset(skb);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->csum_level = SKB_MAX_CSUM_LEVEL;
	skb_reset_transport_header(skb);

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

		if (!gso_size && ovpn_is_keepalive(skb)) {
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
	if (gso_size && ovpn_tcp_gso_restore(skb, gso_size))
		goto drop;

	/* perform Reverse Path Filtering (RPF) */
	if (unlikely(!ovpn_rx_check_src(peer, skb, b))) {
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

	ovpn_netdev_write(peer, skb, b);
	/* skb is passed to upper layer - don't free it */
	skb = NULL;
drop:
	if (unlikely(skb))
		ovpn_dev_dstats_rx_dropped(peer->ovpn->dev);
	kfree_skb(skb);
drop_nocount:
	/* the batch releases its own key slot reference */
	if (likely(ks) && (!b || ks != b->ks))
		ovpn_crypto_key_slot_put(ks);
	if (b)
		b->puts++;
	else
		ovpn_peer_put(peer);
}

/* decrypt a record and forward it to the device, its link stats already
 * accounted by the caller
 */
void ovpn_recv_record(struct ovpn_peer *peer, struct sk_buff *skb, bool tcp)
{
	struct ovpn_rx_batch *b = ovpn_rx_batch_get(peer);
	struct ovpn_crypto_key_slot *ks;
	u8 key_id;

	/* get the key slot matching the key ID in the received packet. The
	 * batch reference covers only synchronous decryption, which completes
	 * before the batch ends; a key replaced during the batch is still used
	 * for the rest of it.
	 */
	key_id = ovpn_key_id_from_skb(skb);
	if (b && b->ks && b->ks->key_id == key_id) {
		ks = b->ks;
	} else {
		ks = ovpn_crypto_key_id_to_slot(&peer->crypto, key_id);
		if (b && !b->ks && ks && ks->decrypt_sync)
			b->ks = ks;
	}
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
	ovpn_decrypt_post(skb, ovpn_aead_decrypt(peer, ks, skb, tcp));
}

/* RX path entry point: decrypt packet and forward it to the device */
void ovpn_recv(struct ovpn_peer *peer, struct sk_buff *skb, bool tcp)
{
	ovpn_peer_stats_increment_rx(&peer->link_stats, skb->len);
	ovpn_recv_record(peer, skb, tcp);
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
	ovpn_peer_touch(&peer->last_sent);
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
	unsigned int packets;

	/* encryption is happening asynchronously. This function will be
	 * called later by the crypto callback with a proper return value
	 */
	if (unlikely(ret == -EINPROGRESS))
		return;

	peer = ovpn_skb_cb(skb)->peer;
	ks = ovpn_skb_cb(skb)->ks;
	packets = ovpn_skb_cb(skb)->tcp_packets ?: 1;

	/* crypto is done, cleanup skb CB and its members */
	kfree(ovpn_skb_cb(skb)->crypto_tmp);

	if (unlikely(ret == -ERANGE)) {
		ovpn_encrypt_key_exhausted(peer, ks);
		goto err;
	}

	if (unlikely(ret < 0))
		goto err;

	ovpn_encrypt_send(peer, ks, skb, packets);
	return;
err:
	ovpn_dev_dstats_tx_dropped(peer->ovpn->dev, packets);
	kfree_skb(skb);
	ovpn_crypto_key_slot_put(ks);
	ovpn_peer_put(peer);
}

/* One request owns the input and output, with no UDP batch completion state.
 * The output owns the peer/key references used by the ordinary send path.
 */
void ovpn_encrypt_tcp_gso_post(void *data, int ret)
{
	struct sk_buff *skb = data;
	struct sk_buff *gso_skb;

	if (unlikely(ret == -EINPROGRESS))
		return;

	gso_skb = ovpn_skb_cb(skb)->tcp_gso;
	kfree(ovpn_skb_cb(skb)->crypto_tmp);
	consume_skb(skb);
	ovpn_encrypt_post(gso_skb, ret);
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

static bool ovpn_peer_uses_tcp(struct ovpn_peer *peer)
{
	struct ovpn_socket *sock;
	bool tcp;

	rcu_read_lock();
	sock = rcu_dereference(peer->sock);
	tcp = sock && sock->sk->sk_protocol == IPPROTO_TCP;
	rcu_read_unlock();

	return tcp;
}

static bool ovpn_encrypt_one(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_crypto_key_slot *ks;

	ks = ovpn_encrypt_refs_get(peer);
	if (unlikely(!ks))
		return false;

	memset(ovpn_skb_cb(skb), 0, sizeof(struct ovpn_cb));
	ovpn_skb_cb(skb)->tcp_packets = ovpn_peer_uses_tcp(peer);
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
	struct ovpn_aead_gso_ctx ctx = { };
	struct sk_buff *skb;
	u32 first_pktid;
	int ret;

	if (unlikely(ovpn_aead_gso_ctx_init(&ctx, ks, batch)))
		goto err;

	/* reserve the complete range before dequeuing any input skb so that a
	 * failure leaves the ordinary transmit path available as a fallback
	 */
	if (unlikely(ovpn_pktid_xmit_range(&ks->pid_xmit, segments,
					   &first_pktid))) {
		ovpn_encrypt_key_exhausted(peer, ks);
		goto err;
	}

	for (i = 0; i < segments; i++) {
		skb = __skb_dequeue(skbs);
		len = skb->len + OVPN_DATA_V2_OVERHEAD;

		ret = ovpn_aead_encrypt_gso(&ctx, peer, ks, skb, batch, offset,
					    first_pktid + i);
		if (unlikely(ret < 0)) {
			DEBUG_NET_WARN_ON_ONCE(ret == -EINPROGRESS ||
					       ret == -EBUSY);
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

	ovpn_aead_gso_ctx_free(&ctx);
	ovpn_encrypt_send(peer, ks, batch, segments);
	return true;
err:
	ovpn_aead_gso_ctx_free(&ctx);
	ovpn_crypto_key_slot_put(ks);
	ovpn_peer_put(peer);
	return false;
}

/* allocate the UDP GSO aggregate of @segments plaintext segments of @seg_len
 * bytes (the last one may be shorter), taking the metadata and the write
 * ownership of @first_segment, or of the GSO input they are built from. A
 * single segment is an ordinary packet: the stack rejects one-segment UDP GSO
 * skbs.
 */
static struct sk_buff *ovpn_udp_gso_alloc(const struct sk_buff *first_segment,
					  unsigned int seg_len,
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

	if (segments > 1) {
		skb_shinfo(gso_skb)->gso_type = SKB_GSO_UDP_L4;
		skb_shinfo(gso_skb)->gso_size = seg_len + OVPN_DATA_V2_OVERHEAD;
		skb_shinfo(gso_skb)->gso_segs = segments;
	}

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

		batch = ovpn_udp_gso_alloc(skb_peek(skbs), skb_peek(skbs)->len,
					   batch_len, segs);
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

/* The transmit stack validates GSO geometry, including DODGY inputs. Only
 * check whether the wire format can represent this skb's offload semantics.
 */
static bool ovpn_tcp_gso_eligible(const struct sk_buff *skb,
				  unsigned int *segments, unsigned int *hdr_len)
{
	const struct skb_shared_info *shinfo = skb_shinfo(skb);
	unsigned int type = shinfo->gso_type & ~SKB_GSO_DODGY;
	unsigned int payload_len;

	if (skb->encapsulation || skb->len > OVPN_TCP_GSO_MAX_INNER ||
	    skb->ip_summed != CHECKSUM_PARTIAL)
		return false;

	if (type != SKB_GSO_TCPV4 && type != SKB_GSO_TCPV6)
		return false;

	*hdr_len = skb_transport_offset(skb) + tcp_hdrlen(skb);
	payload_len = skb->len - *hdr_len;
	*segments = DIV_ROUND_UP(payload_len, shinfo->gso_size);

	return true;
}

/* the output of a TCP GSO input: the record header in the linear head, the
 * ciphertext in pages sent by MSG_SPLICE_PAGES
 */
static struct sk_buff *ovpn_tcp_gso_alloc(const struct sk_buff *skb)
{
	struct sk_buff *gso_skb;
	int ret;

	gso_skb = alloc_skb_with_frags(OVPN_HEAD_ROOM + OVPN_DATA_V2_OVERHEAD,
				       skb->len, SKB_FRAG_PAGE_ORDER, &ret,
				       GFP_ATOMIC);
	if (unlikely(!gso_skb))
		return NULL;

	skb_reserve(gso_skb, OVPN_HEAD_ROOM);
	skb_put(gso_skb, OVPN_DATA_V2_OVERHEAD);
	gso_skb->len += skb->len;
	gso_skb->data_len = skb->len;
	gso_skb->priority = skb->priority;

	/* Keep the originating socket's send-buffer accounting active until
	 * the output is transmitted. This also preserves its cached TX queue.
	 */
	if (skb->sk && is_skb_wmem(skb))
		skb_set_owner_w(gso_skb, skb->sk);

	return gso_skb;
}

/* Returning false leaves the input owned by the segmentation fallback. */
static bool ovpn_send_tcp_gso(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_crypto_key_slot *ks;
	unsigned int segments, hdr_len;
	struct sk_buff *gso_skb;
	int ret;

	if (!ovpn_peer_uses_tcp(peer) ||
	    !ovpn_tcp_gso_eligible(skb, &segments, &hdr_len))
		return false;

	gso_skb = ovpn_tcp_gso_alloc(skb);
	if (unlikely(!gso_skb))
		return false;

	ks = ovpn_encrypt_refs_get(peer);
	if (unlikely(!ks)) {
		kfree_skb(gso_skb);
		return false;
	}

	/* the output owns the references until its completion */
	memset(ovpn_skb_cb(gso_skb), 0, sizeof(struct ovpn_cb));
	ovpn_skb_cb(gso_skb)->peer = peer;
	ovpn_skb_cb(gso_skb)->ks = ks;
	ovpn_skb_cb(gso_skb)->tcp_packets = segments;

	/* Account the same inner bytes as software segmentation, including
	 * replicated IP/TCP headers. The link path counts ciphertext bytes.
	 */
	ovpn_peer_stats_add_tx(&peer->vpn_stats,
			       skb->len + (segments - 1) * hdr_len, segments);

	memset(ovpn_skb_cb(skb), 0, sizeof(struct ovpn_cb));
	ovpn_skb_cb(skb)->tcp_gso = gso_skb;
	ret = ovpn_aead_encrypt_tcp_gso(peer, ks, skb, gso_skb);
	ovpn_encrypt_tcp_gso_post(skb, ret);
	return true;
}

/* A TCP or UDP GSO input segmented without skbs: each segment is built in a
 * per-CPU page and encrypted from there into its UDP GSO aggregate. The pages
 * are allocated at load time, from the linear map as scatterlists require.
 */
struct ovpn_tx_seg {
	local_lock_t bh_lock;
	u8 *buf;
};

static struct ovpn_tx_seg __percpu *ovpn_tx_segs;

void ovpn_tx_segs_free(void)
{
	int cpu;

	if (!ovpn_tx_segs)
		return;

	for_each_possible_cpu(cpu)
		free_page((unsigned long)per_cpu_ptr(ovpn_tx_segs, cpu)->buf);

	free_percpu(ovpn_tx_segs);
	ovpn_tx_segs = NULL;
}

int ovpn_tx_segs_alloc(void)
{
	struct ovpn_tx_seg *seg;
	struct page *page;
	int cpu;

	ovpn_tx_segs = alloc_percpu(struct ovpn_tx_seg);
	if (!ovpn_tx_segs)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		seg = per_cpu_ptr(ovpn_tx_segs, cpu);
		local_lock_init(&seg->bh_lock);

		page = alloc_pages_node(cpu_to_node(cpu), GFP_KERNEL, 0);
		if (!page) {
			ovpn_tx_segs_free();
			return -ENOMEM;
		}
		seg->buf = page_address(page);
	}

	return 0;
}

/* the state of a TCP or UDP GSO input segmented with the TSO helpers, plus
 * what tcp_gso_segment() and __udp_gso_segment() also do and they don't:
 * checksums, fixed IPv4 IDs and CWR on the first TCP segment only
 */
struct ovpn_seg_hdr {
	struct tso_t tso;
	unsigned int hdr_len;	/* network and transport headers */
	unsigned int thoff;	/* transport header offset */
	unsigned int mss;
	unsigned int payload;	/* payload not segmented yet */
	unsigned int oldlen;	/* ~(length of the whole transport packet) */
	__be16 id;
	__sum16 check;		/* the input's pseudo-header checksum */
	bool v4;
	bool udp;
	bool fixedid;
	bool cwr;		/* whether later TCP segments keep CWR */
};

/* Whether ovpn_send_segfree() can build the segments of @skb. Anything
 * unusual is left to skb_gso_segment().
 */
static bool ovpn_segfree_eligible(struct sk_buff *skb, struct ovpn_seg_hdr *h)
{
	const struct skb_shared_info *shinfo = skb_shinfo(skb);
	unsigned int nhlen, thlen, tcp_types, ok;

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		nhlen = sizeof(struct iphdr);
		tcp_types = SKB_GSO_TCPV4 | SKB_GSO_TCP_FIXEDID;
		break;
	case htons(ETH_P_IPV6):
		nhlen = sizeof(struct ipv6hdr);
		tcp_types = SKB_GSO_TCPV6;
		break;
	default:
		return false;
	}

	/* DODGY geometry is validated below, as the GSO handlers do */
	h->udp = !!(shinfo->gso_type & SKB_GSO_UDP_L4);
	if (h->udp)
		ok = SKB_GSO_UDP_L4 | SKB_GSO_DODGY;
	else if (shinfo->gso_type & tcp_types & ~SKB_GSO_TCP_FIXEDID)
		ok = tcp_types | SKB_GSO_TCP_ECN | SKB_GSO_TCP_ACCECN |
		     SKB_GSO_DODGY;
	else
		return false;

	/* the TSO helpers walk the linear part and the frags only, through
	 * skb_frag_address()
	 */
	if (IS_ENABLED(CONFIG_HIGHMEM) ||
	    (shinfo->gso_type & ~ok) || skb->encapsulation ||
	    skb_has_frag_list(skb) || skb->ip_summed != CHECKSUM_PARTIAL ||
	    skb_network_offset(skb) || (shinfo->tx_flags & SKBTX_ANY_TSTAMP) ||
	    skb_checksum_start(skb) != skb_transport_header(skb))
		return false;

	h->v4 = skb->protocol == htons(ETH_P_IP);
	h->thoff = skb_transport_offset(skb);
	thlen = h->udp ? sizeof(struct udphdr) : sizeof(struct tcphdr);
	/* tso_build_hdr() doesn't account for IPv6 extension headers */
	if (h->thoff < nhlen || (!h->v4 && h->thoff != nhlen) ||
	    skb_headlen(skb) < h->thoff + thlen)
		return false;

	if (!h->udp) {
		if (tcp_hdr(skb)->doff < 5)
			return false;
		thlen = tcp_hdrlen(skb);
	}

	h->hdr_len = h->thoff + thlen;
	h->mss = shinfo->gso_size;
	if (skb_headlen(skb) < h->hdr_len || !h->mss ||
	    h->hdr_len + h->mss > PAGE_SIZE ||
	    skb->len <= h->hdr_len + h->mss)
		return false;

	tso_start(skb, &h->tso);
	h->payload = skb->len - h->hdr_len;
	/* the length the input's pseudo-header checksum covers, as the GSO
	 * handlers take it
	 */
	h->oldlen = ~(h->udp ? ntohs(udp_hdr(skb)->len) : skb->len - h->thoff);
	h->check = h->udp ? udp_hdr(skb)->check : tcp_hdr(skb)->check;
	h->id = h->v4 ? ip_hdr(skb)->id : 0;
	h->fixedid = !!(shinfo->gso_type & SKB_GSO_TCP_FIXEDID);
	h->cwr = !!(shinfo->gso_type & SKB_GSO_TCP_ACCECN);

	return true;
}

/* Write the next segment of @skb to @buf: headers, then the payload copied
 * with its checksum. Returns the segment length.
 */
static unsigned int ovpn_segfree_build(const struct sk_buff *skb,
				       struct ovpn_seg_hdr *h, bool first,
				       u8 *buf)
{
	unsigned int plen = min(h->mss, h->payload);
	unsigned int thlen = h->hdr_len - h->thoff;
	u8 *dst = buf + h->hdr_len;
	void *thdr = buf + h->thoff;
	unsigned int off, n;
	__wsum csum = 0;
	__sum16 *check;

	h->payload -= plen;
	tso_build_hdr(skb, buf, &h->tso, plen, !h->payload);
	for (off = 0; off < plen; off += n) {
		n = min_t(unsigned int, plen - off, h->tso.size);
		csum = csum_block_add(csum,
				      csum_partial_copy_nocheck(h->tso.data,
								dst + off, n),
				      off);
		tso_build_data(skb, &h->tso, n);
	}

	if (h->udp) {
		check = &((struct udphdr *)thdr)->check;
	} else {
		struct tcphdr *th = thdr;

		/* tso_build_hdr() clears RST but for the last segment */
		th->rst = tcp_hdr(skb)->rst;
		if (!first)
			th->cwr &= h->cwr;
		check = &th->check;
	}

	/* the pseudo-header checksum for this length, then the full one */
	*check = ~csum_fold(csum_add(csum_unfold(h->check),
				     (__force __wsum)htonl(h->oldlen + thlen +
							   plen)));
	*check = csum_fold(csum_partial(thdr, thlen, csum));
	if (h->udp && !*check)
		*check = CSUM_MANGLED_0;

	if (h->v4) {
		struct iphdr *iph = (struct iphdr *)buf;

		if (h->fixedid)
			iph->id = h->id;
		ip_send_check(iph);
	}

	return h->hdr_len + plen;
}

/* Build the next @n segments of @skb in the per-CPU buffer and encrypt each
 * into @batch, with packet IDs from @pktid on. @first: whether the first one
 * is the input's first segment.
 */
static int ovpn_segfree_encrypt(struct ovpn_aead_gso_ctx *ctx,
				struct ovpn_peer *peer,
				struct ovpn_crypto_key_slot *ks,
				const struct sk_buff *skb,
				struct ovpn_seg_hdr *h, struct sk_buff *batch,
				unsigned int n, u32 pktid, bool first)
{
	unsigned int j, len, offset = 0;
	int ret = 0;
	u8 *buf;

	/* the buffer is released before sending, which may recurse into
	 * another ovpn device
	 */
	local_lock_nested_bh(&ovpn_tx_segs->bh_lock);
	buf = this_cpu_ptr(ovpn_tx_segs)->buf;
	for (j = 0; j < n && !ret; j++) {
		len = ovpn_segfree_build(skb, h, first && !j, buf);
		ret = ovpn_aead_encrypt_gso_buf(ctx, peer, ks, buf, len, batch,
						offset, pktid + j);
		offset += len + OVPN_DATA_V2_OVERHEAD;
	}
	local_unlock_nested_bh(&ovpn_tx_segs->bh_lock);

	DEBUG_NET_WARN_ON_ONCE(ret == -EINPROGRESS || ret == -EBUSY);
	return ret;
}

/* Build, encrypt and send the next @n segments of @skb as one aggregate.
 * @first, @last: whether they include the input's first, last segment.
 * On failure nothing is sent.
 */
static int ovpn_segfree_batch(struct ovpn_peer *peer, struct sk_buff *skb,
			      struct ovpn_seg_hdr *h, unsigned int n,
			      bool first, bool last)
{
	struct ovpn_aead_gso_ctx ctx = { };
	struct ovpn_crypto_key_slot *ks;
	unsigned int batch_len;
	struct sk_buff *batch;
	u32 pktid;
	int ret;

	/* h->payload is what is left: only the last segment is short */
	batch_len = n * (h->hdr_len + OVPN_DATA_V2_OVERHEAD) +
		    min(n * h->mss, h->payload);
	batch = ovpn_udp_gso_alloc(skb, h->hdr_len + h->mss, batch_len, n);
	if (unlikely(!batch))
		return -ENOMEM;

	ks = ovpn_encrypt_refs_get(peer);
	if (unlikely(!ks)) {
		kfree_skb(batch);
		return -ENOKEY;
	}

	/* recheck in case the key was swapped */
	ret = ks->async ? -EOPNOTSUPP : ovpn_aead_gso_ctx_init(&ctx, ks, batch);
	if (likely(!ret)) {
		ret = ovpn_pktid_xmit_range(&ks->pid_xmit, n, &pktid);
		if (unlikely(ret))
			ovpn_encrypt_key_exhausted(peer, ks);
	}
	if (likely(!ret))
		ret = ovpn_segfree_encrypt(&ctx, peer, ks, skb, h, batch, n,
					   pktid, first);
	ovpn_aead_gso_ctx_free(&ctx);
	if (unlikely(ret)) {
		kfree_skb(batch);
		ovpn_crypto_key_slot_put(ks);
		ovpn_peer_put(peer);
		return ret;
	}

	/* the last aggregate takes over the input's write charge, as in
	 * ovpn_encrypt_gso_queue(), so that freeing the input doesn't wake TSQ
	 * before the data has left the host
	 */
	if (last && batch->sk) {
		skb->destructor = NULL;
		skb->sk = NULL;
		WARN_ON_ONCE(refcount_sub_and_test(skb->truesize,
						   &batch->sk->sk_wmem_alloc));
	}

	ovpn_encrypt_send(peer, ks, batch, n);
	return 0;
}

/* Segment a TCP or UDP GSO input like skb_gso_segment() without NETIF_F_SG
 * would, but without allocating a skb per segment: build each segment in a
 * per-CPU buffer and encrypt it from there into its UDP GSO aggregate. Only
 * for synchronous AEADs, so that one buffer serves all the segments.
 * Returning false leaves the input to the ordinary path, also on failures
 * before the first aggregate is sent. As the TSO state can't skip segments,
 * a later failure drops the rest of the input.
 */
static bool ovpn_send_segfree(struct ovpn_peer *peer, struct sk_buff *skb)
{
	unsigned int segs, max_segs, seg_len, done, n;
	struct ovpn_seg_hdr h;

	if (!ovpn_segfree_eligible(skb, &h) || !ovpn_peer_supports_udp_gso(peer))
		return false;

	segs = DIV_ROUND_UP(h.payload, h.mss);
	seg_len = h.hdr_len + h.mss;
	max_segs = min_t(unsigned int, UDP_MAX_SEGMENTS,
			 OVPN_UDP_GSO_MAX_PAYLOAD /
			 (seg_len + OVPN_DATA_V2_OVERHEAD));
	if (max_segs < 2)
		return false;

	for (done = 0; done < segs; done += n) {
		n = min(segs - done, max_segs);
		if (unlikely(ovpn_segfree_batch(peer, skb, &h, n, !done,
						done + n == segs))) {
			if (!done)
				return false;
			goto drop;
		}
	}

	ovpn_peer_stats_add_tx(&peer->vpn_stats,
			       skb->len + (segs - 1) * h.hdr_len, segs);
	consume_skb(skb);
	return true;

drop:
	ovpn_peer_stats_add_tx(&peer->vpn_stats, done * seg_len, done);
	ovpn_dev_dstats_tx_dropped(peer->ovpn->dev, segs - done);
	skb_tx_error(skb);
	kfree_skb(skb);
	return true;
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

	/* Make skb metadata private before modifying it or acquiring TX refs.
	 * Packet data can remain shared for out-of-place encryption.
	 */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb)) {
		ovpn_dev_dstats_tx_dropped(dev, 1);
		return NETDEV_TX_OK;
	}

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

	/* if this is an eligible GSO skb and we're using TCP as transport
	 * protocol, try to send it without prior segmentation
	 */
	if (gso_in && ovpn_send_tcp_gso(peer, skb)) {
		ovpn_peer_put(peer);
		return NETDEV_TX_OK;
	}

	if (gso_out && ovpn_send_segfree(peer, skb)) {
		ovpn_peer_put(peer);
		return NETDEV_TX_OK;
	}

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

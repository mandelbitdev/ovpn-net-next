// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2026 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 *		Ralf Lici <ralf@mandelbit.com>
 */

#include <linux/highmem.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/ip6_checksum.h>
#include <net/sock.h>
#include <net/tso.h>
#include <net/udp.h>

#include "ovpnpriv.h"
#include "peer.h"
#include "io.h"
#include "gso.h"
#include "crypto.h"
#include "crypto_aead.h"
#include "pktid.h"
#include "proto.h"
#include "skb.h"
#include "socket.h"
#include "stats.h"

/* gso_within_dev_limits() requires skb->len, which by then includes the
 * link-layer and outer network headers, to stay below gso_max_size
 */
#define OVPN_GSO_MAX_PAYLOAD		(GSO_LEGACY_MAX_SIZE -		\
					 LL_MAX_HEADER -		\
					 sizeof(struct ipv6hdr) -	\
					 sizeof(struct udphdr) - 1)

static void ovpn_gso_build_hdr(struct sk_buff *skb, struct tso_t *tso,
			       void *header, unsigned int payload_len,
			       __wsum payload_csum, bool is_last,
			       bool partial_csum)
{
	u8 *transport_header = (u8 *)header + skb_transport_offset(skb);
	unsigned int l4_len = tso->tlen + payload_len;
	__wsum csum = 0;
	__sum16 *check;
	u8 proto;

	/* copy the parent's headers and set this record's IP length and ID,
	 * TCP sequence number and flags or UDP length
	 */
	tso_build_hdr(skb, header, tso, payload_len, is_last);

	/* the L4 checksum covers the transport header and the payload, whose
	 * sum the caller computed while copying it
	 */
	if (skb_is_gso_tcp(skb)) {
		check = &((struct tcphdr *)transport_header)->check;
		proto = IPPROTO_TCP;
	} else {
		check = &((struct udphdr *)transport_header)->check;
		proto = IPPROTO_UDP;
	}

	if (!partial_csum) {
		*check = 0;
		csum = csum_partial(transport_header, tso->tlen, payload_csum);
	}

	if (tso->ipv6) {
		struct ipv6hdr *iph = header + skb_network_offset(skb);

		*check = csum_ipv6_magic(&iph->saddr, &iph->daddr, l4_len,
					 proto, csum);
	} else {
		struct iphdr *iph = header + skb_network_offset(skb);

		*check = csum_tcpudp_magic(iph->saddr, iph->daddr, l4_len,
					   proto, csum);
		/* IPv4 also checksums its own header */
		ip_send_check(iph);
	}

	/* partial-csum peers expect the pseudo-header sum itself, while a zero
	 * UDP checksum would mean none
	 */
	if (partial_csum)
		*check = ~*check;
	else if (proto == IPPROTO_UDP && !*check)
		*check = CSUM_MANGLED_0;
}

/* position in the linear area and page frags of an input skb */
struct ovpn_gso_cursor {
	const struct sk_buff *skb;
	unsigned int head_off;
	unsigned int frag_idx;
	unsigned int frag_off;
};

struct ovpn_gso_source {
	unsigned int segments;
	unsigned int next;
	unsigned int record_len;
	unsigned int last_record_len;
	struct sk_buff_head *skbs;
	/* set if the records are ranges of a parent skb instead */
	struct sk_buff *parent;
	struct tso_t tso;
	struct ovpn_gso_cursor cursor;
	unsigned int hdr_len;
	bool partial_csum;
};

static bool ovpn_gso_copy_chunk(struct ovpn_gso_cursor *cur, u8 *to,
				unsigned int len, unsigned int *pos,
				__wsum *csum)
{
	unsigned int head_len = skb_headlen(cur->skb);
	const struct sk_buff *skb = cur->skb;
	__wsum part;

	/* Copy len bytes of the skb from the cursor position, first from the
	 * linear area if the cursor has not left it yet. When requested, also
	 * sum the copied bytes; csum_block_add rotates that partial sum when
	 * it starts at an odd byte position of the copied range.
	 */
	if (cur->head_off < head_len) {
		unsigned int size = min(len, head_len - cur->head_off);
		const u8 *from = skb->data + cur->head_off;

		if (csum) {
			part = csum_partial_copy_nocheck(from, to, size);
			*csum = csum_block_add(*csum, part, *pos);
		} else {
			memcpy(to, from, size);
		}
		cur->head_off += size;
		*pos += size;
		to += size;
		len -= size;
	}

	/* then continue through the page frags */
	while (len && cur->frag_idx < skb_shinfo(skb)->nr_frags) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[cur->frag_idx];
		u32 p_off, p_len, copied;
		unsigned int size;
		struct page *p;
		u8 *vaddr;

		/* map each page separately for highmem; elsewhere the whole
		 * range of the frag is one piece
		 */
		size = min(len, skb_frag_size(frag) - cur->frag_off);
		skb_frag_foreach_page(frag, skb_frag_off(frag) + cur->frag_off,
				      size, p, p_off, p_len, copied) {
			vaddr = kmap_local_page(p);
			if (csum) {
				part = csum_partial_copy_nocheck(vaddr + p_off,
								 to + copied,
								 p_len);
				*csum = csum_block_add(*csum, part,
						       *pos + copied);
			} else {
				memcpy(to + copied, vaddr + p_off, p_len);
			}
			kunmap_local(vaddr);
		}

		/* move on to the next frag once this one is used up */
		cur->frag_off += size;
		*pos += size;
		to += size;
		len -= size;
		if (cur->frag_off == skb_frag_size(frag)) {
			cur->frag_idx++;
			cur->frag_off = 0;
		}
	}

	/* the skb ended before len bytes */
	return !len;
}

static bool ovpn_gso_copy(struct ovpn_gso_cursor *cur, struct sk_buff *batch,
			  unsigned int offset, unsigned int len, __wsum *csum)
{
	unsigned int pos = 0, i;

	/* Copy len bytes of the skb at the cursor into the aggregate at offset
	 * and, when csum is not NULL, return their checksum. The aggregate's
	 * frags come from ovpn_gso_alloc without __GFP_HIGHMEM, so each is
	 * directly mapped: skip those before offset, then copy into each one
	 * in turn, carrying the byte position for the checksum.
	 */
	if (csum)
		*csum = 0;
	for (i = 0; len && i < skb_shinfo(batch)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(batch)->frags[i];
		unsigned int size = skb_frag_size(frag), n;

		if (offset >= size) {
			offset -= size;
			continue;
		}

		n = min(len, size - offset);
		if (!ovpn_gso_copy_chunk(cur, skb_frag_address(frag) + offset,
					 n, &pos, csum))
			return false;
		len -= n;
		offset = 0;
	}

	return !len;
}

static int ovpn_gso_encrypt_segment(struct ovpn_aead_gso_ctx *ctx,
				    struct ovpn_peer *peer,
				    struct ovpn_crypto_key_slot *ks,
				    struct sk_buff *skb, struct sk_buff *batch,
				    unsigned int offset, u32 pktid,
				    bool partial_csum)
{
	unsigned int data = offset + OVPN_DATA_V2_OVERHEAD;
	struct ovpn_gso_cursor cur = { .skb = skb };
	unsigned int start = 0;
	__wsum csum = 0, *sum;
	__sum16 check;
	int ret;

	/* Copy the segment behind the OpenVPN header and the tag. Its L4
	 * checksum is left partial for batching, so copy the headers in front
	 * of it, then the rest summing it on the way, and complete it in the
	 * aggregate as skb_checksum_help would in the segment.
	 */
	if (!partial_csum && skb->ip_summed == CHECKSUM_PARTIAL)
		start = skb_checksum_start_offset(skb);
	sum = partial_csum ? NULL : &csum;
	if (unlikely(!ovpn_gso_copy(&cur, batch, data, start, sum) ||
		     !ovpn_gso_copy(&cur, batch, data + start, skb->len - start,
				    sum)))
		return -EMSGSIZE;
	if (!partial_csum && skb->ip_summed == CHECKSUM_PARTIAL) {
		check = csum_fold(csum) ?: CSUM_MANGLED_0;
		ret = skb_store_bits(batch, data + start + skb->csum_offset,
				     &check, sizeof(check));
		if (unlikely(ret < 0))
			return ret;
	}

	/* store the OpenVPN header in front; encryption fills in the tag */
	ovpn_aead_encrypt_header(peer, ks, pktid, ctx->iv, ctx->head);
	ret = skb_store_bits(batch, offset, ctx->head, OVPN_AAD_SIZE);
	if (unlikely(ret < 0))
		return ret;

	return ovpn_aead_encrypt_gso(ctx, batch, offset, skb->len);
}

static int ovpn_gso_encrypt_record(struct ovpn_gso_source *src,
				   struct ovpn_aead_gso_ctx *ctx,
				   struct ovpn_peer *peer,
				   struct ovpn_crypto_key_slot *ks,
				   struct sk_buff *batch, unsigned int offset,
				   u32 pktid, unsigned int *len)
{
	unsigned int data = offset + OVPN_DATA_V2_OVERHEAD;
	unsigned int hdr_len = src->hdr_len;
	unsigned int index = src->next++;
	unsigned int payload_len;
	u8 *record = ctx->head;
	__wsum csum;
	bool last;
	int ret;

	/* copy the record's payload into its final position in the aggregate,
	 * behind the OpenVPN header, the tag and the inner headers, and sum it
	 * on the way
	 */
	last = index + 1 == src->segments;
	payload_len = (last ? src->last_record_len : src->record_len) - hdr_len;
	if (unlikely(!ovpn_gso_copy(&src->cursor, batch, data + hdr_len,
				    payload_len,
				    src->partial_csum ? NULL : &csum)))
		return -EMSGSIZE;

	/* stage the start of the record as it is laid out in the aggregate:
	 * the OpenVPN header, room for the tag and the synthesized inner
	 * headers, whose checksums cover the payload copied above
	 */
	ovpn_gso_build_hdr(src->parent, &src->tso,
			   record + OVPN_DATA_V2_OVERHEAD, payload_len, csum,
			   last, src->partial_csum);
	tso_advance_hdr(&src->tso, payload_len);
	ovpn_aead_encrypt_header(peer, ks, pktid, ctx->iv, record);

	/* store it in front of the payload; encryption overwrites the tag */
	ret = skb_store_bits(batch, offset, record,
			     OVPN_DATA_V2_OVERHEAD + hdr_len);
	if (unlikely(ret < 0))
		return ret;

	*len = hdr_len + payload_len + OVPN_DATA_V2_OVERHEAD;
	return ovpn_aead_encrypt_gso(ctx, batch, offset, hdr_len + payload_len);
}

static bool ovpn_gso_encrypt_batch(struct ovpn_gso_source *src,
				   struct ovpn_peer *peer,
				   struct ovpn_crypto_key_slot *ks,
				   struct sk_buff *batch, unsigned int segments)
{
	unsigned int offset = 0, moved = 0, i, len, batch_start = src->next;
	struct ovpn_aead_gso_ctx ctx = { };
	struct sk_buff *skb;
	u32 first_pktid;
	int ret;

	if (unlikely(ovpn_aead_gso_ctx_init(&ctx, ks, batch, src->hdr_len)))
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
		if (src->parent) {
			skb = NULL;
			ret = ovpn_gso_encrypt_record(src, &ctx, peer, ks,
						      batch, offset,
						      first_pktid + i, &len);
		} else {
			skb = __skb_dequeue(src->skbs);
			src->next++;
			len = skb->len + OVPN_DATA_V2_OVERHEAD;
			ret = ovpn_gso_encrypt_segment(&ctx, peer, ks, skb,
						       batch, offset,
						       first_pktid + i,
						       src->partial_csum);
		}
		if (unlikely(ret < 0)) {
			DEBUG_NET_WARN_ON_ONCE(ret == -EINPROGRESS ||
					       ret == -EBUSY);
			/* report the whole batch as not handled */
			if (src->parent) {
				src->next = batch_start;
				break;
			}
			ovpn_dev_dstats_tx_dropped(peer->ovpn->dev, i + 1);
			kfree_skb(skb);
			break;
		}

		offset += len;
		/* the caller releases the parent skb of TSO records */
		if (src->parent)
			continue;

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
	}

	/* once the last aggregate is built, the input's data lives in
	 * aggregates which carry their own write charge, so release the
	 * input's charge without waking TSQ before they are transmitted
	 */
	if (src->parent && batch->sk && i == segments &&
	    src->next == src->segments) {
		moved += src->parent->truesize;
		src->parent->destructor = NULL;
		src->parent->sk = NULL;
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

static struct sk_buff *ovpn_gso_alloc(const struct sk_buff *first_segment,
				      unsigned int batch_len,
				      unsigned int record_len,
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
	skb_shinfo(gso_skb)->gso_size = record_len + OVPN_DATA_V2_OVERHEAD;
	skb_shinfo(gso_skb)->gso_segs = segments;

	return gso_skb;
}

static unsigned int ovpn_gso_send_batch(struct ovpn_gso_source *src,
					struct ovpn_peer *peer)
{
	unsigned int max_segs, batch_len, batch_segs, batch_start, remaining;
	struct ovpn_crypto_key_slot *ks;
	struct sk_buff *batch;

	max_segs = min_t(unsigned int, UDP_MAX_SEGMENTS,
			 OVPN_GSO_MAX_PAYLOAD /
				 (src->record_len + OVPN_DATA_V2_OVERHEAD));

	/* if even two encrypted records cannot fit, leave the source for the
	 * ordinary transmit path
	 */
	if (max_segs < 2)
		return 0;

	/* A parent skb cannot leave one record for the ordinary path. If a
	 * batch holds at most two records, an odd record count cannot be split
	 * entirely into valid UDP GSO aggregates, so fall back.
	 */
	if (src->parent && max_segs == 2 && (src->segments & 1))
		return 0;

	/* An input GSO skb might produce more than max_segs records, so
	 * consume as many as can fit in each aggregate. A final materialized
	 * one, or the remainder after a failure, stays for the ordinary path.
	 */
	while (src->segments - src->next > 1) {
		batch_start = src->next;
		remaining = src->segments - src->next;
		batch_segs = min(remaining, max_segs);
		/* a parent skb cannot leave one record behind */
		if (src->parent && remaining - batch_segs == 1)
			batch_segs--;

		/* acquire shared state before allocating/consuming anything */
		ks = ovpn_encrypt_refs_get(peer);
		if (unlikely(!ks))
			break;
		/* recheck in case the key was swapped */
		if (unlikely(ks->async)) {
			ovpn_crypto_key_slot_put(ks);
			ovpn_peer_put(peer);
			break;
		}

		/* all but the final input record have the same length, so
		 * start with the full-size calculation and adjust only the
		 * final group below
		 */
		batch_len = batch_segs *
			    (src->record_len + OVPN_DATA_V2_OVERHEAD);
		if (batch_start + batch_segs == src->segments)
			batch_len -= src->record_len - src->last_record_len;

		batch = ovpn_gso_alloc(src->parent ?: skb_peek(src->skbs),
				       batch_len, src->record_len, batch_segs);
		if (unlikely(!batch)) {
			ovpn_crypto_key_slot_put(ks);
			ovpn_peer_put(peer);
			break;
		}
		if (src->parent && batch_start)
			batch->ooo_okay = 0;

		if (unlikely(!ovpn_gso_encrypt_batch(src, peer, ks, batch,
						     batch_segs))) {
			kfree_skb(batch);
			break;
		}
	}

	return src->next;
}

/**
 * ovpn_gso_send - encrypt materialized segments into UDP GSO aggregates
 * @skbs: segments of one GSO skb, all but the last of the same length
 * @peer: peer to send them to
 * @partial_csum: leave partial inner L4 checksums for the receiver
 *
 * Consumes as many segments as fit into valid aggregates, each sent with its
 * own references to @peer and its key. Segments left in @skbs, if any, are
 * for the ordinary transmit path. Only for peers which pass
 * ovpn_gso_supported.
 */
void ovpn_gso_send(struct sk_buff_head *skbs, struct ovpn_peer *peer,
		   bool partial_csum)
{
	struct ovpn_gso_source src = {
		.segments = skb_queue_len(skbs),
		.record_len = skb_peek(skbs)->len,
		.last_record_len = skb_peek_tail(skbs)->len,
		.partial_csum = partial_csum,
		.skbs = skbs,
	};

	ovpn_gso_send_batch(&src, peer);
}

/**
 * ovpn_gso_send_tso - encrypt a TCP or UDP GSO skb without segmenting it
 * @skb: GSO skb to send
 * @peer: peer to send it to
 * @partial_csum: leave partial inner L4 checksums for the receiver
 *
 * Builds each record from a range of @skb instead of materializing its
 * segments. Only for peers which pass ovpn_gso_supported.
 *
 * Return: true if @skb was consumed along with the caller's reference to
 * @peer, false if it was left for the ordinary segmenter
 */
bool ovpn_gso_send_tso(struct sk_buff *skb, struct ovpn_peer *peer,
		       bool partial_csum)
{
	const netdev_features_t features = NETIF_F_TSO | NETIF_F_TSO6 |
					   NETIF_F_TSO_MANGLEID |
					   NETIF_F_GSO_ACCECN |
					   NETIF_F_GSO_UDP_L4;
	u8 proto = skb_is_gso_tcp(skb) ? IPPROTO_TCP : IPPROTO_UDP;
	unsigned int hdr_len, payload_len, total_segs, handled;
	unsigned int gso_size, last_payload_len, tx_bytes;
	struct ovpn_gso_source src = {
		.parent = skb,
		.partial_csum = partial_csum,
		.cursor.skb = skb,
	};

	if (!skb_gso_ok(skb, features))
		return false;

	/* the aggregates take over the parent's write charge, which requires
	 * owning it alone
	 */
	if (unlikely(skb_shared(skb)))
		return false;

	/* let the protocol segmenter place a TX timestamp request on the
	 * appropriate child before batching those materialized segments
	 */
	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_ANY_TSTAMP))
		return false;

	/* tso_build_hdr does not account for IPv6 extension headers. On a
	 * forwarded skb the transport header still points right behind the
	 * IPv6 header even when extension headers follow it, so check the next
	 * header too.
	 */
	if (skb->protocol == htons(ETH_P_IPV6) &&
	    unlikely(ipv6_hdr(skb)->nexthdr != proto ||
		     skb_network_header_len(skb) != sizeof(struct ipv6hdr)))
		return false;

	/* tso_start reads the TCP header from the linear area */
	if (proto == IPPROTO_TCP &&
	    unlikely(skb_headlen(skb) <
		     skb_transport_offset(skb) + sizeof(struct tcphdr)))
		return false;

	/* tso_build_hdr copies the headers from the linear area */
	hdr_len = tso_start(skb, &src.tso);
	if (unlikely(skb_headlen(skb) < hdr_len))
		return false;

	gso_size = skb_shinfo(skb)->gso_size;
	payload_len = skb->len - hdr_len;
	total_segs = DIV_ROUND_UP(payload_len, gso_size);
	if (unlikely(total_segs < 2))
		return false;

	last_payload_len = payload_len - (total_segs - 1) * gso_size;
	src.segments = total_segs;
	src.record_len = hdr_len + gso_size;
	src.last_record_len = hdr_len + last_payload_len;
	src.cursor.head_off = hdr_len;
	src.hdr_len = hdr_len;

	handled = ovpn_gso_send_batch(&src, peer);
	/* if nothing was sent we can safely fall back to segmentation */
	if (!handled)
		return false;

	tx_bytes = handled * src.record_len;
	if (handled == total_segs)
		tx_bytes -= src.record_len - src.last_record_len;
	ovpn_peer_stats_add_tx(&peer->vpn_stats, tx_bytes, handled);
	if (unlikely(handled < total_segs)) {
		/* the remaining records cannot fall back to the segmenter
		 * without resending those already transmitted
		 */
		ovpn_dev_dstats_tx_dropped(peer->ovpn->dev,
					   total_segs - handled);
		kfree_skb(skb);
	} else {
		consume_skb(skb);
	}
	ovpn_peer_put(peer);
	return true;
}

/**
 * ovpn_gso_supported - check whether a peer can send UDP GSO aggregates
 * @peer: peer to check
 *
 * Return: true if the primary key of @peer is synchronous and its socket is a
 * UDP socket which sends checksums
 */
bool ovpn_gso_supported(struct ovpn_peer *peer)
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

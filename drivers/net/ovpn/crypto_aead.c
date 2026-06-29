// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2025 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include <crypto/aead.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/udp.h>

#include "ovpnpriv.h"
#include "main.h"
#include "io.h"
#include "pktid.h"
#include "crypto_aead.h"
#include "crypto.h"
#include "netlink.h"
#include "peer.h"
#include "proto.h"
#include "skb.h"

#define OVPN_AEAD_DECRYPT_FAILURE_NOTIFY	BIT_ULL(35)
#define OVPN_AEAD_DECRYPT_FAILURE_LIMIT		BIT_ULL(36)
#define OVPN_AEAD_DECRYPT_FAILURE_NOTIFY_BIT	0

static bool
ovpn_aead_decrypt_failure_exceeded(const struct ovpn_key_ctx *key)
{
	return atomic64_read(&key->decrypt_failures) >
	       OVPN_AEAD_DECRYPT_FAILURE_LIMIT;
}

bool ovpn_aead_decrypt_failure_record(struct ovpn_key_ctx *key)
{
	u64 failures = atomic64_inc_return(&key->decrypt_failures);

	return failures > OVPN_AEAD_DECRYPT_FAILURE_NOTIFY &&
	       !test_and_set_bit(OVPN_AEAD_DECRYPT_FAILURE_NOTIFY_BIT,
				 &key->decrypt_failure_flags);
}

static int ovpn_aead_encap_overhead(const struct ovpn_key_ctx *key)
{
	return OVPN_AEAD_DIRECT_AAD_SIZE + crypto_aead_authsize(key->tfm);
}

/**
 * ovpn_aead_crypto_tmp_size - compute the size of a temporary object containing
 *			       an AEAD request structure with extra space for SG
 *			       and IV.
 * @tfm: the AEAD cipher handle
 * @nfrags: the number of fragments in the skb
 *
 * This function calculates the size of a contiguous memory block that includes
 * the initialization vector (IV), the AEAD request, and an array of scatterlist
 * entries. For alignment considerations, the IV is placed first, followed by
 * the request, and then the scatterlist.
 * Additional alignment is applied according to the requirements of the
 * underlying structures.
 *
 * Return: the size of the temporary memory that needs to be allocated
 */
static unsigned int ovpn_aead_crypto_tmp_size(struct crypto_aead *tfm,
					      const unsigned int nfrags)
{
	unsigned int len = OVPN_NONCE_SIZE;

	DEBUG_NET_WARN_ON_ONCE(crypto_aead_ivsize(tfm) != OVPN_NONCE_SIZE);

	/* min size for a buffer of ivsize, aligned to alignmask */
	len += crypto_aead_alignmask(tfm) & ~(crypto_tfm_ctx_alignment() - 1);
	/* round up to the next multiple of the crypto ctx alignment */
	len = ALIGN(len, crypto_tfm_ctx_alignment());

	/* reserve space for the AEAD request */
	len += sizeof(struct aead_request) + crypto_aead_reqsize(tfm);
	/* round up to the next multiple of the scatterlist alignment */
	len = ALIGN(len, __alignof__(struct scatterlist));

	/* add enough space for nfrags + 2 scatterlist entries */
	len += array_size(sizeof(struct scatterlist), nfrags + 2);
	return len;
}

/**
 * ovpn_aead_crypto_tmp_iv - retrieve the pointer to the IV within a temporary
 *			     buffer allocated using ovpn_aead_crypto_tmp_size
 * @aead: the AEAD cipher handle
 * @tmp: a pointer to the beginning of the temporary buffer
 *
 * This function retrieves a pointer to the initialization vector (IV) in the
 * temporary buffer. If the AEAD cipher specifies an IV size, the pointer is
 * adjusted using the AEAD's alignment mask to ensure proper alignment.
 *
 * Returns: a pointer to the IV within the temporary buffer
 */
static u8 *ovpn_aead_crypto_tmp_iv(struct crypto_aead *aead, void *tmp)
{
	return likely(crypto_aead_ivsize(aead)) ?
		      PTR_ALIGN((u8 *)tmp, crypto_aead_alignmask(aead) + 1) :
		      tmp;
}

/**
 * ovpn_aead_crypto_tmp_req - retrieve the pointer to the AEAD request structure
 *			      within a temporary buffer allocated using
 *			      ovpn_aead_crypto_tmp_size
 * @aead: the AEAD cipher handle
 * @iv: a pointer to the initialization vector in the temporary buffer
 *
 * This function computes the location of the AEAD request structure that
 * immediately follows the IV in the temporary buffer and it ensures the request
 * is aligned to the crypto transform context alignment.
 *
 * Returns: a pointer to the AEAD request structure
 */
static struct aead_request *ovpn_aead_crypto_tmp_req(struct crypto_aead *aead,
						     const u8 *iv)
{
	return (void *)PTR_ALIGN(iv + crypto_aead_ivsize(aead),
				 crypto_tfm_ctx_alignment());
}

/**
 * ovpn_aead_crypto_req_sg - locate the scatterlist following the AEAD request
 *			     within a temporary buffer allocated using
 *			     ovpn_aead_crypto_tmp_size
 * @aead: the AEAD cipher handle
 * @req: a pointer to the AEAD request structure in the temporary buffer
 *
 * This function computes the starting address of the scatterlist that is
 * allocated immediately after the AEAD request structure. It aligns the pointer
 * based on the alignment requirements of the scatterlist structure.
 *
 * Returns: a pointer to the scatterlist
 */
static struct scatterlist *ovpn_aead_crypto_req_sg(struct crypto_aead *aead,
						   struct aead_request *req)
{
	return (void *)ALIGN((unsigned long)(req + 1) +
			     crypto_aead_reqsize(aead),
			     __alignof__(struct scatterlist));
}

int ovpn_aead_encrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *skb)
{
	unsigned int plaintext_len, tag_size;
	struct ovpn_key_ctx *key = NULL;
	struct aead_request *req;
	struct sk_buff *trailer;
	u64 aead_blocks, pktid;
	struct scatterlist *sg;
	bool pktid_notify;
	int nfrags, ret;
	void *tmp;
	u32 op;
	u8 *iv;

	ovpn_skb_cb(skb)->peer = peer;
	ovpn_skb_cb(skb)->ks = ks;
	plaintext_len = skb->len;

	ret = ovpn_key_ctx_get(&key, &ks->encrypt);
	if (unlikely(ret))
		return ret;
	ovpn_skb_cb(skb)->key = key;

	tag_size = crypto_aead_authsize(key->tfm);

	/* Sample AEAD header format:
	 * 48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
	 * [ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
	 *          [4-byte
	 *          IV head]
	 */

	/* check that there's enough headroom in the skb for packet
	 * encapsulation
	 */
	if (unlikely(skb_cow_head(skb, OVPN_HEAD_ROOM)))
		return -ENOBUFS;

	/* get number of skb frags and ensure that packet data is writable */
	nfrags = skb_cow_data(skb, 0, &trailer);
	if (unlikely(nfrags < 0))
		return nfrags;

	if (unlikely(nfrags + 2 > (MAX_SKB_FRAGS + 2)))
		return -ENOSPC;

	/* allocate temporary memory for iv, sg and req */
	tmp = kmalloc(ovpn_aead_crypto_tmp_size(key->tfm, nfrags),
		      GFP_ATOMIC);
	if (unlikely(!tmp))
		return -ENOMEM;

	ovpn_skb_cb(skb)->crypto_tmp = tmp;

	iv = ovpn_aead_crypto_tmp_iv(key->tfm, tmp);
	req = ovpn_aead_crypto_tmp_req(key->tfm, iv);
	sg = ovpn_aead_crypto_req_sg(key->tfm, req);

	/* sg table:
	 * 0: op, wire nonce (AD, len=OVPN_AEAD_DIRECT_AAD_SIZE),
	 * 1, 2, 3, ..., n: payload,
	 * n+1: auth_tag (len=tag_size)
	 */
	sg_init_table(sg, nfrags + 2);

	/* build scatterlist to encrypt packet payload */
	ret = skb_to_sgvec_nomark(skb, sg + 1, 0, skb->len);
	if (unlikely(ret < 0)) {
		netdev_err(peer->ovpn->dev,
			   "encrypt: cannot map skb to sg: %d\n", ret);
		return ret;
	}

	/* append auth_tag onto scatterlist */
	__skb_push(skb, tag_size);
	sg_set_buf(sg + ret + 1, skb->data, tag_size);

	/* obtain packet ID, which is used both as a first
	 * 4 bytes of nonce and last 4 bytes of associated data.
	 */
	ret = ovpn_pktid_xmit_next(&key->pid.xmit, &pktid);
	if (unlikely(ret < 0))
		return ret;
	pktid_notify = ret > 0;

	aead_blocks = ovpn_aead_limit_blocks(ks->cipher_alg, ks->aad_size,
					     plaintext_len);
	ret = ovpn_key_usage_xmit(&key->usage, &ks->usage_limit, pktid,
				  aead_blocks, pktid_notify);
	if (unlikely(ret < 0))
		return ret;
	if (unlikely(ret > 0))
		ovpn_nl_key_swap_notify(peer, ks->key_id);

	/* concat 4 bytes packet id and 8 bytes nonce tail into 12 bytes
	 * nonce
	 */
	pktid = ovpn_pktid_aead_write(0, pktid, key->implicit_iv, iv);

	/* make space for packet id and push it to the front */
	__skb_push(skb, ks->pktid_size);
	ovpn_pktid_wire_write(skb->data, false, pktid);

	/* add packet op as head of additional data */
	op = ovpn_opcode_compose(OVPN_DATA_V2, ks->key_id, peer->tx_id);
	__skb_push(skb, OVPN_OPCODE_SIZE);
	BUILD_BUG_ON(sizeof(op) != OVPN_OPCODE_SIZE);
	*((__force __be32 *)skb->data) = htonl(op);

	/* AEAD Additional data */
	sg_set_buf(sg, skb->data, ks->aad_size);

	/* setup async crypto operation */
	aead_request_set_tfm(req, key->tfm);
	aead_request_set_callback(req, 0, ovpn_encrypt_post, skb);
	aead_request_set_crypt(req, sg, sg,
			       skb->len - ovpn_aead_encap_overhead(key), iv);
	aead_request_set_ad(req, ks->aad_size);

	/* encrypt it */
	return crypto_aead_encrypt(req);
}

int ovpn_aead_decrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *skb)
{
	unsigned int payload_offset, tag_size;
	struct ovpn_key_ctx *key = NULL;
	int ret, payload_len, nfrags;
	struct aead_request *req;
	struct sk_buff *trailer;
	struct scatterlist *sg;
	void *tmp;
	u8 *iv;

	ovpn_skb_cb(skb)->peer = peer;
	ovpn_skb_cb(skb)->ks = ks;

	ret = ovpn_key_ctx_get(&key, &ks->decrypt);
	if (unlikely(ret))
		return ret;
	ovpn_skb_cb(skb)->key = key;

	tag_size = crypto_aead_authsize(key->tfm);
	payload_offset = ovpn_aead_direct_payload_offset(tag_size);
	payload_len = skb->len - payload_offset;

	ovpn_skb_cb(skb)->payload_offset = payload_offset;

	/* sanity check on packet size, payload size must be >= 0 */
	if (unlikely(payload_len < 0))
		return -EINVAL;

	if (unlikely(ovpn_aead_decrypt_failure_exceeded(key)))
		return -EKEYREJECTED;

	/* Prepare the skb data buffer to be accessed up until the auth tag.
	 * This is required because this area is directly mapped into the sg
	 * list.
	 */
	if (unlikely(!pskb_may_pull(skb, payload_offset)))
		return -ENODATA;

	/* get number of skb frags and ensure that packet data is writable */
	nfrags = skb_cow_data(skb, 0, &trailer);
	if (unlikely(nfrags < 0))
		return nfrags;

	if (unlikely(nfrags + 2 > (MAX_SKB_FRAGS + 2)))
		return -ENOSPC;

	/* allocate temporary memory for iv, sg and req */
	tmp = kmalloc(ovpn_aead_crypto_tmp_size(key->tfm, nfrags),
		      GFP_ATOMIC);
	if (unlikely(!tmp))
		return -ENOMEM;

	ovpn_skb_cb(skb)->crypto_tmp = tmp;

	iv = ovpn_aead_crypto_tmp_iv(key->tfm, tmp);
	req = ovpn_aead_crypto_tmp_req(key->tfm, iv);
	sg = ovpn_aead_crypto_req_sg(key->tfm, req);

	/* sg table:
	 * 0: op, wire nonce (AD, len=OVPN_AEAD_DIRECT_AAD_SIZE),
	 * 1, 2, 3, ..., n: payload,
	 * n+1: auth_tag (len=tag_size)
	 */
	sg_init_table(sg, nfrags + 2);

	/* packet op is head of additional data */
	sg_set_buf(sg, skb->data, ks->aad_size);

	/* build scatterlist to decrypt packet payload */
	ret = skb_to_sgvec_nomark(skb, sg + 1, payload_offset, payload_len);
	if (unlikely(ret < 0)) {
		netdev_err(peer->ovpn->dev,
			   "decrypt: cannot map skb to sg: %d\n", ret);
		return ret;
	}

	/* append auth_tag onto scatterlist */
	sg_set_buf(sg + ret + 1, skb->data + OVPN_AEAD_DIRECT_TAG_OFFSET,
		   tag_size);

	/* copy nonce into IV buffer */
	memcpy(iv, ovpn_aead_direct_wire_nonce(skb), OVPN_NONCE_WIRE_SIZE);
	memcpy(iv + OVPN_NONCE_WIRE_SIZE,
	       key->implicit_iv + OVPN_NONCE_WIRE_SIZE, OVPN_NONCE_TAIL_SIZE);

	/* setup async crypto operation */
	aead_request_set_tfm(req, key->tfm);
	aead_request_set_callback(req, 0, ovpn_decrypt_post, skb);
	aead_request_set_crypt(req, sg, sg, payload_len + tag_size, iv);

	aead_request_set_ad(req, ks->aad_size);

	/* decrypt it */
	return crypto_aead_decrypt(req);
}

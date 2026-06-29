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

/**
 * ovpn_aead_crypto_tmp_size - compute the size of a temporary object containing
 *			       an AEAD request structure with extra space for SG
 *			       and IV.
 * @tfm: the AEAD cipher handle
 * @sg_nents: the number of scatterlist entries
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
					      const unsigned int sg_nents)
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

	/* add enough space for the scatterlist entries */
	len += array_size(sizeof(struct scatterlist), sg_nents);
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

/**
 * ovpn_advance_encrypt_key - promote TX to a target epoch
 * @ks: key slot containing TX epoch state
 * @target_epoch: epoch to promote TX to
 * @required: whether the caller must stop if promotion cannot complete
 *
 * TX promotion consumes prederived future keys up to @target_epoch. If another
 * context is already updating TX state or refill has not caught up, optional
 * promotions keep using the current key while required promotions fail in the
 * caller.
 *
 * Return: 0 on success, -EINPROGRESS if the TX lock is busy, -EALREADY if TX
 * is already at or beyond @target_epoch, -ENOKEY if the future ring cannot
 * provide @target_epoch, or another negative error code otherwise.
 */
int ovpn_advance_encrypt_key(struct ovpn_crypto_key_slot *ks, u16 target_epoch,
			     bool required)
{
	u16 stale_count = 0, advance, count, index, stale_index, i;
	struct ovpn_key_ctx *stale[OVPN_EPOCH_FUTURE_KEYS_COUNT];
	struct ovpn_key_ctx *old_encrypt, *new_encrypt, *future;
	struct ovpn_key_ctx __rcu **slot;
	bool lock_held;

	/* concurrent promotion or refill means another context is moving tx */
	if (unlikely(!spin_trylock_bh(&ks->tx_lock)))
		return -EINPROGRESS;

	lock_held = lockdep_is_held(&ks->tx_lock);
	old_encrypt = rcu_dereference_protected(ks->encrypt,
						lock_held);
	if (unlikely(old_encrypt->epoch >= target_epoch)) {
		spin_unlock_bh(&ks->tx_lock);
		return -EALREADY;
	}

	count = ovpn_epoch_future_keys_count(&ks->future_tx_keys);
	advance = target_epoch - old_encrypt->epoch;
	/* refill can lag behind packet processing under pressure */
	if (unlikely(count < advance)) {
		spin_unlock_bh(&ks->tx_lock);
		ovpn_schedule_refill(ks, true);
		return -ENOKEY;
	}

	index = (ks->future_tx_keys.tail + advance - 1) %
		OVPN_EPOCH_FUTURE_KEYS_COUNT;
	new_encrypt = rcu_dereference_protected(ks->future_tx_keys.keys[index],
						lock_held);
	if (WARN_ON_ONCE(!new_encrypt ||
			 new_encrypt->epoch != target_epoch)) {
		spin_unlock_bh(&ks->tx_lock);
		return -ENOKEY;
	}

	for (i = 0; i < advance; i++) {
		/* drop skipped future keys when advancing past them */
		stale_index = (ks->future_tx_keys.tail + i) %
			      OVPN_EPOCH_FUTURE_KEYS_COUNT;
		slot = &ks->future_tx_keys.keys[stale_index];
		future = rcu_dereference_protected(*slot, lock_held);
		if (future != new_encrypt)
			stale[stale_count++] = future;
		RCU_INIT_POINTER(*slot, NULL);
	}

	/* each concrete key carries fresh packet-ID state */
	rcu_assign_pointer(ks->encrypt, new_encrypt);
	ks->future_tx_keys.tail = (ks->future_tx_keys.tail + advance) %
				  OVPN_EPOCH_FUTURE_KEYS_COUNT;
	ks->future_tx_keys.full = false;
	spin_unlock_bh(&ks->tx_lock);

	ovpn_key_ctx_put(old_encrypt);
	for (i = 0; i < stale_count; i++)
		ovpn_key_ctx_put(stale[i]);

	ovpn_schedule_refill(ks, true);

	return 0;
}

static int ovpn_aead_encrypt_next_seq(struct ovpn_peer *peer,
				      struct ovpn_crypto_key_slot *ks,
				      struct ovpn_key_ctx *encrypt,
				      unsigned int pkt_len, u64 *seq)
{
	bool required = false, pktid_notify;
	u64 aead_blocks;
	int ret;

	/* hard packet-ID exhaustion requires fresh key material */
	ret = ovpn_pktid_xmit_next(&encrypt->pid.xmit, seq);
	if (unlikely(ret < 0)) {
		if (!ks->epoch_format)
			return ret;
		required = true;
		goto new_key;
	}
	pktid_notify = ret > 0;

	aead_blocks = ovpn_aead_limit_blocks(ks->cipher_alg, ks->aad_size,
					     pkt_len);
	ret = ovpn_key_usage_xmit(&encrypt->usage, &ks->usage_limit, *seq,
				  aead_blocks, pktid_notify);
	if (unlikely(ret < 0)) {
		/* epoch keys rotate internally instead of asking userspace */
		if (!ks->epoch_format)
			return ret;
		required = true;
		goto new_key;
	}
	if (unlikely(ret > 0)) {
		if (!ks->epoch_format) {
			ovpn_nl_key_swap_notify(peer, ks->key_id);
			return 0;
		}
		/* epoch tx rotates locally when the soft limit is crossed */
		set_bit(OVPN_CRYPTO_TX_ROTATE_PENDING, &ks->flags);
	}

	if (!ks->epoch_format)
		return 0;

	/* rx can request a tx epoch bump without adding rx work to every
	 * tx packet
	 */
	if (unlikely(test_bit(OVPN_CRYPTO_TX_ROTATE_PENDING, &ks->flags)))
		goto new_key;

	return 0;

new_key:
	/* keep enough epoch space for the future-key ring after promotion */
	if (unlikely(encrypt->epoch + 1 + OVPN_EPOCH_FUTURE_KEYS_COUNT >=
		     OVPN_MAX_EPOCH))
		return -ERANGE;

	ret = ovpn_advance_encrypt_key(ks, encrypt->epoch + 1, required);
	if (unlikely(ret == -EINPROGRESS || ret == -ENOKEY))
		return required ? -EBUSY : 0;
	if (unlikely(ret < 0 && ret != -EALREADY))
		return ret;

	/* A concurrent soft-limit request can theoretically be lost here,
	 * but it would require the new tx epoch to consume its soft limit
	 * before this CPU clears the bit. Hard limits still force rotation.
	 */
	clear_bit(OVPN_CRYPTO_TX_ROTATE_PENDING, &ks->flags);

	return -EAGAIN;
}

int ovpn_aead_encrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *skb)
{
	unsigned int plaintext_len, payload_sg_len, sg_nents, tag_size;
	struct ovpn_key_ctx *key = NULL;
	struct aead_request *req;
	struct sk_buff *trailer;
	struct scatterlist *sg;
	bool retried = false;
	int nfrags, ret;
	u64 pktid, seq;
	void *tmp;
	u32 op;
	u8 *iv;

	ovpn_skb_cb(skb)->peer = peer;
	ovpn_skb_cb(skb)->ks = ks;
	plaintext_len = skb->len;

	/* direct-key DATA_V2 wire format:
	 * 48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
	 * [ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
	 *          [4-byte
	 *          IV head]
	 *
	 * epoch-key DATA_V2 wire format:
	 * 48000001 0001 000000000005 380275a... 7e7046bd 444a7e28 cc6387b1 64a4d6c1
	 * [ OP32 ] [ epoch ][  seq #   ] [ payload ... ] [             auth tag            ]
	 *          [        8-byte packet ID          ]
	 */

retry:
	ret = ovpn_key_ctx_get(&key, &ks->encrypt);
	if (unlikely(ret))
		return ret;
	ovpn_skb_cb(skb)->key = key;

	tag_size = crypto_aead_authsize(key->tfm);

	ret = ovpn_aead_encrypt_next_seq(peer, ks, key, plaintext_len, &seq);
	if (unlikely(ret == -EAGAIN)) {
		if (retried)
			return -EBUSY;

		/* retry once after epoch promotion */
		ovpn_skb_cb(skb)->key = NULL;
		ovpn_key_ctx_put(key);
		key = NULL;
		retried = true;
		goto retry;
	}
	if (unlikely(ret < 0))
		return ret;

	/* check that there's enough headroom in the skb for packet
	 * encapsulation
	 */
	if (unlikely(skb_cow_head(skb, OVPN_HEAD_ROOM)))
		return -ENOBUFS;

	/* ensure packet data is writable and epoch tag tailroom exists */
	nfrags = skb_cow_data(skb, ks->tail_tag_size, &trailer);
	if (unlikely(nfrags < 0))
		return nfrags;

	sg_nents = nfrags + 1 + !ks->tail_tag_size;
	if (unlikely(sg_nents > MAX_SKB_FRAGS + 2))
		return -ENOSPC;

	/* epoch packets place the authentication tag after payload */
	if (unlikely(ks->tail_tag_size))
		pskb_put(skb, trailer, ks->tail_tag_size);
	payload_sg_len = plaintext_len + ks->tail_tag_size;

	/* allocate temporary memory for iv, sg and req */
	tmp = kmalloc(ovpn_aead_crypto_tmp_size(key->tfm, sg_nents),
		      GFP_ATOMIC);
	if (unlikely(!tmp))
		return -ENOMEM;

	ovpn_skb_cb(skb)->crypto_tmp = tmp;

	iv = ovpn_aead_crypto_tmp_iv(key->tfm, tmp);
	req = ovpn_aead_crypto_tmp_req(key->tfm, iv);
	sg = ovpn_aead_crypto_req_sg(key->tfm, req);

	/* sg table:
	 * 0: op, packet ID (AD, len=ks->aad_size),
	 * 1, 2, 3, ..., n: payload and epoch auth_tag,
	 * n+1: direct auth_tag (len=tag_size)
	 */
	sg_init_table(sg, sg_nents);

	/* build scatterlist to encrypt packet payload */
	ret = skb_to_sgvec_nomark(skb, sg + 1, 0, payload_sg_len);
	if (unlikely(ret < 0)) {
		netdev_err(peer->ovpn->dev,
			   "encrypt: cannot map skb to sg: %d\n", ret);
		return ret;
	}

	if (likely(!ks->tail_tag_size)) {
		/* direct packets prepend the tag before payload */
		__skb_push(skb, tag_size);
		sg_set_buf(sg + ret + 1, skb->data, tag_size);
	}
	sg_mark_end(sg + ret + !ks->tail_tag_size);

	/* create the AEAD IV from packet ID and implicit IV */
	pktid = ovpn_pktid_aead_write(key->epoch, seq, key->implicit_iv, iv);

	/* make space for packet id and push it to the front */
	__skb_push(skb, ks->pktid_size);
	/* packet ID is 64 bits for epoch packets and 32 bits otherwise */
	ovpn_pktid_wire_write(skb->data, ks->epoch_format, pktid);

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
	aead_request_set_crypt(req, sg, sg, plaintext_len, iv);
	aead_request_set_ad(req, ks->aad_size);

	/* encrypt it */
	return crypto_aead_encrypt(req);
}

/**
 * ovpn_aead_decrypt_key - get the decrypt key matching a packet epoch
 * @ks: key slot containing RX epoch state
 * @pkt_epoch: epoch decoded from the packet ID
 *
 * Direct-key packets must carry epoch 0. Epoch RX first tries the current key,
 * then the retiring key for reordered packets, and finally the future ring. A
 * future key is returned only for authentication; promotion happens after the
 * packet has authenticated.
 *
 * Return: referenced key context or an error pointer.
 */
static struct ovpn_key_ctx *
ovpn_aead_decrypt_key(struct ovpn_crypto_key_slot *ks, u16 pkt_epoch)
{
	u16 current_epoch, epoch_diff, index;
	struct ovpn_key_ctx *key;

	if (likely(!ks->epoch_format)) {
		if (unlikely(pkt_epoch))
			return ERR_PTR(-EINVAL);
		if (unlikely(ovpn_key_ctx_get(&key, &ks->decrypt)))
			return ERR_PTR(-ENOKEY);
		return key;
	}

	spin_lock_bh(&ks->rx_lock);

	key = rcu_dereference_protected(ks->decrypt,
					lockdep_is_held(&ks->rx_lock));
	if (unlikely(!key)) {
		key = ERR_PTR(-ENOKEY);
		goto out;
	}
	/* current key is the expected rx path */
	if (likely(key->epoch == pkt_epoch)) {
		if (kref_get_unless_zero(&key->refcount))
			goto out;
		key = ERR_PTR(-ENOKEY);
		goto out;
	}
	current_epoch = key->epoch;

	key = rcu_dereference_protected(ks->retiring_key,
					lockdep_is_held(&ks->rx_lock));
	/* retiring key accepts late packets from the previous epoch */
	if (unlikely(key && key->epoch == pkt_epoch)) {
		if (kref_get_unless_zero(&key->refcount))
			goto out;
		key = ERR_PTR(-ENOKEY);
		goto out;
	}

	if (unlikely(pkt_epoch < current_epoch)) {
		key = ERR_PTR(-ERANGE);
		goto out;
	}
	/* stay away from the epoch range where future refill would wrap */
	if (unlikely(pkt_epoch >
		     OVPN_MAX_EPOCH - OVPN_EPOCH_FUTURE_KEYS_COUNT - 1)) {
		key = ERR_PTR(-ERANGE);
		goto out;
	}

	epoch_diff = pkt_epoch - current_epoch;
	if (unlikely(!epoch_diff ||
		     epoch_diff > OVPN_EPOCH_FUTURE_KEYS_COUNT)) {
		key = ERR_PTR(-ERANGE);
		goto out;
	}

	/* future keys are consecutive starting at tail/current_epoch + 1 */
	index = (ks->future_rx_keys.tail + epoch_diff - 1) %
		OVPN_EPOCH_FUTURE_KEYS_COUNT;
	key = rcu_dereference_protected(ks->future_rx_keys.keys[index],
					lockdep_is_held(&ks->rx_lock));
	if (unlikely(!key || key->epoch != pkt_epoch ||
		     !kref_get_unless_zero(&key->refcount))) {
		key = ERR_PTR(-ENOKEY);
		goto out;
	}

out:
	spin_unlock_bh(&ks->rx_lock);

	return key;
}

int ovpn_aead_decrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *skb)
{
	unsigned int payload_offset, payload_sg_len, sg_nents, tag_size;
	int ret, payload_len, nfrags;
	struct ovpn_key_ctx *key;
	struct aead_request *req;
	struct sk_buff *trailer;
	struct scatterlist *sg;
	u16 pkt_epoch;
	u64 pkt_seq;
	void *tmp;
	u8 *iv;

	payload_offset = ks->payload_offset;
	ovpn_skb_cb(skb)->payload_offset = payload_offset;
	ovpn_skb_cb(skb)->peer = peer;
	ovpn_skb_cb(skb)->ks = ks;

	if (unlikely(skb->len < payload_offset))
		return -EINVAL;
	payload_len = skb->len - payload_offset;
	if (unlikely(ks->tail_tag_size)) {
		if (unlikely(payload_len < ks->tail_tag_size))
			return -EINVAL;
		payload_len -= ks->tail_tag_size;
	}

	/* sanity check on packet size, payload size must be >= 0 */
	if (unlikely(payload_len < 0))
		return -EINVAL;

	/* make additional data contiguous for sg[0] */
	if (unlikely(!pskb_may_pull(skb, payload_offset)))
		return -ENODATA;

	/* epoch packet ID includes both epoch and per-epoch counter */
	pkt_seq = ovpn_pktid_read(skb->data + OVPN_OPCODE_SIZE,
				  ks->epoch_format, &pkt_epoch);
	key = ovpn_aead_decrypt_key(ks, pkt_epoch);
	if (IS_ERR(key))
		return PTR_ERR(key);
	ovpn_skb_cb(skb)->key = key;

	if (unlikely(ovpn_aead_decrypt_failure_exceeded(key)))
		return -EKEYREJECTED;

	tag_size = crypto_aead_authsize(key->tfm);
	/* epoch tag is at the tail and remains in the crypto input */
	payload_sg_len = payload_len + ks->tail_tag_size;

	/* get number of skb frags and ensure that packet data is writable */
	nfrags = skb_cow_data(skb, 0, &trailer);
	if (unlikely(nfrags < 0))
		return nfrags;

	sg_nents = nfrags + 1 + !ks->tail_tag_size;
	if (unlikely(sg_nents > MAX_SKB_FRAGS + 2))
		return -ENOSPC;

	/* allocate temporary memory for iv, sg and req */
	tmp = kmalloc(ovpn_aead_crypto_tmp_size(key->tfm, sg_nents),
		      GFP_ATOMIC);
	if (unlikely(!tmp))
		return -ENOMEM;

	ovpn_skb_cb(skb)->crypto_tmp = tmp;

	iv = ovpn_aead_crypto_tmp_iv(key->tfm, tmp);
	req = ovpn_aead_crypto_tmp_req(key->tfm, iv);
	sg = ovpn_aead_crypto_req_sg(key->tfm, req);

	/* sg table:
	 * 0: op, packet ID (AD, len=ks->aad_size),
	 * 1, 2, 3, ..., n: payload and epoch auth_tag,
	 * n+1: direct auth_tag (len=tag_size)
	 */
	sg_init_table(sg, sg_nents);

	/* packet op is head of additional data */
	sg_set_buf(sg, skb->data, ks->aad_size);

	/* build scatterlist to decrypt packet payload */
	ret = skb_to_sgvec_nomark(skb, sg + 1, payload_offset,
				  payload_sg_len);
	if (unlikely(ret < 0)) {
		netdev_err(peer->ovpn->dev,
			   "decrypt: cannot map skb to sg: %d\n", ret);
		return ret;
	}

	if (likely(!ks->tail_tag_size)) {
		/* direct tag is prepended; epoch tag is in payload sg */
		sg_set_buf(sg + ret + 1,
			   skb->data + OVPN_AEAD_DIRECT_TAG_OFFSET,
			   tag_size);
	}
	sg_mark_end(sg + ret + !ks->tail_tag_size);

	/* rebuild the AEAD IV from packet ID and implicit IV */
	ovpn_pktid_aead_write(pkt_epoch, pkt_seq, key->implicit_iv, iv);

	/* setup async crypto operation */
	aead_request_set_tfm(req, key->tfm);
	aead_request_set_callback(req, 0, ovpn_decrypt_post, skb);
	aead_request_set_crypt(req, sg, sg, payload_len + tag_size, iv);

	aead_request_set_ad(req, ks->aad_size);

	/* decrypt it */
	return crypto_aead_decrypt(req);
}

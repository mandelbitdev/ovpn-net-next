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
#include "peer.h"
#include "proto.h"
#include "skb.h"

#define OVPN_AUTH_TAG_SIZE	16

#define ALG_NAME_AES		"gcm(aes)"
#define ALG_NAME_CHACHAPOLY	"rfc7539(chacha20,poly1305)"

/**
 * ovpn_aead_crypto_tmp_size - compute the size of a temporary object containing
 *			       an AEAD request structure with extra space for SG
 *			       and IV.
 * @tfm: the AEAD cipher handle
 * @nsg: the number of scatterlist entries to reserve
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
					      const unsigned int nsg)
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
	len += array_size(sizeof(struct scatterlist), nsg);
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
		      struct sk_buff *in)
{
	const unsigned int tag_size = crypto_aead_authsize(ks->encrypt);
	const unsigned int src_nents = skb_shinfo(in)->nr_frags + 2;
	const unsigned int out_len = OVPN_AAD_SIZE + tag_size + in->len;
	const unsigned int payload_len = in->len;
	const unsigned int dst_nents = 3;
	struct scatterlist *src, *dst;
	struct aead_request *req;
	struct sk_buff *out;
	u32 pktid, op;
	void *tmp;
	int ret;
	u8 *iv;

	ovpn_skb_cb(in)->peer = peer;
	ovpn_skb_cb(in)->ks = ks;

	/* Sample AEAD header format:
	 * 48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
	 * [ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
	 *          [4-byte
	 *          IV head]
	 */

	/* allocate the output skb for out-of-place crypto */
	out = netdev_alloc_skb(peer->ovpn->dev, OVPN_HEAD_ROOM + out_len);
	if (unlikely(!out))
		return -ENOMEM;

	/* setup the skb layout */
	skb_reserve(out, OVPN_HEAD_ROOM);
	skb_put(out, out_len);
	skb_reset_inner_network_header(out);

	memset(ovpn_skb_cb(out), 0, sizeof(struct ovpn_cb));
	ovpn_skb_cb(out)->nosignal = ovpn_skb_cb(in)->nosignal;
	ovpn_skb_cb(in)->out_skb = out;

	/* allocate temporary memory for iv, req and sgs */
	tmp = kmalloc(ovpn_aead_crypto_tmp_size(ks->encrypt,
						src_nents + dst_nents),
		      GFP_ATOMIC);
	if (unlikely(!tmp))
		return -ENOMEM;

	ovpn_skb_cb(in)->crypto_tmp = tmp;

	iv = ovpn_aead_crypto_tmp_iv(ks->encrypt, tmp);
	req = ovpn_aead_crypto_tmp_req(ks->encrypt, iv);
	src = ovpn_aead_crypto_req_sg(ks->encrypt, req);
	dst = src + src_nents;

	/* obtain packet ID, which is used both as a first
	 * 4 bytes of nonce and last 4 bytes of associated data.
	 */
	ret = ovpn_pktid_xmit_next(&ks->pid_xmit, &pktid);
	if (unlikely(ret < 0))
		return ret;

	/* concat 4 bytes packet id and 8 bytes nonce tail into 12 bytes
	 * nonce
	 */
	ovpn_pktid_aead_write(pktid, ks->nonce_tail_xmit, iv);

	op = ovpn_opcode_compose(OVPN_DATA_V2, ks->key_id, peer->tx_id);
	BUILD_BUG_ON(sizeof(op) != OVPN_OPCODE_SIZE);
	*((__force __be32 *)out->data) = htonl(op);
	memcpy(out->data + OVPN_OPCODE_SIZE, iv, OVPN_NONCE_WIRE_SIZE);

	/* source sg table:
	 * 0: op, wire nonce (AD, len=OVPN_OP_SIZE_V2+OVPN_NONCE_WIRE_SIZE),
	 * 1, ..., src_nents: plaintext
	 */
	sg_init_table(src, src_nents);

	/* destination sg table:
	 * 0: AAD,
	 * 1: ciphertext,
	 * 2: auth_tag (len=tag_size)
	 */
	sg_init_table(dst, dst_nents);

	/* use the already written OpenVPN AEAD Additional data in the output
	 * skb as the source AAD for AEAD authentication
	 */
	sg_set_buf(src, out->data, OVPN_AAD_SIZE);
	ret = skb_to_sgvec_nomark(in, src + 1, 0, payload_len);
	if (unlikely(ret < 0)) {
		netdev_err(peer->ovpn->dev,
			   "encrypt: cannot map skb to src sg: %d\n", ret);
		return ret;
	}
	sg_mark_end(src + ret);

	/* output skb layout:
	 * AAD:        out->data             = dst[0]
	 * tag:        out->data + AAD       = dst[2]
	 * ciphertext: out->data + AAD + tag = dst[1]
	 */
	sg_set_buf(dst, out->data, OVPN_AAD_SIZE);
	sg_set_buf(dst + 1, out->data + OVPN_AAD_SIZE + tag_size,
		   payload_len);
	sg_set_buf(dst + 2, out->data + OVPN_AAD_SIZE, tag_size);

	aead_request_set_tfm(req, ks->encrypt);
	aead_request_set_callback(req, 0, ovpn_encrypt_post, in);
	aead_request_set_crypt(req, src, dst, payload_len, iv);
	aead_request_set_ad(req, OVPN_AAD_SIZE);

	/* encrypt it */
	return crypto_aead_encrypt(req);
}

int ovpn_aead_decrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *in)
{
	const unsigned int tag_size = crypto_aead_authsize(ks->decrypt);
	const unsigned int payload_offset = OVPN_AAD_SIZE + tag_size;
	const int payload_len = in->len - payload_offset;
	const unsigned int dst_nents = 2;
	struct scatterlist *src, *dst;
	struct aead_request *req;
	unsigned int src_nents;
	struct sk_buff *out;
	void *tmp;
	int ret;
	u8 *iv;

	ovpn_skb_cb(in)->peer = peer;
	ovpn_skb_cb(in)->ks = ks;

	/* sanity check on packet size, payload size must be >= 0 */
	if (unlikely(payload_len < 0))
		return -EINVAL;

	/* Prepare the skb data buffer to be accessed up until the auth tag.
	 * This is required because this area is directly mapped into the sg
	 * list.
	 */
	if (unlikely(!pskb_may_pull(in, payload_offset)))
		return -ENODATA;

	/* allocate the output skb for out-of-place crypto */
	out = netdev_alloc_skb(peer->ovpn->dev, payload_len);
	if (unlikely(!out))
		return -ENOMEM;

	skb_put(out, payload_len);
	memset(ovpn_skb_cb(out), 0, sizeof(struct ovpn_cb));
	ovpn_skb_cb(in)->out_skb = out;

	/* source sg needs one entry for AAD, up to nr_frags + 1 entries for
	 * ciphertext and one entry for auth_tag
	 */
	src_nents = skb_shinfo(in)->nr_frags + 3;

	/* allocate temporary memory for iv, req and sgs */
	tmp = kmalloc(ovpn_aead_crypto_tmp_size(ks->decrypt,
						src_nents + dst_nents),
		      GFP_ATOMIC);
	if (unlikely(!tmp))
		return -ENOMEM;

	ovpn_skb_cb(in)->crypto_tmp = tmp;

	iv = ovpn_aead_crypto_tmp_iv(ks->decrypt, tmp);
	req = ovpn_aead_crypto_tmp_req(ks->decrypt, iv);
	src = ovpn_aead_crypto_req_sg(ks->decrypt, req);
	dst = src + src_nents;

	/* source sg table:
	 * 0: op, wire nonce (AD, len=OVPN_OPCODE_SIZE+OVPN_NONCE_WIRE_SIZE),
	 * 1, 2, 3, ..., n: payload,
	 * n+1: auth_tag (len=tag_size)
	 */
	sg_init_table(src, src_nents);

	/* destination sg table:
	 * 0: AAD,
	 * 1: plaintext
	 */
	sg_init_table(dst, dst_nents);

	/* packet op is head of additional data */
	sg_set_buf(src, in->data, OVPN_AAD_SIZE);

	/* build scatterlist to decrypt packet payload */
	ret = skb_to_sgvec_nomark(in, src + 1, payload_offset, payload_len);
	if (unlikely(ret < 0)) {
		netdev_err(peer->ovpn->dev,
			   "decrypt: cannot map skb to src sg: %d\n", ret);
		return ret;
	}

	/* append auth_tag onto scatterlist */
	sg_set_buf(src + ret + 1, in->data + OVPN_AAD_SIZE, tag_size);
	sg_mark_end(src + ret + 1);

	/* use the already written OpenVPN AEAD Additional data in the input
	 * skb as the destination AAD for AEAD authentication
	 */
	sg_set_buf(dst, in->data, OVPN_AAD_SIZE);
	sg_set_buf(dst + 1, out->data, payload_len);

	/* copy nonce into IV buffer */
	memcpy(iv, in->data + OVPN_OPCODE_SIZE, OVPN_NONCE_WIRE_SIZE);
	memcpy(iv + OVPN_NONCE_WIRE_SIZE, ks->nonce_tail_recv,
	       OVPN_NONCE_TAIL_SIZE);

	/* setup async crypto operation */
	aead_request_set_tfm(req, ks->decrypt);
	aead_request_set_callback(req, 0, ovpn_decrypt_post, in);
	aead_request_set_crypt(req, src, dst, payload_len + tag_size, iv);

	aead_request_set_ad(req, OVPN_AAD_SIZE);

	/* decrypt it */
	return crypto_aead_decrypt(req);
}

/* Initialize a struct crypto_aead object */
static struct crypto_aead *ovpn_aead_init(const char *title,
					  const char *alg_name,
					  const unsigned char *key,
					  unsigned int keylen)
{
	struct crypto_aead *aead;
	int ret;

	aead = crypto_alloc_aead(alg_name, 0, 0);
	if (IS_ERR(aead)) {
		ret = PTR_ERR(aead);
		pr_err("%s crypto_alloc_aead failed, err=%d\n", title, ret);
		aead = NULL;
		goto error;
	}

	ret = crypto_aead_setkey(aead, key, keylen);
	if (ret) {
		pr_err("%s crypto_aead_setkey size=%u failed, err=%d\n", title,
		       keylen, ret);
		goto error;
	}

	ret = crypto_aead_setauthsize(aead, OVPN_AUTH_TAG_SIZE);
	if (ret) {
		pr_err("%s crypto_aead_setauthsize failed, err=%d\n", title,
		       ret);
		goto error;
	}

	/* basic AEAD assumption
	 * all current algorithms use OVPN_NONCE_SIZE.
	 * ovpn_aead_crypto_tmp_size and ovpn_aead_encrypt/decrypt
	 * expect this.
	 */
	if (crypto_aead_ivsize(aead) != OVPN_NONCE_SIZE) {
		pr_err("%s IV size must be %d\n", title, OVPN_NONCE_SIZE);
		ret = -EINVAL;
		goto error;
	}

	pr_debug("********* Cipher %s (%s)\n", alg_name, title);
	pr_debug("*** IV size=%u\n", crypto_aead_ivsize(aead));
	pr_debug("*** req size=%u\n", crypto_aead_reqsize(aead));
	pr_debug("*** block size=%u\n", crypto_aead_blocksize(aead));
	pr_debug("*** auth size=%u\n", crypto_aead_authsize(aead));
	pr_debug("*** alignmask=0x%x\n", crypto_aead_alignmask(aead));

	return aead;

error:
	crypto_free_aead(aead);
	return ERR_PTR(ret);
}

void ovpn_aead_crypto_key_slot_destroy(struct ovpn_crypto_key_slot *ks)
{
	if (!ks)
		return;

	crypto_free_aead(ks->encrypt);
	crypto_free_aead(ks->decrypt);
	kfree(ks);
}

struct ovpn_crypto_key_slot *
ovpn_aead_crypto_key_slot_new(const struct ovpn_key_config *kc)
{
	struct ovpn_crypto_key_slot *ks = NULL;
	const char *alg_name;
	int ret;

	/* validate crypto alg */
	switch (kc->cipher_alg) {
	case OVPN_CIPHER_ALG_AES_GCM:
		alg_name = ALG_NAME_AES;
		break;
	case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
		alg_name = ALG_NAME_CHACHAPOLY;
		break;
	default:
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (kc->encrypt.nonce_tail_size != OVPN_NONCE_TAIL_SIZE ||
	    kc->decrypt.nonce_tail_size != OVPN_NONCE_TAIL_SIZE)
		return ERR_PTR(-EINVAL);

	/* build the key slot */
	ks = kmalloc_obj(*ks);
	if (!ks)
		return ERR_PTR(-ENOMEM);

	ks->encrypt = NULL;
	ks->decrypt = NULL;
	kref_init(&ks->refcount);
	ks->key_id = kc->key_id;

	ks->encrypt = ovpn_aead_init("encrypt", alg_name,
				     kc->encrypt.cipher_key,
				     kc->encrypt.cipher_key_size);
	if (IS_ERR(ks->encrypt)) {
		ret = PTR_ERR(ks->encrypt);
		ks->encrypt = NULL;
		goto destroy_ks;
	}

	ks->decrypt = ovpn_aead_init("decrypt", alg_name,
				     kc->decrypt.cipher_key,
				     kc->decrypt.cipher_key_size);
	if (IS_ERR(ks->decrypt)) {
		ret = PTR_ERR(ks->decrypt);
		ks->decrypt = NULL;
		goto destroy_ks;
	}

	memcpy(ks->nonce_tail_xmit, kc->encrypt.nonce_tail,
	       OVPN_NONCE_TAIL_SIZE);
	memcpy(ks->nonce_tail_recv, kc->decrypt.nonce_tail,
	       OVPN_NONCE_TAIL_SIZE);

	/* init packet ID generation/validation */
	ovpn_pktid_xmit_init(&ks->pid_xmit);
	ovpn_pktid_recv_init(&ks->pid_recv);

	return ks;

destroy_ks:
	ovpn_aead_crypto_key_slot_destroy(ks);
	return ERR_PTR(ret);
}

enum ovpn_cipher_alg ovpn_aead_crypto_alg(struct ovpn_crypto_key_slot *ks)
{
	const char *alg_name;

	if (!ks->encrypt)
		return OVPN_CIPHER_ALG_NONE;

	alg_name = crypto_tfm_alg_name(crypto_aead_tfm(ks->encrypt));

	if (!strcmp(alg_name, ALG_NAME_AES))
		return OVPN_CIPHER_ALG_AES_GCM;
	else if (!strcmp(alg_name, ALG_NAME_CHACHAPOLY))
		return OVPN_CIPHER_ALG_CHACHA20_POLY1305;
	else
		return OVPN_CIPHER_ALG_NONE;
}

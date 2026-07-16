// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2026 OpenVPN, Inc.
 *
 *  Author:	Ralf Lici <ralf@mandelbit.com>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include <crypto/hkdf.h>
#include <linux/unaligned.h>

#include "crypto_epoch.h"
#include "proto.h"

#define OVPN_EPOCH_DATA_KEY_LABEL "data_key"
#define OVPN_EPOCH_DATA_IV_LABEL "data_iv"
#define OVPN_EPOCH_UPDATE_LABEL "datakey upd"
#define OVPN_EPOCH_LABEL_PREFIX "ovpn "

static_assert(OVPN_EPOCH_PRK_SIZE == SHA256_DIGEST_SIZE);

/* The prefixed label length must fit its u8 field. */
#define OVPN_EPOCH_FULL_LABEL_LEN(label) \
	(sizeof(OVPN_EPOCH_LABEL_PREFIX) - 1 + sizeof(label) - 1)

static_assert(OVPN_EPOCH_FULL_LABEL_LEN(OVPN_EPOCH_DATA_KEY_LABEL) <= U8_MAX);
static_assert(OVPN_EPOCH_FULL_LABEL_LEN(OVPN_EPOCH_DATA_IV_LABEL) <= U8_MAX);
static_assert(OVPN_EPOCH_FULL_LABEL_LEN(OVPN_EPOCH_UPDATE_LABEL) <= U8_MAX);

static void ovpn_expand_label(const struct hmac_sha256_key *prk,
			      const u8 *label,
			      size_t label_len, u8 *okm, u16 okm_len)
{
	static const u8 label_prefix[] = OVPN_EPOCH_LABEL_PREFIX;
	static const u8 empty_context_len;
	u8 hdr[3];
	const struct hkdf_seg info[] = {
		{ .data = hdr, .len = sizeof(hdr) },
		{ .data = label_prefix, .len = sizeof(label_prefix) - 1 },
		{ .data = label, .len = label_len },
		{ .data = &empty_context_len, .len = 1 },
	};

	/* encode okm length and prefixed label length */
	put_unaligned_be16(okm_len, hdr);
	hdr[2] = sizeof(label_prefix) - 1 + label_len;

	hkdf_sha256_expand(prk, info, ARRAY_SIZE(info), okm, okm_len);
}

/**
 * ovpn_epoch_derive_next_prk - derive the next epoch PRK
 * @epoch_key: PRK derivation state
 * @next_prk: destination for the next PRK
 *
 * Epoch data keys are derived from a per-direction PRK. Advancing from E_N to
 * E_N+1 uses OVPN-Expand-Label(E_N, "datakey upd", "", 32).
 *
 * Return: 0 on success or a negative error code otherwise.
 */
int ovpn_epoch_derive_next_prk(const struct ovpn_epoch_key *epoch_key,
			       u8 next_prk[])
{
	if (unlikely(epoch_key->epoch == OVPN_MAX_EPOCH))
		return -ERANGE;

	ovpn_expand_label(&epoch_key->prk, OVPN_EPOCH_UPDATE_LABEL,
			  sizeof(OVPN_EPOCH_UPDATE_LABEL) - 1,
			  next_prk, OVPN_EPOCH_PRK_SIZE);

	return 0;
}

void ovpn_epoch_set_prk(struct ovpn_epoch_key *epoch_key, const u8 prk[],
			u16 epoch)
{
	hmac_sha256_preparekey(&epoch_key->prk, prk, OVPN_EPOCH_PRK_SIZE);
	epoch_key->epoch = epoch;
}

/**
 * ovpn_epoch_iterate - advance an epoch PRK to the next epoch
 * @epoch_key: PRK derivation state
 *
 * Epoch data keys are derived from a per-direction PRK. Advancing from E_N to
 * E_N+1 uses OVPN-Expand-Label(E_N, "datakey upd", "", 32).
 *
 * Return: 0 on success or a negative error code otherwise.
 */
int ovpn_epoch_iterate(struct ovpn_epoch_key *epoch_key)
{
	u8 key[OVPN_EPOCH_PRK_SIZE];
	int ret;

	ret = ovpn_epoch_derive_next_prk(epoch_key, key);
	if (ret)
		goto out;

	/* expose the next epoch only after its PRK is installed */
	ovpn_epoch_set_prk(epoch_key, key, epoch_key->epoch + 1);

out:
	memzero_explicit(key, sizeof(key));
	return ret;
}

/**
 * ovpn_epoch_derive_key - derive the concrete AEAD key for an epoch
 * @epoch_key: PRK derivation state
 * @cipher_key: destination for the AEAD cipher key
 * @implicit_iv: destination for the AEAD implicit IV
 *
 * K_i is OVPN-Expand-Label(E_i, "data_key", "", key_size), while the implicit
 * IV is OVPN-Expand-Label(E_i, "data_iv", "", OVPN_NONCE_SIZE).
 *
 * Return: 0 on success or a negative error code otherwise.
 */
int ovpn_epoch_derive_key(const struct ovpn_epoch_key *epoch_key,
			  u8 cipher_key[], u8 implicit_iv[])
{
	if (WARN_ON_ONCE(!epoch_key->cipher_key_len ||
			 epoch_key->cipher_key_len > OVPN_EPOCH_PRK_SIZE))
		return -EINVAL;

	/* derive the concrete AEAD key for the current epoch */
	ovpn_expand_label(&epoch_key->prk, OVPN_EPOCH_DATA_KEY_LABEL,
			  sizeof(OVPN_EPOCH_DATA_KEY_LABEL) - 1,
			  cipher_key, epoch_key->cipher_key_len);

	/* derive the implicit IV paired with that AEAD key */
	ovpn_expand_label(&epoch_key->prk, OVPN_EPOCH_DATA_IV_LABEL,
			  sizeof(OVPN_EPOCH_DATA_IV_LABEL) - 1,
			  implicit_iv, OVPN_NONCE_SIZE);

	return 0;
}

/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2026 OpenVPN, Inc.
 *
 *  Author:	Ralf Lici <ralf@mandelbit.com>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_OVPNEPOCH_H_
#define _NET_OVPN_OVPNEPOCH_H_

#include <crypto/sha2.h>
#include <linux/limits.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <uapi/linux/ovpn.h>

#define OVPN_MAX_EPOCH U16_MAX
#define OVPN_EPOCH_FUTURE_KEYS_COUNT 16

struct ovpn_key_ctx;

/* key derivation state for HKDF-Expand-Label */
struct ovpn_epoch_key {
	u16 epoch;
	unsigned int cipher_key_len;
	struct hmac_sha256_key prk;
};

/* ring buffer of prederived future epoch data keys */
struct ovpn_future_keys {
	struct ovpn_key_ctx __rcu *keys[OVPN_EPOCH_FUTURE_KEYS_COUNT];
	u16 head;
	u16 tail;
	bool full;
};

static inline u16
ovpn_epoch_future_keys_count(const struct ovpn_future_keys *fk)
{
	if (fk->full)
		return OVPN_EPOCH_FUTURE_KEYS_COUNT;

	return (fk->head - fk->tail + OVPN_EPOCH_FUTURE_KEYS_COUNT) %
	       OVPN_EPOCH_FUTURE_KEYS_COUNT;
}

int ovpn_epoch_derive_next_prk(const struct ovpn_epoch_key *epoch_key,
			       u8 next_prk[]);
void ovpn_epoch_set_prk(struct ovpn_epoch_key *epoch_key, const u8 prk[],
			u16 epoch);
int ovpn_epoch_iterate(struct ovpn_epoch_key *epoch_key);
int ovpn_epoch_derive_key(const struct ovpn_epoch_key *epoch_key,
			  u8 cipher_key[], u8 implicit_iv[]);

#endif /* _NET_OVPN_OVPNEPOCH_H_ */

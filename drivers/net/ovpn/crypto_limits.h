/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2026 OpenVPN, Inc.
 *
 *  Author:	Ralf Lici <ralf@mandelbit.com>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_CRYPTO_LIMITS_H_
#define _NET_OVPN_CRYPTO_LIMITS_H_

#include <crypto/aes.h>
#include <linux/atomic.h>
#include <linux/limits.h>
#include <linux/math.h>
#include <linux/types.h>
#include <uapi/linux/ovpn.h>

/* use the OpenVPN/SP 800-38D AES-GCM invocation limit */
#define OVPN_AES_GCM_USAGE_LIMIT ((1ULL << 36) - 1)

/* notify userspace at 7/8 of the AES-GCM hard limit */
#define OVPN_AES_GCM_USAGE_NOTIFY (OVPN_AES_GCM_USAGE_LIMIT / 8 * 7)

#define OVPN_KEY_USAGE_NOTIFY_BIT 0

struct ovpn_limit {
	u64 soft;
	u64 hard;
};

struct ovpn_key_usage {
	atomic64_t blocks;
	unsigned long flags;
};

static inline void ovpn_key_usage_init(struct ovpn_key_usage *usage)
{
	atomic64_set(&usage->blocks, 0);
	usage->flags = 0;
}

static inline void
ovpn_key_usage_limit_init(struct ovpn_limit *limit,
			  enum ovpn_cipher_alg cipher_alg)
{
	limit->soft = U64_MAX;
	limit->hard = U64_MAX;

	switch (cipher_alg) {
	case OVPN_CIPHER_ALG_AES_GCM:
		limit->soft = OVPN_AES_GCM_USAGE_NOTIFY;
		limit->hard = OVPN_AES_GCM_USAGE_LIMIT;
		break;
	case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
	default:
		break;
	}
}

static inline bool ovpn_key_usage_over_limit(u64 limit, u64 pktid, u64 blocks)
{
	return pktid > limit || blocks > limit - pktid;
}

static inline bool ovpn_key_usage_notify_once(struct ovpn_key_usage *usage)
{
	return !test_and_set_bit(OVPN_KEY_USAGE_NOTIFY_BIT, &usage->flags);
}

static inline int
ovpn_key_usage_xmit(struct ovpn_key_usage *usage,
		    const struct ovpn_limit *limit,
		    u64 pktid, u64 blocks, bool pktid_notify)
{
	int ret = 0;
	u64 total;

	total = atomic64_add_return(blocks, &usage->blocks);

	/* tx must stop before the hard limit is crossed */
	if (unlikely(ovpn_key_usage_over_limit(limit->hard, pktid, total)))
		return -ERANGE;

	/* soft limits ask userspace to rekey before tx must stop */
	if (unlikely(pktid_notify ||
		     ovpn_key_usage_over_limit(limit->soft, pktid, total)) &&
	    ovpn_key_usage_notify_once(usage))
		ret = 1;

	return ret;
}

static inline bool
ovpn_key_usage_recv(struct ovpn_key_usage *usage,
		    const struct ovpn_limit *limit,
		    u64 pktid, u64 blocks)
{
	u64 total;

	total = atomic64_add_return(blocks, &usage->blocks);

	/* rx threshold crossings are reported once without dropping
	 * the packet
	 */
	return unlikely(ovpn_key_usage_over_limit(limit->soft, pktid, total)) &&
	       ovpn_key_usage_notify_once(usage);
}

static inline u64 ovpn_aead_limit_blocks(enum ovpn_cipher_alg cipher_alg,
					 unsigned int aad,
					 unsigned int bytes)
{
	switch (cipher_alg) {
	case OVPN_CIPHER_ALG_AES_GCM:
		return DIV_ROUND_UP_ULL(aad, AES_BLOCK_SIZE) +
		       DIV_ROUND_UP_ULL(bytes, AES_BLOCK_SIZE);
	case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
	default:
		return 0;
	}
}

#endif /* _NET_OVPN_CRYPTO_LIMITS_H_ */

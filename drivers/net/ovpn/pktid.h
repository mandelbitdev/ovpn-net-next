/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2025 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 *		James Yonan <james@openvpn.net>
 */

#ifndef _NET_OVPN_OVPNPKTID_H_
#define _NET_OVPN_OVPNPKTID_H_

#include "crypto_limits.h"
#include "proto.h"

/* If no packets received for this length of time, set a backtrack floor
 * at highest received packet ID thus far.
 */
#define PKTID_RECV_EXPIRE (30 * HZ)

/* notify userspace when the packet ID space is close to wrapping */
#define PKTID_XMIT_REKEY_NOTIFY 0xff000000U

/* Packet-ID state for transmitter */
struct ovpn_pktid_xmit {
	atomic_t seq_num;
};

/* replay window sizing in bytes = 2^REPLAY_WINDOW_ORDER */
#define REPLAY_WINDOW_ORDER 8

#define REPLAY_WINDOW_BYTES BIT(REPLAY_WINDOW_ORDER)
#define REPLAY_WINDOW_SIZE  (REPLAY_WINDOW_BYTES * 8)
#define REPLAY_INDEX(base, i) (((base) + (i)) & (REPLAY_WINDOW_SIZE - 1))

/* Packet-ID state for receiver.
 * Other than lock member, can be zeroed to initialize.
 */
struct ovpn_pktid_recv {
	/* "sliding window" bitmask of recent packet IDs received */
	DECLARE_BITMAP(history, REPLAY_WINDOW_SIZE);
	/* bit position of deque base in history */
	unsigned int base;
	/* extent (in bits) of deque in history */
	unsigned int extent;
	/* expiration of history in jiffies */
	unsigned long expire;
	/* highest sequence number received */
	u32 id;
	/* highest time stamp received */
	u32 time;
	/* we will only accept backtrack IDs > id_floor */
	u32 id_floor;
	unsigned int max_backtrack;
	/* protects entire pktd ID state */
	spinlock_t lock;
};

/**
 * ovpn_pktid_xmit_next - allocate a transmit packet ID
 * @pid: transmit packet ID state
 * @usage: key usage state
 * @limit: key usage limits
 * @aead_blocks: AEAD usage blocks consumed by this packet
 * @pktid: location where the generated packet ID is stored
 *
 * The returned packet ID becomes part of the AEAD nonce, so the helper rejects
 * the packet before the 32-bit packet-ID space wraps. It also reserves this
 * packet's AEAD usage against the key and rejects the packet before the hard
 * AES-GCM usage limit would be exceeded.
 *
 * Soft thresholds do not reject the packet. They return 1 once so the caller
 * can notify userspace to rekey while packet-ID space remains and before the
 * hard AES-GCM usage limit is reached.
 *
 * Return: 1 if userspace should be notified, 0 if no notification is needed,
 * or a negative error code otherwise.
 */
static inline int ovpn_pktid_xmit_next(struct ovpn_pktid_xmit *pid,
				       struct ovpn_key_usage *usage,
				       const struct ovpn_limit *limit,
				       u64 aead_blocks, u32 *pktid)
{
	const u32 seq_num = atomic_fetch_add_unless(&pid->seq_num, 1, 0);
	bool pktid_notify;
	int ret;

	/* packet IDs are used to create cipher IVs and must not wrap */
	if (unlikely(!seq_num))
		return -ERANGE;

	pktid_notify = seq_num >= PKTID_XMIT_REKEY_NOTIFY;
	ret = ovpn_key_usage_xmit(usage, limit, seq_num, aead_blocks,
				  pktid_notify);
	if (unlikely(ret < 0))
		return ret;

	*pktid = seq_num;

	return ret;
}

/**
 * ovpn_pktid_recv_update_aead - account receive-side AEAD usage
 * @pr: receive packet ID state
 * @usage: key usage state
 * @limit: key usage limits
 * @aead_blocks: AEAD usage blocks consumed by this packet
 *
 * RX AEAD accounting is only informational for the local userspace process.
 * The peer's packets that already passed authentication and replay checks are
 * not dropped because the peer crossed a local usage threshold.
 *
 * Return: true if userspace should be notified, false otherwise.
 */
static inline bool
ovpn_pktid_recv_update_aead(struct ovpn_pktid_recv *pr,
			    struct ovpn_key_usage *usage,
			    const struct ovpn_limit *limit,
			    u64 aead_blocks)
{
	bool ret;

	spin_lock_bh(&pr->lock);
	ret = ovpn_key_usage_recv(usage, limit, pr->id, aead_blocks);
	spin_unlock_bh(&pr->lock);

	return ret;
}

/* write the direct-key AEAD IV to dest */
static inline void ovpn_pktid_aead_write(const u32 pktid,
					 const u8 implicit_iv[],
					 unsigned char *dest)
{
	*(__force __be32 *)(dest) = htonl(pktid);
	BUILD_BUG_ON(OVPN_NONCE_WIRE_SIZE + OVPN_NONCE_TAIL_SIZE !=
		     OVPN_NONCE_SIZE);
	memcpy(dest + OVPN_NONCE_WIRE_SIZE,
	       implicit_iv + OVPN_NONCE_WIRE_SIZE, OVPN_NONCE_TAIL_SIZE);
}

void ovpn_pktid_xmit_init(struct ovpn_pktid_xmit *pid);
void ovpn_pktid_recv_init(struct ovpn_pktid_recv *pr);

int ovpn_pktid_recv(struct ovpn_pktid_recv *pr, u32 pkt_id, u32 pkt_time);

#endif /* _NET_OVPN_OVPNPKTID_H_ */

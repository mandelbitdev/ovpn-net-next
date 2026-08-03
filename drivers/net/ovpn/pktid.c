// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2025 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 *		James Yonan <james@openvpn.net>
 */

#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/jiffies.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/types.h>

#include "ovpnpriv.h"
#include "main.h"
#include "pktid.h"

void ovpn_pktid_xmit_init(struct ovpn_pktid_xmit *pid)
{
	atomic_set(&pid->seq_num, 1);
}

int ovpn_pktid_recv_init(struct ovpn_pktid_recv *pr,
			 unsigned int window_size)
{
	memset(pr, 0, sizeof(*pr));
	pr->history = bitmap_zalloc(window_size, GFP_KERNEL);
	if (!pr->history)
		return -ENOMEM;

	pr->window_size = window_size;
	spin_lock_init(&pr->lock);

	return 0;
}

void ovpn_pktid_recv_cleanup(struct ovpn_pktid_recv *pr)
{
	bitmap_free(pr->history);
}

/* Packet replay detection.
 * Allows ID backtrack of up to pr->window_size - 1.
 */
int ovpn_pktid_recv(struct ovpn_pktid_recv *pr, u32 pkt_id, u32 pkt_time)
{
	unsigned int clear_start, clear_len, first;
	const unsigned long now = jiffies;
	int ret;

	/* ID must not be zero */
	if (unlikely(pkt_id == 0))
		return -EINVAL;

	spin_lock_bh(&pr->lock);

	/* expire backtracks at or below pr->id after PKTID_RECV_EXPIRE time */
	if (unlikely(time_after_eq(now, pr->expire)))
		pr->id_floor = pr->id;

	/* time changed? */
	if (unlikely(pkt_time != pr->time)) {
		if (pkt_time > pr->time) {
			/* time moved forward, accept */
			pr->base = 0;
			pr->extent = 0;
			pr->id = 0;
			pr->time = pkt_time;
			pr->id_floor = 0;
		} else {
			/* time moved backward, reject */
			ret = -ETIME;
			goto out;
		}
	}

	if (likely(pkt_id == pr->id + 1)) {
		/* well-formed ID sequence (incremented by 1) */
		pr->base = REPLAY_INDEX(pr->base, -1, pr->window_size);
		__set_bit(pr->base, pr->history);
		if (pr->extent < pr->window_size)
			++pr->extent;
		pr->id = pkt_id;
	} else if (pkt_id > pr->id) {
		/* ID jumped forward by more than one */
		const unsigned int delta = pkt_id - pr->id;

		if (delta < pr->window_size) {
			pr->base = REPLAY_INDEX(pr->base, -delta,
						pr->window_size);
			__set_bit(pr->base, pr->history);
			pr->extent += delta;
			if (pr->extent > pr->window_size)
				pr->extent = pr->window_size;

			clear_start = REPLAY_INDEX(pr->base, 1,
						   pr->window_size);
			clear_len = delta - 1;
			first = min(clear_len, pr->window_size - clear_start);
			bitmap_clear(pr->history, clear_start, first);
			if (clear_len > first)
				bitmap_clear(pr->history, 0, clear_len - first);
		} else {
			pr->base = 0;
			pr->extent = pr->window_size;
			bitmap_zero(pr->history, pr->window_size);
			__set_bit(0, pr->history);
		}
		pr->id = pkt_id;
	} else {
		/* ID backtrack */
		const unsigned int delta = pr->id - pkt_id;
		unsigned int ri;

		if (delta > pr->max_backtrack)
			pr->max_backtrack = delta;
		if (delta < pr->extent) {
			if (pkt_id > pr->id_floor) {
				ri = REPLAY_INDEX(pr->base, delta,
						  pr->window_size);

				if (__test_and_set_bit(ri, pr->history)) {
					ret = -EINVAL;
					goto out;
				}
			} else {
				ret = -EINVAL;
				goto out;
			}
		} else {
			ret = -EINVAL;
			goto out;
		}
	}

	pr->expire = now + PKTID_RECV_EXPIRE;
	ret = 0;
out:
	spin_unlock_bh(&pr->lock);
	return ret;
}

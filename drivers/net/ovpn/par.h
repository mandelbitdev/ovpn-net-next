/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2026 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_PAR_H_
#define _NET_OVPN_PAR_H_

#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/workqueue.h>

struct ovpn_peer;
struct sk_buff;

/**
 * struct ovpn_par_queue - per-peer queue delivering parallel jobs in order
 * @lock: protects the jobs list, their done flags and the kicked flag
 * @jobs: jobs in submission order, until delivered
 * @peer: the peer embedding the queue
 * @inflight: jobs submitted and not delivered yet
 * @kicked: whether the delivery work is queued or running
 * @cpu: CPU that submitted the last job, where the delivery work runs
 * @work: delivery work
 */
struct ovpn_par_queue {
	spinlock_t lock; /* protects jobs, their done flags and kicked */
	struct list_head jobs;
	struct ovpn_peer *peer;
	atomic_t inflight;
	bool kicked;
	int cpu;
	struct work_struct work;
};

void ovpn_par_queue_init(struct ovpn_par_queue *q, struct ovpn_peer *peer);
bool ovpn_rx_par_enabled(void);
bool ovpn_rx_par_dispatch(struct ovpn_peer *peer, struct sk_buff *list,
			  unsigned int bytes);
int ovpn_par_init(void);
void ovpn_par_exit(void);

#endif /* _NET_OVPN_PAR_H_ */

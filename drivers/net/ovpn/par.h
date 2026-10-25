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
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "crypto.h"
#include "pktid.h"

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

/**
 * struct ovpn_tx_ctx - transmit job being encrypted by a worker
 * @peer: peer the job transmits to
 * @ks: key slot the packet IDs were reserved from, referenced by the job
 * @next: next reserved packet ID
 * @end: first packet ID after the reserved range
 * @head: encrypted outputs collected for in-order transmission
 * @tail: where the next collected output is linked
 * @task: the worker running the job
 * @sender_cpu: XPS source CPU of the outputs, the CPU that submitted the job
 *
 * Installed only while a worker runs a job in task context with BHs
 * disabled. Interrupts ignore it, and so does any other task that could run
 * on that CPU where BH-disabled sections are preemptible.
 */
struct ovpn_tx_ctx {
	struct ovpn_peer *peer;
	struct ovpn_crypto_key_slot *ks;
	u32 next;
	u32 end;
	struct sk_buff *head;
	struct sk_buff **tail;
	struct task_struct *task;
	unsigned int sender_cpu;
};

DECLARE_PER_CPU(struct ovpn_tx_ctx *, ovpn_tx_ctx_cur);

static inline struct ovpn_tx_ctx *ovpn_tx_ctx_current(void)
{
	struct ovpn_tx_ctx *ctx;

	if (!in_task())
		return NULL;

	/* not preempted between reading the context and checking its owner */
	guard(preempt)();
	ctx = this_cpu_read(ovpn_tx_ctx_cur);
	return ctx && ctx->task == current ? ctx : NULL;
}

/**
 * ovpn_tx_pktid_next - get the packet ID for an outgoing packet
 * @ks: the key slot encrypting the packet
 * @pktid: the packet ID
 *
 * Packets of a parallel transmit job use the IDs reserved when the job was
 * submitted, so that the wire order matches the packet ID order.
 *
 * Return: 0 on success or -ERANGE when the packet ID space is exhausted
 */
static inline int ovpn_tx_pktid_next(struct ovpn_crypto_key_slot *ks,
				     u32 *pktid)
{
	struct ovpn_tx_ctx *ctx = ovpn_tx_ctx_current();

	if (ctx && ctx->ks == ks && ctx->next != ctx->end) {
		*pktid = ctx->next++;
		return 0;
	}

	return ovpn_pktid_xmit_next(&ks->pid_xmit, pktid);
}

/**
 * ovpn_tx_pktid_range - get consecutive packet IDs for outgoing packets
 * @ks: the key slot encrypting the packets
 * @count: number of packet IDs
 * @pktid: the first packet ID
 *
 * Like ovpn_tx_pktid_next(), for a range.
 *
 * Return: 0 on success or -ERANGE when the packet ID space is exhausted
 */
static inline int ovpn_tx_pktid_range(struct ovpn_crypto_key_slot *ks,
				      unsigned int count, u32 *pktid)
{
	struct ovpn_tx_ctx *ctx = ovpn_tx_ctx_current();

	if (ctx && ctx->ks == ks && ctx->end - ctx->next >= count) {
		*pktid = ctx->next;
		ctx->next += count;
		return 0;
	}

	return ovpn_pktid_xmit_range(&ks->pid_xmit, count, pktid);
}

void ovpn_par_queue_init(struct ovpn_par_queue *q, struct ovpn_peer *peer);
bool ovpn_rx_par_enabled(void);
bool ovpn_rx_par_dispatch(struct ovpn_peer *peer, struct sk_buff *list,
			  unsigned int bytes);
bool ovpn_tx_par_dispatch(struct ovpn_peer *peer, struct sk_buff *skb);
bool ovpn_tx_par_collect(struct ovpn_peer *peer,
			 struct ovpn_crypto_key_slot *ks, struct sk_buff *skb,
			 unsigned int packets);
int ovpn_par_init(void);
void ovpn_par_exit(void);

#endif /* _NET_OVPN_PAR_H_ */

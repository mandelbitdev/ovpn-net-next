/* SPDX-License-Identifier: GPL-2.0-only */
/* OpenVPN data channel offload
 *
 *  Copyright (C) 2026 OpenVPN, Inc.
 *
 *  Author:	Ralf Lici <ralf@mandelbit.com>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_QUEUE_H_
#define _NET_OVPN_QUEUE_H_

#include <linux/atomic.h>
#include <linux/skbuff.h>
#include <linux/types.h>

/**
 * struct ovpn_ordered_queue - lockless per-peer ordered MPSC queue
 * @stub: sentinel node
 * @head: producer-side head pointer
 * @tail: consumer-side tail pointer
 * @peeked: packet currently observed by consumer but not yet consumed
 * @count: queue length
 */
struct ovpn_ordered_queue {
	struct sk_buff stub;
	struct sk_buff *head;
	struct sk_buff *tail;
	struct sk_buff *peeked;
	atomic_t count;
};

void ovpn_ordered_queue_init(struct ovpn_ordered_queue *queue);
bool ovpn_ordered_queue_enqueue(struct ovpn_ordered_queue *queue,
				struct sk_buff *skb, unsigned int max_len);
static inline bool
ovpn_ordered_queue_empty(const struct ovpn_ordered_queue *queue)
{
	return !READ_ONCE(queue->peeked) && !atomic_read(&queue->count);
}
struct sk_buff *ovpn_ordered_queue_dequeue(struct ovpn_ordered_queue *queue);
struct sk_buff *ovpn_ordered_queue_peek(struct ovpn_ordered_queue *queue);
void ovpn_ordered_queue_drop_peeked(struct ovpn_ordered_queue *queue);

#endif /* _NET_OVPN_QUEUE_H_ */

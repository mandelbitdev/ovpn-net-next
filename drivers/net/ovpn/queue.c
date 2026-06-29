// SPDX-License-Identifier: GPL-2.0
/* OpenVPN data channel offload
 *
 *  Copyright (C) 2026 OpenVPN, Inc.
 *
 *  Author:	Ralf Lici <ralf@mandelbit.com>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include <linux/compiler_types.h>
#include <linux/stddef.h>

#include "queue.h"

/* skb->prev is used as the private single-linked queue pointer but it actually
 * encodes the next skb from the queue user standpoint
 */
#define OVPN_ORDERED_NEXT(skb) ((skb)->prev)

/**
 * ovpn_ordered_queue_init - initialize an ordered skb queue
 * @queue: queue to initialize
 */
void ovpn_ordered_queue_init(struct ovpn_ordered_queue *queue)
{
	WRITE_ONCE(OVPN_ORDERED_NEXT(&queue->stub), NULL);
	queue->head = &queue->stub;
	queue->tail = &queue->stub;
	queue->peeked = NULL;
	atomic_set(&queue->count, 0);
}

static void ovpn_ordered_queue_enqueue_node(struct ovpn_ordered_queue *queue,
					    struct sk_buff *skb)
{
	struct sk_buff *old;

	/* enqueue with release semantics (MPSC) */
	skb_mark_not_on_list(skb);
	WRITE_ONCE(OVPN_ORDERED_NEXT(skb), NULL);
	old = xchg(&queue->head, skb);
	/* pairs with dequeue smp_load_acquire() */
	smp_store_release(&OVPN_ORDERED_NEXT(old), skb);
}

/**
 * ovpn_ordered_queue_enqueue - enqueue an skb preserving producer order
 * @queue: queue where the skb should be stored
 * @skb: skb to enqueue
 * @max_len: maximum queue length
 *
 * Return: true if the skb was queued or false if @max_len was reached.
 */
bool ovpn_ordered_queue_enqueue(struct ovpn_ordered_queue *queue,
				struct sk_buff *skb, unsigned int max_len)
{
	if (unlikely(!atomic_add_unless(&queue->count, 1, max_len)))
		return false;

	ovpn_ordered_queue_enqueue_node(queue, skb);
	return true;
}

/**
 * ovpn_ordered_queue_dequeue - remove the oldest skb from the queue
 * @queue: queue to dequeue from
 *
 * Return: the oldest queued skb, or NULL if no skb is currently available.
 * NULL can also mean a producer is still publishing the next link.
 */
struct sk_buff *ovpn_ordered_queue_dequeue(struct ovpn_ordered_queue *queue)
{
	struct sk_buff *tail = queue->tail;
	struct sk_buff *next;

	/* pairs with smp_store_release in ovpn_ordered_queue_enqueue* */
	next = smp_load_acquire(&OVPN_ORDERED_NEXT(tail));

	/* the consumer is at the beginning of the queue */
	if (tail == &queue->stub) {
		/* queue is empty */
		if (!next)
			return NULL;

		queue->tail = next;
		tail = next;
		/* pairs with enqueue-node smp_store_release() */
		next = smp_load_acquire(&OVPN_ORDERED_NEXT(next));
	}

	/* consume tail and advance the consumer pointer when the next skb is
	 * already visible
	 */
	if (next) {
		queue->tail = next;
		atomic_dec(&queue->count);
		WRITE_ONCE(OVPN_ORDERED_NEXT(tail), NULL);
		return tail;
	}

	/* a producer moved head but has not published tail->prev yet: retry */
	if (tail != READ_ONCE(queue->head))
		return NULL;

	/* Re-arm the stub exactly like a normal enqueue.
	 * This must clear STUB->next first, otherwise stale linkage can keep
	 * old nodes reachable and trigger double-free paths.
	 */
	ovpn_ordered_queue_enqueue_node(queue, &queue->stub);
	/* pairs with enqueue-node smp_store_release() */
	next = smp_load_acquire(&OVPN_ORDERED_NEXT(tail));
	if (next) {
		queue->tail = next;
		atomic_dec(&queue->count);
		WRITE_ONCE(OVPN_ORDERED_NEXT(tail), NULL);
		return tail;
	}

	return NULL;
}

/**
 * ovpn_ordered_queue_peek - read the oldest skb without consuming it
 * @queue: queue to peek from
 *
 * Return: the oldest queued skb, or NULL if no skb is currently available.
 */
struct sk_buff *ovpn_ordered_queue_peek(struct ovpn_ordered_queue *queue)
{
	if (queue->peeked)
		return queue->peeked;

	queue->peeked = ovpn_ordered_queue_dequeue(queue);
	return queue->peeked;
}

/**
 * ovpn_ordered_queue_drop_peeked - mark the peeked skb as consumed
 * @queue: queue whose peeked skb should be consumed
 */
void ovpn_ordered_queue_drop_peeked(struct ovpn_ordered_queue *queue)
{
	queue->peeked = NULL;
}

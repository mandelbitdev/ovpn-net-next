// SPDX-License-Identifier: GPL-2.0-only
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2026 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

/* Ordered parallel crypto: large received batches and transmitted packets
 * of a peer become jobs processed by per-CPU workers. Each peer queue then
 * delivers its jobs in submission order, from a work running on the CPU that
 * submitted them.
 */

#include <linux/llist.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "ovpnpriv.h"
#include "io.h"
#include "peer.h"
#include "par.h"
#include "skb.h"
#include "stats.h"

/* EXPERIMENTAL: CPUs processing jobs, 0 keeps the work in the calling
 * context. Clearing a mask while jobs are queued lets new work overtake them.
 */
static unsigned long rx_par_cpus;
module_param(rx_par_cpus, ulong, 0644);
MODULE_PARM_DESC(rx_par_cpus, "bitmask of CPUs decrypting received batches");

static unsigned long tx_par_cpus;
module_param(tx_par_cpus, ulong, 0644);
MODULE_PARM_DESC(tx_par_cpus, "bitmask of CPUs encrypting transmitted packets");

/* EXPERIMENTAL: smaller work stays in the calling context, unless earlier
 * work of the same peer is still queued
 */
static unsigned int rx_par_min_bytes = 16384;
module_param(rx_par_min_bytes, uint, 0644);
MODULE_PARM_DESC(rx_par_min_bytes, "minimum bytes in a parallel RX batch");

static unsigned int tx_par_min_bytes = 16384;
module_param(tx_par_min_bytes, uint, 0644);
MODULE_PARM_DESC(tx_par_min_bytes, "minimum bytes in a parallel TX job");

/* EXPERIMENTAL: parallel TX lowers throughput on TCP transport, as the
 * receiver pays more per record
 */
static bool tx_par_tcp;
module_param(tx_par_tcp, bool, 0644);
MODULE_PARM_DESC(tx_par_tcp, "encrypt in parallel for TCP transport peers too");

/**
 * struct ovpn_par_job - work processed by a worker and delivered in order
 * @node: entry in the queue of the worker processing the job
 * @list: entry in the peer queue ordering delivery
 * @q: the peer queue the job belongs to
 * @skbs: RX: records to decrypt, then records to deliver;
 *	  TX: packet to encrypt, then encrypted outputs to send
 * @ks: TX: key slot the packet IDs were reserved from, or NULL
 * @pktid: TX: first reserved packet ID
 * @npkt: TX: number of reserved packet IDs
 * @cpu: TX: the CPU that submitted the job
 * @tx: whether this is a transmit job
 * @done: whether processing completed, protected by the queue lock
 */
struct ovpn_par_job {
	struct llist_node node;
	struct list_head list;
	struct ovpn_par_queue *q;
	struct sk_buff *skbs;
	struct ovpn_crypto_key_slot *ks;
	u32 pktid;
	u32 npkt;
	int cpu;
	bool tx;
	bool done;
};

/* per-CPU worker: jobs waiting to be processed and the work draining them */
struct ovpn_par_worker {
	struct llist_head jobs;
	struct work_struct work;
};

DEFINE_PER_CPU(struct ovpn_tx_ctx *, ovpn_tx_ctx_cur);
static DEFINE_PER_CPU(struct ovpn_par_worker, ovpn_par_workers);
static DEFINE_PER_CPU(unsigned int, ovpn_par_last_cpu);
static struct workqueue_struct *ovpn_par_wq;
static struct kmem_cache *ovpn_par_job_cache;

static void ovpn_par_deliver_work(struct work_struct *work);

/**
 * ovpn_par_queue_init - initialize a peer queue
 * @q: the queue
 * @peer: the peer embedding the queue
 */
void ovpn_par_queue_init(struct ovpn_par_queue *q, struct ovpn_peer *peer)
{
	spin_lock_init(&q->lock);
	INIT_LIST_HEAD(&q->jobs);
	q->peer = peer;
	atomic_set(&q->inflight, 0);
	q->kicked = false;
	q->cpu = 0;
	INIT_WORK(&q->work, ovpn_par_deliver_work);
}

/**
 * ovpn_rx_par_enabled - check whether received records may be decrypted by
 *			 workers
 *
 * Return: true if parallel decryption is enabled
 */
bool ovpn_rx_par_enabled(void)
{
	return READ_ONCE(rx_par_cpus) != 0;
}

static void ovpn_rx_job_run(struct ovpn_par_job *job)
{
	struct sk_buff *skb, *next, *head = NULL, **tail = &head;
	int ret;

	skb_list_walk_safe(job->skbs, skb, next) {
		skb_mark_not_on_list(skb);

		/* each record carries its own peer reference */
		ret = ovpn_recv_decrypt(job->q->peer, skb, false);

		/* a pending record is completed by the crypto callback and
		 * may be gone already
		 */
		if (ret == OVPN_RECV_CONSUMED || ret == -EINPROGRESS)
			continue;

		ovpn_skb_cb(skb)->rx_ret = ret;
		*tail = skb;
		tail = &skb->next;
	}

	job->skbs = head;
}

static void ovpn_tx_job_run(struct ovpn_par_job *job)
{
	struct ovpn_tx_ctx ctx = {
		.peer = job->q->peer,
		.ks = job->ks,
		.next = job->pktid,
		.end = job->pktid + job->npkt,
		.task = current,
		.sender_cpu = job->cpu + 1,
	};

	ctx.tail = &ctx.head;

	/* the transmit path expects BHs disabled, which also keeps anything
	 * else on this CPU from seeing the context
	 */
	local_bh_disable();
	this_cpu_write(ovpn_tx_ctx_cur, &ctx);
	ovpn_xmit_peer(job->q->peer, job->skbs);
	this_cpu_write(ovpn_tx_ctx_cur, NULL);
	local_bh_enable();

	job->skbs = ctx.head;
	if (job->ks)
		ovpn_crypto_key_slot_put(job->ks);
}

/**
 * ovpn_tx_par_collect - keep an encrypted output for in-order transmission
 * @peer: the peer the output is sent to, its reference is passed on success
 * @ks: the key slot used, its reference is passed on success
 * @skb: the encrypted output
 * @packets: number of packets accounted for the output
 *
 * Return: true if the output was collected by the running transmit job
 */
bool ovpn_tx_par_collect(struct ovpn_peer *peer,
			 struct ovpn_crypto_key_slot *ks, struct sk_buff *skb,
			 unsigned int packets)
{
	struct ovpn_tx_ctx *ctx = ovpn_tx_ctx_current();

	if (!ctx || ctx->peer != peer)
		return false;

	skb_mark_not_on_list(skb);
	ovpn_skb_cb(skb)->peer = peer;
	ovpn_skb_cb(skb)->ks = ks;
	ovpn_skb_cb(skb)->tcp_packets = packets;
#ifdef CONFIG_XPS
	/* keep the outer flow on the TX queue the inline path would use */
	skb->sender_cpu = ctx->sender_cpu;
#endif
	*ctx->tail = skb;
	ctx->tail = &skb->next;

	return true;
}

static void ovpn_par_job_deliver(struct ovpn_par_job *job)
{
	struct sk_buff *skb, *next;

	/* BHs disabled as in the inline paths: TX sends under the socket
	 * lock, RX gro_cells run when BHs are enabled again, before the next
	 * job is delivered
	 */
	local_bh_disable();
	if (!job->tx)
		ovpn_rx_batch_begin(job->q->peer);
	skb_list_walk_safe(job->skbs, skb, next) {
		skb_mark_not_on_list(skb);
		if (job->tx)
			ovpn_encrypt_send_deferred(skb);
		else
			ovpn_decrypt_post(skb, ovpn_skb_cb(skb)->rx_ret);
	}
	if (!job->tx)
		ovpn_rx_batch_end();
	local_bh_enable();
}

/* Deliver the completed jobs at the head of the queue, in order. Called and
 * returns with q->lock held, dropped while each job is delivered: jobs
 * completed meanwhile are picked up by the next iteration. The caller
 * releases one peer reference per delivered job, once it no longer needs the
 * queue.
 */
static unsigned int ovpn_par_deliver_ready(struct ovpn_par_queue *q)
{
	struct ovpn_par_job *job;
	unsigned int n = 0;

	while ((job = list_first_entry_or_null(&q->jobs, struct ovpn_par_job,
					       list)) && job->done) {
		list_del(&job->list);
		spin_unlock_bh(&q->lock);

		ovpn_par_job_deliver(job);
		atomic_dec(&q->inflight);
		kmem_cache_free(ovpn_par_job_cache, job);
		n++;

		spin_lock_bh(&q->lock);
	}

	return n;
}

static void ovpn_par_deliver_work(struct work_struct *work)
{
	struct ovpn_par_queue *q = container_of(work, struct ovpn_par_queue,
						work);
	struct ovpn_peer *peer = q->peer;
	unsigned int puts;

	spin_lock_bh(&q->lock);
	puts = ovpn_par_deliver_ready(q);
	/* cleared under the lock that also covers marking a job done, so a
	 * job completed after the last check kicks the work again
	 */
	q->kicked = false;
	spin_unlock_bh(&q->lock);

	/* job references, then the one taken when the work was kicked */
	while (puts--)
		ovpn_peer_put(peer);
	ovpn_peer_put(peer);
}

/* Workers never deliver: a worker delivering the jobs of the others would
 * stall the ones queued to it, and through the ordering every other worker.
 */
static void ovpn_par_job_complete(struct ovpn_par_job *job)
{
	struct ovpn_par_queue *q = job->q;
	bool kick;

	spin_lock_bh(&q->lock);
	job->done = true;

	/* kick the delivery once the head is ready. The reference of this
	 * job, still queued, keeps the peer alive while the work takes its own
	 */
	kick = !q->kicked &&
	       list_first_entry(&q->jobs, struct ovpn_par_job, list)->done &&
	       !WARN_ON_ONCE(!ovpn_peer_hold(q->peer));
	if (kick)
		q->kicked = true;
	spin_unlock_bh(&q->lock);

	if (kick && !queue_work_on(READ_ONCE(q->cpu), ovpn_par_wq, &q->work))
		ovpn_peer_put(q->peer);
}

static void ovpn_par_work(struct work_struct *work)
{
	struct ovpn_par_worker *w = container_of(work, struct ovpn_par_worker,
						 work);
	struct ovpn_par_job *job, *tmp;
	struct llist_node *n;

	n = llist_reverse_order(llist_del_all(&w->jobs));
	llist_for_each_entry_safe(job, tmp, n, node) {
		if (job->tx)
			ovpn_tx_job_run(job);
		else
			ovpn_rx_job_run(job);
		ovpn_par_job_complete(job);
		cond_resched();
	}
}

/* round-robin over the online CPUs of the mask */
static int ovpn_par_pick_cpu(unsigned long mask)
{
	unsigned int cpu = this_cpu_read(ovpn_par_last_cpu), i;

	for (i = 0; i < BITS_PER_LONG; i++) {
		cpu = find_next_bit(&mask, BITS_PER_LONG, cpu + 1);
		if (cpu >= BITS_PER_LONG)
			cpu = find_first_bit(&mask, BITS_PER_LONG);
		if (cpu >= BITS_PER_LONG)
			return -1;
		if (cpu < nr_cpu_ids && cpu_online(cpu)) {
			this_cpu_write(ovpn_par_last_cpu, cpu);
			return cpu;
		}
		__clear_bit(cpu, &mask);
	}

	return -1;
}

static struct ovpn_par_job *ovpn_par_job_alloc(struct ovpn_par_queue *q,
					       unsigned long mask, int *cpu)
{
	struct ovpn_par_job *job;

	*cpu = ovpn_par_pick_cpu(mask);
	if (*cpu < 0)
		return NULL;

	job = kmem_cache_alloc(ovpn_par_job_cache, GFP_ATOMIC);
	if (unlikely(!job))
		return NULL;

	/* released when the job is delivered */
	if (unlikely(!ovpn_peer_hold(q->peer))) {
		kmem_cache_free(ovpn_par_job_cache, job);
		return NULL;
	}

	job->q = q;
	job->ks = NULL;
	job->pktid = 0;
	job->npkt = 0;
	job->done = false;

	return job;
}

/* called with q->lock held, released on return */
static void ovpn_par_job_submit(struct ovpn_par_job *job, int cpu)
{
	struct ovpn_par_worker *w = per_cpu_ptr(&ovpn_par_workers, cpu);
	struct ovpn_par_queue *q = job->q;

	WRITE_ONCE(q->cpu, smp_processor_id());
	atomic_inc(&q->inflight);
	list_add_tail(&job->list, &q->jobs);
	spin_unlock_bh(&q->lock);

	if (llist_add(&job->node, &w->jobs))
		queue_work_on(cpu, ovpn_par_wq, &w->work);
}

/**
 * ovpn_rx_par_dispatch - queue received records for parallel decryption
 * @peer: the peer the records were received from
 * @list: the records, each owning a reference to @peer
 * @bytes: total length of the records
 *
 * Return: true if the records were consumed, false if the caller still owns
 * them and has to process them itself
 */
bool ovpn_rx_par_dispatch(struct ovpn_peer *peer, struct sk_buff *list,
			  unsigned int bytes)
{
	unsigned long mask = READ_ONCE(rx_par_cpus);
	struct ovpn_par_queue *q = &peer->rx_par;
	struct ovpn_par_job *job;
	int cpu;

	if (!mask)
		return false;

	if (bytes < READ_ONCE(rx_par_min_bytes) && !atomic_read(&q->inflight))
		return false;

	job = ovpn_par_job_alloc(q, mask, &cpu);
	if (unlikely(!job)) {
		struct sk_buff *skb, *next;

		if (!atomic_read(&q->inflight))
			return false;

		/* processing here would overtake earlier queued records */
		skb_list_walk_safe(list, skb, next) {
			skb_mark_not_on_list(skb);
			ovpn_dev_dstats_rx_dropped(peer->ovpn->dev);
			kfree_skb(skb);
			ovpn_peer_put(peer);
		}
		return true;
	}

	job->skbs = list;
	job->tx = false;

	spin_lock_bh(&q->lock);
	ovpn_par_job_submit(job, cpu);

	return true;
}

/**
 * ovpn_tx_par_dispatch - queue a packet for parallel encryption
 * @peer: the peer the packet is sent to, its reference is passed on success
 * @skb: the packet
 *
 * Return: true if the packet was consumed, false if the caller still owns it
 * and the peer reference
 */
bool ovpn_tx_par_dispatch(struct ovpn_peer *peer, struct sk_buff *skb)
{
	unsigned long mask = READ_ONCE(tx_par_cpus);
	struct ovpn_par_queue *q = &peer->tx_par;
	struct ovpn_crypto_key_slot *ks;
	struct ovpn_par_job *job;
	unsigned int npkt;
	int cpu;

	if (!mask)
		return false;

	/* packets behind queued jobs follow them, whatever their size or
	 * transport, so that none overtakes, also after tx_par_tcp is cleared
	 */
	if ((!skb_is_gso(skb) || skb->len < READ_ONCE(tx_par_min_bytes) ||
	     (!READ_ONCE(tx_par_tcp) && ovpn_peer_uses_tcp(peer))) &&
	    !atomic_read(&q->inflight))
		return false;

	job = ovpn_par_job_alloc(q, mask, &cpu);
	if (unlikely(!job)) {
		if (!atomic_read(&q->inflight))
			return false;

		/* sending here would overtake earlier queued packets, whose
		 * packet IDs could then fall behind the peer's replay window
		 */
		ovpn_dev_dstats_tx_dropped(peer->ovpn->dev, 1);
		skb_tx_error(skb);
		kfree_skb(skb);
		ovpn_peer_put(peer);
		return true;
	}

	/* the worker consumes the caller's peer reference */
	job->skbs = skb;
	job->tx = true;
	job->cpu = smp_processor_id();
	npkt = ovpn_xmit_records(peer, skb);

	/* Reserve the packet IDs under the queue lock, so that IDs increase
	 * in delivery order. Without a reservation, or for a shortfall, the
	 * worker allocates IDs as usual.
	 */
	spin_lock_bh(&q->lock);
	ks = ovpn_crypto_key_slot_primary(&peer->crypto);
	if (ks && npkt &&
	    !ovpn_pktid_xmit_range(&ks->pid_xmit, npkt, &job->pktid)) {
		job->ks = ks;
		job->npkt = npkt;
	} else if (ks) {
		ovpn_crypto_key_slot_put(ks);
	}
	ovpn_par_job_submit(job, cpu);

	return true;
}

/**
 * ovpn_par_init - allocate the parallel workers
 *
 * Return: 0 on success or a negative error code otherwise
 */
int ovpn_par_init(void)
{
	int cpu;

	ovpn_par_job_cache = KMEM_CACHE(ovpn_par_job, 0);
	if (!ovpn_par_job_cache)
		return -ENOMEM;

	ovpn_par_wq = alloc_workqueue("ovpn_par", WQ_PERCPU | WQ_HIGHPRI, 0);
	if (!ovpn_par_wq) {
		kmem_cache_destroy(ovpn_par_job_cache);
		return -ENOMEM;
	}

	for_each_possible_cpu(cpu) {
		struct ovpn_par_worker *w = per_cpu_ptr(&ovpn_par_workers, cpu);

		init_llist_head(&w->jobs);
		INIT_WORK(&w->work, ovpn_par_work);
	}

	return 0;
}

/**
 * ovpn_par_exit - release the parallel workers
 *
 * Called once every device is unregistered, so no job is left: a job holds
 * its peer and the peer its device. Works may still be returning.
 */
void ovpn_par_exit(void)
{
	destroy_workqueue(ovpn_par_wq);
	ovpn_par_wq = NULL;
	kmem_cache_destroy(ovpn_par_job_cache);
}

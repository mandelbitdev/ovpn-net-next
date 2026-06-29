// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2019-2025 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include <crypto/aead.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/math64.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/ratelimit.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/timekeeping.h>
#include <net/gso.h>
#include <net/ip.h>

#include "ovpnpriv.h"
#include "peer.h"
#include "io.h"
#include "bind.h"
#include "crypto.h"
#include "crypto_aead.h"
#include "netlink.h"
#include "proto.h"
#include "queue.h"
#include "tcp.h"
#include "udp.h"
#include "skb.h"
#include "socket.h"

#define OVPN_RING_LEN 4096
#define OVPN_QUEUE_LEN 4096

const unsigned char ovpn_keepalive_message[OVPN_KEEPALIVE_SIZE] = {
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

static void ovpn_pkt_state_set(struct sk_buff *skb,
			       enum ovpn_pkt_state new_state)
{
	/* pairs with pkt_state acquire loads in per-peer poll */
	smp_store_release(&ovpn_skb_cb(skb)->pkt_state, new_state);
}

static void ovpn_pkt_complete_and_schedule(struct sk_buff *skb,
					   struct napi_struct *napi,
					   enum ovpn_pkt_state new_state)
{
	bool schedule;

	/* keep the split NAPI claim, state publish and NAPI queueing in
	 * BH-disabled context because once the terminal state is visible, poll
	 * may consume skb, so napi must already have been claimed
	 */
	local_bh_disable();
	schedule = napi_schedule_prep(napi);
	ovpn_pkt_state_set(skb, new_state);
	if (schedule)
		__napi_schedule(napi);
	local_bh_enable();
}

static int ovpn_cpumask_next_online(int *last_cpu)
{
	int cpu = cpumask_next(READ_ONCE(*last_cpu), cpu_online_mask);

	if (cpu >= nr_cpu_ids)
		cpu = cpumask_first(cpu_online_mask);
	WRITE_ONCE(*last_cpu, cpu);

	return cpu;
}

static void ovpn_rx_worker_kick(struct ovpn_priv *ovpn)
{
	struct ovpn_rx_worker *worker;
	int cpu;

	cpu = ovpn_cpumask_next_online(&ovpn->rx_queue.last_cpu);
	worker = per_cpu_ptr(ovpn->rx_queue.worker, cpu);
	queue_work_on(cpu, ovpn->rx_wq, &worker->work);
}

/* send skb to connected peer in current context */
static bool ovpn_encrypt_xmit(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_socket *sock;
	bool sent = false;

	rcu_read_lock();
	sock = rcu_dereference(peer->sock);
	if (unlikely(!sock))
		goto out;

	switch (sock->sk->sk_protocol) {
	case IPPROTO_UDP:
		ovpn_udp_send_skb(peer, sock->sk, skb);
		sent = true;
		break;
	case IPPROTO_TCP:
		ovpn_tcp_send_skb(peer, sock->sk, skb);
		sent = true;
		break;
	default:
		break;
	}

out:
	rcu_read_unlock();
	return sent;
}

static int ovpn_peer_tx_poll(struct napi_struct *napi, int budget)
{
	struct ovpn_peer *peer = container_of(napi, struct ovpn_peer, tx_napi);
	enum ovpn_pkt_state pkt_state;
	unsigned int orig_len;
	struct sk_buff *skb;
	int work_done = 0;

	for (;;) {
		if (work_done >= budget)
			break;

		skb = ovpn_ordered_queue_peek(&peer->tx_queue);
		if (!skb)
			break;

		/* pairs with pkt_state release stores from TX completions */
		pkt_state = smp_load_acquire(&ovpn_skb_cb(skb)->pkt_state);
		if (pkt_state == OVPN_PKT_PENDING ||
		    pkt_state == OVPN_PKT_PROCESSING)
			break;

		ovpn_ordered_queue_drop_peeked(&peer->tx_queue);

		if (likely(pkt_state == OVPN_PKT_READY)) {
			orig_len = skb->len;

			if (likely(ovpn_encrypt_xmit(peer, skb))) {
				ovpn_peer_stats_increment_tx(&peer->link_stats,
							     orig_len);
				WRITE_ONCE(peer->last_sent,
					   ktime_get_real_seconds());
				skb = NULL;
			}
		}

		if (unlikely(skb)) {
			dev_dstats_tx_dropped(peer->ovpn->dev);
			kfree_skb(skb);
		}

		ovpn_peer_put(peer);
		work_done++;
		/* peer removal waits for this consumer to empty the queue */
		if (unlikely(ovpn_ordered_queue_empty(&peer->tx_queue)) &&
		    wq_has_sleeper(&peer->drain_wait))
			wake_up(&peer->drain_wait);
	}

	if (work_done < budget)
		napi_complete_done(napi, work_done);

	return work_done;
}
/**
 * ovpn_is_keepalive - check if skb contains a keepalive message
 * @skb: packet to check
 *
 * Assumes that the first byte of skb->data is defined.
 *
 * Return: true if skb contains a keepalive or false otherwise
 */
static bool ovpn_is_keepalive(struct sk_buff *skb)
{
	if (*skb->data != ovpn_keepalive_message[0])
		return false;

	if (skb->len != OVPN_KEEPALIVE_SIZE)
		return false;

	if (!pskb_may_pull(skb, OVPN_KEEPALIVE_SIZE))
		return false;

	return !memcmp(skb->data, ovpn_keepalive_message, OVPN_KEEPALIVE_SIZE);
}

/* Called after decrypt to write the IP packet to the device.
 * This method is expected to manage/free the skb.
 */
static void ovpn_netdev_write_napi(struct ovpn_peer *peer,
				   struct napi_struct *napi,
				   struct sk_buff *skb)
{
	unsigned int pkt_len;

	/*
	 * GSO state from the transport layer is not valid for the tunnel/data
	 * path. Reset all GSO fields to prevent any further GSO processing
	 * from entering an inconsistent state.
	 */
	skb_gso_reset(skb);

	/* we can't guarantee the packet wasn't corrupted before entering the
	 * VPN, therefore we give other layers a chance to check that
	 */
	skb->ip_summed = CHECKSUM_NONE;

	/* skb hash for transport packet no longer valid after decapsulation */
	skb_clear_hash(skb);

	/* post-decrypt scrub -- prepare to inject encapsulated packet onto the
	 * interface, based on __skb_tunnel_rx() in dst.h
	 */
	skb->dev = peer->ovpn->dev;
	skb_set_queue_mapping(skb, 0);
	skb_scrub_packet(skb, true);

	/* network header reset in ovpn_decrypt_finalize_napi() */
	skb_reset_mac_header(skb);
	skb_reset_transport_header(skb);
	skb_reset_inner_headers(skb);

	/* cause packet to be "received" by the interface */
	pkt_len = skb->len;
	/* caller runs from NAPI poll context, so GRO and device stats already
	 * run with BH disabled
	 */
	napi_gro_receive(napi, skb);
	/* update RX stats with the size of decrypted packet */
	ovpn_peer_stats_increment_rx(&peer->vpn_stats, pkt_len);
	dev_dstats_rx_add(peer->ovpn->dev, pkt_len);
}

static void ovpn_decrypt_finalize_napi(struct ovpn_peer *peer,
				       struct napi_struct *napi,
				       struct sk_buff *skb)
{
	unsigned int payload_offset = ovpn_skb_cb(skb)->payload_offset;
	struct ovpn_crypto_key_slot *ks = ovpn_skb_cb(skb)->ks;
	struct ovpn_socket *sock;
	__be16 proto;
	__be32 *pid;
	int ret;

	/* PID sits after the op */
	pid = (__force __be32 *)(skb->data + OVPN_OPCODE_SIZE);
	ret = ovpn_pktid_recv(&ks->pid_recv, ntohl(*pid), 0);
	if (unlikely(ret < 0)) {
		net_err_ratelimited("%s: PKT ID RX error for peer %u: %d\n",
				    netdev_name(peer->ovpn->dev), peer->id,
				    ret);
		goto drop;
	}

	/* keep track of last received authenticated packet for keepalive */
	WRITE_ONCE(peer->last_recv, ktime_get_real_seconds());

	rcu_read_lock();
	sock = rcu_dereference(peer->sock);
	if (sock && sock->sk->sk_protocol == IPPROTO_UDP)
		/* check if this peer changed local or remote endpoint */
		ovpn_peer_endpoints_update(peer, skb);
	rcu_read_unlock();

	/* point to encapsulated IP packet */
	__skb_pull(skb, payload_offset);

	/* check if this is a valid datapacket that has to be delivered to the
	 * ovpn interface
	 */
	skb_reset_network_header(skb);
	proto = ovpn_ip_check_protocol(skb);
	if (unlikely(!proto)) {
		/* check if null packet */
		if (unlikely(!pskb_may_pull(skb, 1))) {
			net_info_ratelimited("%s: NULL packet received from peer %u\n",
					     netdev_name(peer->ovpn->dev),
					     peer->id);
			goto drop;
		}

		if (ovpn_is_keepalive(skb)) {
			net_dbg_ratelimited("%s: ping received from peer %u\n",
					    netdev_name(peer->ovpn->dev),
					    peer->id);
			/* we drop the packet, but this is not a failure */
			consume_skb(skb);
			goto drop_nocount;
		}

		net_info_ratelimited("%s: unsupported protocol received from peer %u\n",
				     netdev_name(peer->ovpn->dev), peer->id);
		goto drop;
	}
	skb->protocol = proto;

	/* perform Reverse Path Filtering (RPF) */
	if (unlikely(!ovpn_peer_check_by_src(peer->ovpn, skb, peer))) {
		if (skb->protocol == htons(ETH_P_IPV6))
			net_dbg_ratelimited("%s: RPF dropped packet from peer %u, src: %pI6c\n",
					    netdev_name(peer->ovpn->dev),
					    peer->id, &ipv6_hdr(skb)->saddr);
		else
			net_dbg_ratelimited("%s: RPF dropped packet from peer %u, src: %pI4\n",
					    netdev_name(peer->ovpn->dev),
					    peer->id, &ip_hdr(skb)->saddr);
		goto drop;
	}

	ovpn_netdev_write_napi(peer, napi, skb);
	/* skb is passed to upper layer - don't free it */
	skb = NULL;
drop:
	if (unlikely(skb))
		ovpn_dev_dstats_rx_dropped(peer->ovpn->dev);
	kfree_skb(skb);
drop_nocount:
	ovpn_peer_put(peer);
	ovpn_crypto_key_slot_put(ks);
}

void ovpn_decrypt_post(void *data, int ret)
{
	struct sk_buff *skb = data;
	struct ovpn_peer *peer;
	struct ovpn_cb *cb;

	/* crypto is happening asynchronously. this function will be called
	 * again later by the crypto callback with a proper return code.
	 * With MAY_BACKLOG, -EBUSY is also a queued/pending outcome.
	 */
	if (unlikely(ret == -EINPROGRESS || ret == -EBUSY))
		return;

	/* crypto is done, cleanup skb CB and its members */
	cb = ovpn_skb_cb(skb);
	peer = cb->peer;
	kfree(cb->crypto_tmp);

	ovpn_pkt_complete_and_schedule(skb, &peer->rx_napi,
				       ret < 0 ? OVPN_PKT_DEAD :
						 OVPN_PKT_READY);
}

static int ovpn_peer_rx_poll(struct napi_struct *napi, int budget)
{
	struct ovpn_peer *peer = container_of(napi, struct ovpn_peer, rx_napi);
	struct ovpn_crypto_key_slot *ks;
	enum ovpn_pkt_state pkt_state;
	struct ovpn_peer *skb_peer;
	int work_done = 0;
	struct sk_buff *skb;
	struct ovpn_cb *cb;

	for (;;) {
		if (work_done >= budget)
			break;

		skb = ovpn_ordered_queue_peek(&peer->rx_queue);
		if (!skb)
			break;

		cb = ovpn_skb_cb(skb);
		/* pairs with pkt_state release stores from RX completions */
		pkt_state = smp_load_acquire(&cb->pkt_state);
		if (pkt_state == OVPN_PKT_PENDING ||
		    pkt_state == OVPN_PKT_PROCESSING)
			break;

		ovpn_ordered_queue_drop_peeked(&peer->rx_queue);
		/* peer removal waits for this consumer to empty the queue */
		if (unlikely(ovpn_ordered_queue_empty(&peer->rx_queue)) &&
		    wq_has_sleeper(&peer->drain_wait))
			wake_up(&peer->drain_wait);

		if (likely(pkt_state == OVPN_PKT_READY)) {
			ovpn_decrypt_finalize_napi(peer, napi, skb);
		} else {
			skb_peer = cb->peer;
			ks = cb->ks;
			ovpn_dev_dstats_rx_dropped(peer->ovpn->dev);
			kfree_skb(skb);
			ovpn_peer_put(skb_peer);
			if (ks)
				ovpn_crypto_key_slot_put(ks);
		}
		work_done++;
	}

	if (work_done < budget)
		napi_complete_done(napi, work_done);

	return work_done;
}

static void ovpn_tx_worker_kick(struct ovpn_priv *ovpn)
{
	struct ovpn_tx_worker *worker;
	int cpu;

	cpu = ovpn_cpumask_next_online(&ovpn->tx_queue.last_cpu);
	worker = per_cpu_ptr(ovpn->tx_queue.worker, cpu);
	queue_work_on(cpu, ovpn->tx_wq, &worker->work);
}

static bool ovpn_encrypt_one(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_cb *cb = ovpn_skb_cb(skb);

	/* take a reference to the peer because the crypto code may run async.
	 * ovpn_encrypt_post() will release it upon completion
	 */
	if (unlikely(!ovpn_peer_hold(peer))) {
		DEBUG_NET_WARN_ON_ONCE(1);
		return false;
	}

	/* keep queue bookkeeping stable while worker/completion drain run
	 * concurrently
	 */
	cb->crypto_tmp = NULL;
	WRITE_ONCE(cb->pkt_state, OVPN_PKT_PROCESSING);
	ovpn_encrypt_post(skb, ovpn_aead_encrypt(peer, cb->ks, skb));
	return true;
}

static void ovpn_tx_worker(struct work_struct *work)
{
	const struct ovpn_tx_worker *worker;
	struct ovpn_priv *ovpn;
	struct ovpn_peer *peer;
	struct sk_buff *curr;
	struct ovpn_cb *cb;

	worker = container_of(work, struct ovpn_tx_worker, work);
	ovpn = worker->ovpn;

	while ((curr = ptr_ring_consume_bh(&ovpn->tx_queue.ring)) != NULL) {
		peer = ovpn_skb_cb(curr)->peer;

		if (unlikely(!ovpn_encrypt_one(peer, curr))) {
			cb = ovpn_skb_cb(curr);
			ovpn_crypto_key_slot_put(cb->ks);
			cb->ks = NULL;
			ovpn_pkt_complete_and_schedule(curr, &peer->tx_napi,
						       OVPN_PKT_DEAD);
			continue;
		}

		if (need_resched())
			cond_resched();
	}
}

static int ovpn_peer_rx_enqueue(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_priv *ovpn = peer->ovpn;
	struct ovpn_cb *cb = ovpn_skb_cb(skb);

	memset(cb, 0, sizeof(*cb));
	cb->peer = peer;
	/* publish RX queue ownership before workers can observe this skb */
	smp_store_release(&cb->pkt_state, OVPN_PKT_PENDING);

	/* enqueue in per-peer order first; consumer waits for state changes */
	if (unlikely(!ovpn_ordered_queue_enqueue(&peer->rx_queue, skb,
						 OVPN_QUEUE_LEN)))
		return -ENOSPC;

	if (unlikely(ptr_ring_produce_bh(&ovpn->rx_queue.ring, skb))) {
		ovpn_pkt_complete_and_schedule(skb, &peer->rx_napi,
					       OVPN_PKT_DEAD);
		return 0;
	}

	ovpn_rx_worker_kick(ovpn);
	return 0;
}

/* RX path entry point: queue packet for decryption and device delivery */
void ovpn_recv_defer(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_priv *ovpn = peer->ovpn;
	int ret;

	ovpn_peer_stats_increment_rx(&peer->link_stats, skb->len);
	ret = ovpn_peer_rx_enqueue(peer, skb);
	if (unlikely(ret))
		goto drop;
	return;

drop:
	ovpn_dev_dstats_rx_dropped(ovpn->dev);
	kfree_skb(skb);
	ovpn_peer_put(peer);
}

void ovpn_encrypt_post(void *data, int ret)
{
	struct ovpn_crypto_key_slot *ks;
	struct sk_buff *skb = data;
	struct ovpn_peer *peer;
	struct ovpn_cb *cb;

	cb = ovpn_skb_cb(skb);

	/* encryption is happening asynchronously. This function will be
	 * called later by the crypto callback with a proper return value.
	 * With MAY_BACKLOG, -EBUSY is also a queued/pending outcome.
	 */
	if (unlikely(ret == -EINPROGRESS || ret == -EBUSY))
		return;

	ks = cb->ks;
	peer = cb->peer;

	/* crypto is done, cleanup skb CB and its members */
	kfree(cb->crypto_tmp);

	if (unlikely(ret == -ERANGE)) {
		/* we ran out of IVs and we must kill the key as it can't be
		 * use anymore
		 */
		netdev_warn(peer->ovpn->dev,
			    "killing key %u for peer %u\n", ks->key_id,
			    peer->id);
		if (ovpn_crypto_kill_key(&peer->crypto, ks->key_id))
			/* let userspace know so that a new key must be
			 * negotiated
			 */
			ovpn_nl_key_swap_notify(peer, ks->key_id);
	}

	ovpn_pkt_complete_and_schedule(skb, &peer->tx_napi,
				       ret < 0 ? OVPN_PKT_DEAD :
						 OVPN_PKT_READY);

	/* avoid completion-side kick churn when stage-2 ring is idle */
	if (unlikely(!ptr_ring_empty_bh(&peer->ovpn->tx_queue.ring)))
		ovpn_tx_worker_kick(peer->ovpn);

	ovpn_peer_put(peer);
	ovpn_crypto_key_slot_put(ks);
}

static void ovpn_rx_worker(struct work_struct *work)
{
	const struct ovpn_rx_worker *worker;
	struct ovpn_crypto_key_slot *ks;
	struct ovpn_priv *ovpn;
	struct ovpn_peer *peer;
	struct sk_buff *skb;
	u8 key_id;

	worker = container_of(work, struct ovpn_rx_worker, work);
	ovpn = worker->ovpn;

	while ((skb = ptr_ring_consume_bh(&ovpn->rx_queue.ring)) != NULL) {
		peer = ovpn_skb_cb(skb)->peer;

		/* get the key slot matching the key ID in the received
		 * packet
		 */
		key_id = ovpn_key_id_from_skb(skb);

		ks = ovpn_crypto_key_id_to_slot(&peer->crypto, key_id);
		if (unlikely(!ks)) {
			net_info_ratelimited("%s: no available key for peer %u, key-id: %u\n",
					     netdev_name(peer->ovpn->dev),
					     peer->id, key_id);
			ovpn_pkt_complete_and_schedule(skb, &peer->rx_napi,
						       OVPN_PKT_DEAD);
			continue;
		}

		ovpn_pkt_state_set(skb, OVPN_PKT_PROCESSING);
		ovpn_decrypt_post(skb, ovpn_aead_decrypt(peer, ks, skb));
		if (need_resched())
			cond_resched();
	}
}

static void ovpn_tx_ring_cleanup_cb(void *ptr)
{
	/* the ring is non-owning: every pending skb is also linked in the
	 * owning peer queue, which must be empty before device TX teardown
	 */
	DEBUG_NET_WARN_ON_ONCE(1);
}

static void ovpn_rx_ring_cleanup_cb(void *ptr)
{
	/* the ring is non-owning: every pending skb is also linked in the
	 * owning peer queue, which must be empty before device RX teardown
	 */
	DEBUG_NET_WARN_ON_ONCE(1);
}

int ovpn_rx_init(struct ovpn_priv *ovpn)
{
	struct ovpn_rx_worker *worker;
	int ret, cpu;

	ovpn->rx_wq = alloc_workqueue("ovpn-rx-%s",
				      WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 0,
				      netdev_name(ovpn->dev));
	if (!ovpn->rx_wq)
		return -ENOMEM;

	ret = ptr_ring_init(&ovpn->rx_queue.ring, OVPN_RING_LEN, GFP_KERNEL);
	if (ret < 0)
		goto err_destroy_wq;

	ovpn->rx_queue.worker = alloc_percpu(struct ovpn_rx_worker);
	if (!ovpn->rx_queue.worker) {
		ret = -ENOMEM;
		goto err_cleanup_ring;
	}

	for_each_possible_cpu(cpu) {
		worker = per_cpu_ptr(ovpn->rx_queue.worker, cpu);
		INIT_WORK(&worker->work, ovpn_rx_worker);
		worker->ovpn = ovpn;
	}
	ovpn->rx_queue.last_cpu = -1;

	return 0;

err_cleanup_ring:
	ptr_ring_cleanup(&ovpn->rx_queue.ring, NULL);
err_destroy_wq:
	destroy_workqueue(ovpn->rx_wq);
	ovpn->rx_wq = NULL;

	return ret;
}

void ovpn_rx_uninit(struct ovpn_priv *ovpn)
{
	if (ovpn->rx_wq) {
		destroy_workqueue(ovpn->rx_wq);
		ovpn->rx_wq = NULL;
	}

	if (ovpn->rx_queue.worker) {
		free_percpu(ovpn->rx_queue.worker);
		ovpn->rx_queue.worker = NULL;
	}

	ptr_ring_cleanup(&ovpn->rx_queue.ring, ovpn_rx_ring_cleanup_cb);
}

int ovpn_tx_init(struct ovpn_priv *ovpn)
{
	struct ovpn_tx_worker *worker;
	int ret, cpu;

	ovpn->tx_wq = alloc_workqueue("ovpn-tx-%s",
				      WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM |
				      WQ_HIGHPRI,
				      0, netdev_name(ovpn->dev));
	if (!ovpn->tx_wq)
		return -ENOMEM;

	ret = ptr_ring_init(&ovpn->tx_queue.ring, OVPN_RING_LEN, GFP_KERNEL);
	if (ret < 0)
		goto err_destroy_wq;

	ovpn->tx_queue.worker = alloc_percpu(struct ovpn_tx_worker);
	if (!ovpn->tx_queue.worker) {
		ret = -ENOMEM;
		goto err_cleanup_ring;
	}

	for_each_possible_cpu(cpu) {
		worker = per_cpu_ptr(ovpn->tx_queue.worker, cpu);
		INIT_WORK(&worker->work, ovpn_tx_worker);
		worker->ovpn = ovpn;
	}
	ovpn->tx_queue.last_cpu = -1;

	return 0;

err_cleanup_ring:
	ptr_ring_cleanup(&ovpn->tx_queue.ring, NULL);
err_destroy_wq:
	destroy_workqueue(ovpn->tx_wq);
	ovpn->tx_wq = NULL;
	return ret;
}

void ovpn_tx_uninit(struct ovpn_priv *ovpn)
{
	if (ovpn->tx_wq) {
		destroy_workqueue(ovpn->tx_wq);
		ovpn->tx_wq = NULL;
	}

	if (ovpn->tx_queue.worker) {
		free_percpu(ovpn->tx_queue.worker);
		ovpn->tx_queue.worker = NULL;
	}

	ptr_ring_cleanup(&ovpn->tx_queue.ring, ovpn_tx_ring_cleanup_cb);
}

void ovpn_peer_tx_init(struct ovpn_peer *peer)
{
	ovpn_ordered_queue_init(&peer->tx_queue);
	netif_napi_add(peer->ovpn->dev, &peer->tx_napi, ovpn_peer_tx_poll);
	napi_enable(&peer->tx_napi);
}

void ovpn_peer_rx_init(struct ovpn_peer *peer)
{
	ovpn_ordered_queue_init(&peer->rx_queue);
	netif_napi_add(peer->ovpn->dev, &peer->rx_napi, ovpn_peer_rx_poll);
	napi_enable(&peer->rx_napi);
}

void ovpn_peer_rx_stop(struct ovpn_peer *peer, bool netdev_locked)
{
	/* producers are quiesced before this point; NAPI owns queue draining */
	wait_event(peer->drain_wait, ovpn_ordered_queue_empty(&peer->rx_queue));

	if (netdev_locked) {
		napi_disable_locked(&peer->rx_napi);
		__netif_napi_del_locked(&peer->rx_napi);
	} else {
		napi_disable(&peer->rx_napi);
		__netif_napi_del(&peer->rx_napi);
	}
}

void ovpn_peer_tx_stop(struct ovpn_peer *peer, bool netdev_locked)
{
	/* producers are quiesced before this point; NAPI owns queue draining */
	wait_event(peer->drain_wait, ovpn_ordered_queue_empty(&peer->tx_queue));

	if (netdev_locked) {
		napi_disable_locked(&peer->tx_napi);
		__netif_napi_del_locked(&peer->tx_napi);
	} else {
		napi_disable(&peer->tx_napi);
		__netif_napi_del(&peer->tx_napi);
	}
}

static void ovpn_peer_tx_enqueue(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_crypto_key_slot *ks;
	struct sk_buff *curr, *next;
	bool kick_worker = false;
	struct ovpn_priv *ovpn;
	struct ovpn_cb *cb;
	u32 pktid;

	ovpn = peer->ovpn;

	skb_list_walk_safe(skb, curr, next) {
		/* Per-skb queueing: detach from original skb chain before
		 * enqueueing, otherwise tx_drain() may walk stale next links.
		 */
		skb_mark_not_on_list(curr);

		/* finalize inner checksum before encryption if the stack
		 * handed us a partial checksum skb
		 */
		if (unlikely(curr->ip_summed == CHECKSUM_PARTIAL &&
			     skb_checksum_help(curr)))
			goto drop_curr;

		/* bind key slot + packet ID in stage-1 enqueue order */
		ks = ovpn_crypto_key_slot_primary(&peer->crypto);
		if (unlikely(!ks))
			goto drop_curr;

		if (unlikely(ovpn_pktid_xmit_next(&ks->pid_xmit, &pktid) < 0)) {
			ovpn_crypto_key_slot_put(ks);
			goto drop_curr;
		}

		cb = ovpn_skb_cb(curr);
		memset(cb, 0, sizeof(*cb));
		cb->peer = peer;
		cb->ks = ks;
		cb->tx_pktid = pktid;
		WRITE_ONCE(cb->pkt_state, OVPN_PKT_PENDING);

		if (unlikely(!ovpn_peer_hold(peer))) {
			ovpn_crypto_key_slot_put(ks);
			goto drop_curr;
		}

		if (unlikely(!ovpn_ordered_queue_enqueue(&peer->tx_queue, curr,
							 OVPN_QUEUE_LEN))) {
			ovpn_crypto_key_slot_put(ks);
			ovpn_peer_put(peer);
			dev_dstats_tx_dropped(ovpn->dev);
			kfree_skb(curr);
			continue;
		}

		if (unlikely(ptr_ring_produce_bh(&ovpn->tx_queue.ring, curr))) {
			ovpn_crypto_key_slot_put(ks);
			cb->ks = NULL;
			ovpn_pkt_complete_and_schedule(curr, &peer->tx_napi,
						       OVPN_PKT_DEAD);
			continue;
		}

		kick_worker = true;
		continue;

drop_curr:
		dev_dstats_tx_dropped(peer->ovpn->dev);
		kfree_skb(curr);
	}

	if (kick_worker)
		ovpn_tx_worker_kick(ovpn);

	/* this consumes the reference passed by the caller */
	ovpn_peer_put(peer);
}

/* Send user data to the network
 */
netdev_tx_t ovpn_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ovpn_priv *ovpn = netdev_priv(dev);
	struct sk_buff *segments, *curr, *next;
	struct sk_buff_head skb_list;
	unsigned int tx_bytes = 0;
	struct ovpn_peer *peer;
	__be16 proto;
	int ret;

	/* reset netfilter state */
	nf_reset_ct(skb);

	/* verify IP header size in network packet */
	proto = ovpn_ip_check_protocol(skb);
	if (unlikely(!proto || skb->protocol != proto))
		goto drop_no_peer;

	/* retrieve peer serving the destination IP of this packet */
	peer = ovpn_peer_get_by_dst(ovpn, skb);
	if (unlikely(!peer)) {
		switch (skb->protocol) {
		case htons(ETH_P_IP):
			net_dbg_ratelimited("%s: no peer to send data to dst=%pI4\n",
					    netdev_name(ovpn->dev),
					    &ip_hdr(skb)->daddr);
			break;
		case htons(ETH_P_IPV6):
			net_dbg_ratelimited("%s: no peer to send data to dst=%pI6c\n",
					    netdev_name(ovpn->dev),
					    &ipv6_hdr(skb)->daddr);
			break;
		}
		goto drop_no_peer;
	}
	/* dst was needed for peer selection - it can now be dropped */
	skb_dst_drop(skb);

	if (skb_is_gso(skb)) {
		segments = skb_gso_segment(skb, 0);
		if (IS_ERR(segments)) {
			ret = PTR_ERR(segments);
			net_err_ratelimited("%s: cannot segment payload packet: %d\n",
					    netdev_name(dev), ret);
			goto drop;
		}

		consume_skb(skb);
		skb = segments;
	}

	/* from this moment on, "skb" might be a list */

	__skb_queue_head_init(&skb_list);
	skb_list_walk_safe(skb, curr, next) {
		skb_mark_not_on_list(curr);

		curr = skb_share_check(curr, GFP_ATOMIC);
		if (unlikely(!curr)) {
			net_err_ratelimited("%s: skb_share_check failed for payload packet\n",
					    netdev_name(dev));
			ovpn_dev_dstats_tx_dropped(ovpn->dev);
			continue;
		}

		/* only count what we actually send */
		tx_bytes += curr->len;
		__skb_queue_tail(&skb_list, curr);
	}

	/* no segments survived: don't jump to 'drop' because we already
	 * incremented the counter for each failure in the loop
	 */
	if (unlikely(skb_queue_empty(&skb_list))) {
		ovpn_peer_put(peer);
		return NETDEV_TX_OK;
	}
	skb_list.prev->next = NULL;

	ovpn_peer_stats_increment_tx(&peer->vpn_stats, tx_bytes);
	ovpn_peer_tx_enqueue(peer, skb_list.next);

	return NETDEV_TX_OK;

drop:
	ovpn_peer_put(peer);
drop_no_peer:
	ovpn_dev_dstats_tx_dropped(ovpn->dev);
	skb_tx_error(skb);
	kfree_skb_list(skb);
	return NETDEV_TX_OK;
}

/**
 * ovpn_xmit_special - encrypt and transmit an out-of-band message to peer
 * @peer: peer to send the message to
 * @data: message content
 * @len: message length
 *
 * Assumes that caller holds a reference to peer, which will be
 * passed to ovpn_peer_tx_enqueue().
 */
void ovpn_xmit_special(struct ovpn_peer *peer, const void *data,
		       const unsigned int len)
{
	struct ovpn_priv *ovpn;
	struct sk_buff *skb;

	ovpn = peer->ovpn;
	if (unlikely(!ovpn)) {
		ovpn_peer_put(peer);
		return;
	}

	skb = alloc_skb(256 + len, GFP_ATOMIC);
	if (unlikely(!skb)) {
		ovpn_peer_put(peer);
		return;
	}

	skb_reserve(skb, 128);
	skb->priority = TC_PRIO_BESTEFFORT;
	__skb_put_data(skb, data, len);

	ovpn_peer_tx_enqueue(peer, skb);
}

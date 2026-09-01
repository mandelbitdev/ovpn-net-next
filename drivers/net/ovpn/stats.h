/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2025 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 *		Lev Stipakov <lev@openvpn.net>
 */

#ifndef _NET_OVPN_OVPNSTATS_H_
#define _NET_OVPN_OVPNSTATS_H_

#include <linux/netdevice.h>

/* one stat */
struct ovpn_peer_stat {
	atomic64_t bytes;
	atomic64_t packets;
};

/* rx and tx stats combined */
struct ovpn_peer_stats {
	struct ovpn_peer_stat rx;
	struct ovpn_peer_stat tx;
};

/**
 * struct ovpn_peer_estats - per-peer drop/event counters
 * @rx_decrypt_errors: packets dropped due to decryption/auth failure
 * @rx_replay_errors: packets dropped by the replay protection check
 * @rx_unknown_keyid: packets dropped due to unknown key ID
 * @rx_unsupported_proto: packets dropped due to unsupported or malformed
 *			  inner protocol
 * @rx_rpf_errors: packets dropped by the reverse path filtering check
 * @tx_encrypt_errors: packets dropped due to encryption failure
 * @tx_iv_exhausted: packets dropped due to packet ID (IV) exhaustion
 * @tx_no_key: packets dropped due to missing primary key
 * @tx_no_transport: packets dropped due to missing transport socket
 * @tx_gso_errors: packets dropped due to GSO segmentation failure
 * @keepalive_rx: keepalive packets received from this peer
 * @keepalive_tx: keepalive packets sent to this peer
 * @floats: number of times the peer endpoint floated
 */
struct ovpn_peer_estats {
	atomic64_t rx_decrypt_errors;
	atomic64_t rx_replay_errors;
	atomic64_t rx_unknown_keyid;
	atomic64_t rx_unsupported_proto;
	atomic64_t rx_rpf_errors;
	atomic64_t tx_encrypt_errors;
	atomic64_t tx_iv_exhausted;
	atomic64_t tx_no_key;
	atomic64_t tx_no_transport;
	atomic64_t tx_gso_errors;
	atomic64_t keepalive_rx;
	atomic64_t keepalive_tx;
	atomic64_t floats;
};

void ovpn_peer_stats_init(struct ovpn_peer_stats *ps);

static inline void ovpn_peer_stats_increment(struct ovpn_peer_stat *stat,
					     const unsigned int n)
{
	atomic64_add(n, &stat->bytes);
	atomic64_inc(&stat->packets);
}

static inline void ovpn_peer_stats_increment_rx(struct ovpn_peer_stats *stats,
						const unsigned int n)
{
	ovpn_peer_stats_increment(&stats->rx, n);
}

static inline void ovpn_peer_stats_increment_tx(struct ovpn_peer_stats *stats,
						const unsigned int n)
{
	ovpn_peer_stats_increment(&stats->tx, n);
}

static inline void ovpn_dev_dstats_tx_dropped(struct net_device *dev)
{
	local_bh_disable();
	dev_dstats_tx_dropped(dev);
	local_bh_enable();
}

static inline void ovpn_dev_dstats_rx_dropped(struct net_device *dev)
{
	local_bh_disable();
	dev_dstats_rx_dropped(dev);
	local_bh_enable();
}

#endif /* _NET_OVPN_OVPNSTATS_H_ */

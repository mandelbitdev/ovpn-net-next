/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2025 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_MAIN_H_
#define _NET_OVPN_MAIN_H_

#include <linux/local_lock.h>

/**
 * struct ovpn_rx_pool - per-CPU pool of pages received records are copied to
 * @bh_lock: serializes the allocations from @pool on its CPU
 * @pool: page pool used by this CPU
 */
struct ovpn_rx_pool {
	local_lock_t bh_lock;
	struct page_pool *pool;
};

extern struct ovpn_rx_pool __percpu *ovpn_rx_pools;

bool ovpn_dev_is_valid(const struct net_device *dev);

#endif /* _NET_OVPN_MAIN_H_ */

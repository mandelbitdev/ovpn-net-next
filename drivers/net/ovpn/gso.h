/* SPDX-License-Identifier: GPL-2.0-only */
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2026 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 *		Ralf Lici <ralf@mandelbit.com>
 */

#ifndef _NET_OVPN_GSO_H_
#define _NET_OVPN_GSO_H_

#include <linux/skbuff.h>

#include "peer.h"

void ovpn_gso_send(struct sk_buff_head *skbs, struct ovpn_peer *peer);
bool ovpn_gso_supported(struct ovpn_peer *peer);

#endif /* _NET_OVPN_GSO_H_ */

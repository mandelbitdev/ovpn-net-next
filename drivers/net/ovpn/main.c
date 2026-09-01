// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2025 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 *		James Yonan <james@openvpn.net>
 */

#include <linux/ethtool.h>
#include <linux/genetlink.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/gro_cells.h>
#include <net/ip.h>
#include <net/rtnetlink.h>
#include <uapi/linux/if_arp.h>

#include "ovpnpriv.h"
#include "main.h"
#include "netlink.h"
#include "io.h"
#include "peer.h"
#include "proto.h"
#include "tcp.h"
#include "udp.h"

static void ovpn_priv_free(struct net_device *net)
{
	struct ovpn_priv *ovpn = netdev_priv(net);

	free_percpu(ovpn->estats);
	kfree(ovpn->peers);
}

static int ovpn_mp_alloc(struct ovpn_priv *ovpn)
{
	int i;

	if (ovpn->mode != OVPN_MODE_MP)
		return 0;

	/* the peer container is fairly large, therefore we allocate it only in
	 * MP mode
	 */
	ovpn->peers = kzalloc_obj(*ovpn->peers);
	if (!ovpn->peers)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(ovpn->peers->by_id); i++) {
		INIT_HLIST_HEAD(&ovpn->peers->by_id[i]);
		INIT_HLIST_NULLS_HEAD(&ovpn->peers->by_vpn_addr4[i], i);
		INIT_HLIST_NULLS_HEAD(&ovpn->peers->by_vpn_addr6[i], i);
		INIT_HLIST_NULLS_HEAD(&ovpn->peers->by_transp_addr[i], i);
	}

	return 0;
}

static int ovpn_net_init(struct net_device *dev)
{
	struct ovpn_priv *ovpn = netdev_priv(dev);
	int err;

	ovpn->estats = netdev_alloc_pcpu_stats(struct ovpn_dev_estats);
	if (!ovpn->estats)
		return -ENOMEM;

	err = gro_cells_init(&ovpn->gro_cells, dev);

	if (err < 0)
		goto err_free_estats;

	err = ovpn_mp_alloc(ovpn);
	if (err < 0) {
		gro_cells_destroy(&ovpn->gro_cells);
		goto err_free_estats;
	}

	return 0;

err_free_estats:
	free_percpu(ovpn->estats);
	ovpn->estats = NULL;
	return err;
}

static void ovpn_net_uninit(struct net_device *dev)
{
	struct ovpn_priv *ovpn = netdev_priv(dev);

	disable_delayed_work_sync(&ovpn->keepalive_work);
	ovpn_peers_free(ovpn, NULL, OVPN_DEL_PEER_REASON_TEARDOWN);
	gro_cells_destroy(&ovpn->gro_cells);
}

static int ovpn_net_open(struct net_device *dev)
{
	struct ovpn_priv *ovpn = netdev_priv(dev);
	struct in_device *dev_v4;

	/* the IPv4 in_device (and thus its config) is recreated whenever the
	 * interface is moved to a new netns, so redirects must be disabled on
	 * every bring-up rather than once at creation time, otherwise the
	 * setting is silently lost after such a move
	 */
	if (ovpn->mode == OVPN_MODE_MP) {
		dev_v4 = __in_dev_get_rtnl(dev);
		if (dev_v4) {
			/* disable redirects as Linux gets confused by ovpn
			 * handling same-LAN routing.
			 * This happens because a multipeer interface is used as
			 * relay point between hosts in the same subnet, while
			 * in a classic LAN this would not be needed because the
			 * two hosts would be able to talk directly.
			 */
			IN_DEV_CONF_SET(dev_v4, SEND_REDIRECTS, false);
			IPV4_DEVCONF_ALL(dev_net(dev), SEND_REDIRECTS) = false;
		}
	}

	return 0;
}

static const struct net_device_ops ovpn_netdev_ops = {
	.ndo_init		= ovpn_net_init,
	.ndo_uninit		= ovpn_net_uninit,
	.ndo_open		= ovpn_net_open,
	.ndo_start_xmit		= ovpn_net_xmit,
};

static const struct device_type ovpn_type = {
	.name = OVPN_FAMILY_NAME,
};

static const struct nla_policy ovpn_policy[IFLA_OVPN_MAX + 1] = {
	[IFLA_OVPN_MODE] = NLA_POLICY_RANGE(NLA_U8, OVPN_MODE_P2P,
					    OVPN_MODE_MP),
};

/**
 * ovpn_dev_is_valid - check if the netdevice is of type 'ovpn'
 * @dev: the interface to check
 *
 * Return: whether the netdevice is of type 'ovpn'
 */
bool ovpn_dev_is_valid(const struct net_device *dev)
{
	return dev->netdev_ops == &ovpn_netdev_ops;
}

static void ovpn_get_drvinfo(struct net_device *dev,
			     struct ethtool_drvinfo *info)
{
	strscpy(info->driver, "ovpn", sizeof(info->driver));
	strscpy(info->bus_info, "ovpn", sizeof(info->bus_info));
}

/**
 * struct ovpn_ethtool_stat - descriptor for one ethtool counter
 * @name: counter name, as shown by ethtool -S
 * @index: index of the counter within struct ovpn_dev_estats
 */
struct ovpn_ethtool_stat {
	const char *name;
	unsigned int index;
};

#define OVPN_ETHTOOL_ESTAT(_counter) \
	{ #_counter, OVPN_PEER_ESTAT_IDX(_counter) }

static const struct ovpn_ethtool_stat ovpn_ethtool_stats[] = {
	OVPN_ETHTOOL_ESTAT(rx_decrypt_errors),
	OVPN_ETHTOOL_ESTAT(rx_replay_errors),
	OVPN_ETHTOOL_ESTAT(rx_unknown_keyid),
	OVPN_ETHTOOL_ESTAT(rx_unsupported_proto),
	OVPN_ETHTOOL_ESTAT(rx_rpf_errors),
	OVPN_ETHTOOL_ESTAT(tx_encrypt_errors),
	OVPN_ETHTOOL_ESTAT(tx_iv_exhausted),
	OVPN_ETHTOOL_ESTAT(tx_no_key),
	OVPN_ETHTOOL_ESTAT(tx_no_transport),
	OVPN_ETHTOOL_ESTAT(tx_gso_errors),
	OVPN_ETHTOOL_ESTAT(keepalive_rx),
	OVPN_ETHTOOL_ESTAT(keepalive_tx),
	OVPN_ETHTOOL_ESTAT(floats),
	/* device-only counters */
	{ "rx_no_peer", OVPN_DEV_ESTAT_RX_NO_PEER },
	{ "tx_no_peer", OVPN_DEV_ESTAT_TX_NO_PEER },
	{ "tx_bad_proto", OVPN_DEV_ESTAT_TX_BAD_PROTO },
};

static void ovpn_get_strings(struct net_device *dev, u32 stringset, u8 *data)
{
	unsigned int i;

	if (stringset != ETH_SS_STATS)
		return;

	for (i = 0; i < ARRAY_SIZE(ovpn_ethtool_stats); i++)
		ethtool_puts(&data, ovpn_ethtool_stats[i].name);
}

static int ovpn_get_sset_count(struct net_device *dev, int sset)
{
	if (sset == ETH_SS_STATS)
		return ARRAY_SIZE(ovpn_ethtool_stats);

	return -EOPNOTSUPP;
}

static void ovpn_get_ethtool_stats(struct net_device *dev,
				   struct ethtool_stats *stats, u64 *data)
{
	struct ovpn_priv *ovpn = netdev_priv(dev);
	struct ovpn_dev_estats *estats;
	const u64_stats_t *counter;
	unsigned int start;
	unsigned int i;
	u64 value;
	int cpu;

	for (i = 0; i < ARRAY_SIZE(ovpn_ethtool_stats); i++) {
		data[i] = 0;
		for_each_possible_cpu(cpu) {
			estats = per_cpu_ptr(ovpn->estats, cpu);
			counter = &estats->counters[ovpn_ethtool_stats[i].index];
			do {
				start = u64_stats_fetch_begin(&estats->syncp);
				value = u64_stats_read(counter);
			} while (u64_stats_fetch_retry(&estats->syncp, start));
			data[i] += value;
		}
	}
}

static const struct ethtool_ops ovpn_ethtool_ops = {
	.get_drvinfo		= ovpn_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_ts_info		= ethtool_op_get_ts_info,
	.get_strings		= ovpn_get_strings,
	.get_sset_count		= ovpn_get_sset_count,
	.get_ethtool_stats	= ovpn_get_ethtool_stats,
};

static void ovpn_setup(struct net_device *dev)
{
	netdev_features_t feat = NETIF_F_SG | NETIF_F_GSO |
				 NETIF_F_GSO_SOFTWARE | NETIF_F_HIGHDMA;

	dev->needs_free_netdev = true;

	dev->pcpu_stat_type = NETDEV_PCPU_STAT_DSTATS;

	dev->ethtool_ops = &ovpn_ethtool_ops;
	dev->netdev_ops = &ovpn_netdev_ops;

	dev->priv_destructor = ovpn_priv_free;

	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->mtu = ETH_DATA_LEN - OVPN_HEAD_ROOM;
	dev->min_mtu = IPV4_MIN_MTU;
	dev->max_mtu = IP_MAX_MTU - OVPN_HEAD_ROOM;

	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP;
	dev->priv_flags |= IFF_NO_QUEUE;
	/* when routing packets to a LAN behind a client, we rely on the
	 * route entry that originally brought the packet into ovpn, so
	 * don't release it
	 */
	netif_keep_dst(dev);

	dev->lltx = true;
	dev->features |= feat;
	dev->hw_features |= feat;
	dev->hw_enc_features |= feat;

	dev->needed_headroom = ALIGN(OVPN_HEAD_ROOM, 4);
	dev->needed_tailroom = OVPN_MAX_PADDING;

	SET_NETDEV_DEVTYPE(dev, &ovpn_type);
}

static int ovpn_newlink(struct net_device *dev,
			struct rtnl_newlink_params *params,
			struct netlink_ext_ack *extack)
{
	struct ovpn_priv *ovpn = netdev_priv(dev);
	struct nlattr **data = params->data;
	enum ovpn_mode mode = OVPN_MODE_P2P;
	int ret;

	if (data && data[IFLA_OVPN_MODE]) {
		mode = nla_get_u8(data[IFLA_OVPN_MODE]);
		netdev_dbg(dev, "setting device mode: %u\n", mode);
	}

	ovpn->dev = dev;
	ovpn->mode = mode;
	spin_lock_init(&ovpn->lock);
	INIT_DELAYED_WORK(&ovpn->keepalive_work, ovpn_peer_keepalive_work);

	/* Set carrier explicitly after registration, this way state is
	 * clearly defined.
	 *
	 * In case of MP interfaces we keep the carrier always on.
	 *
	 * Carrier for P2P interfaces is initially off and it is then
	 * switched on and off when the remote peer is added or deleted.
	 */
	if (ovpn->mode == OVPN_MODE_MP)
		netif_carrier_on(dev);
	else
		netif_carrier_off(dev);

	ret = register_netdevice(dev);
	if (ret < 0)
		return ret;

	return 0;
}

static size_t ovpn_get_size(const struct net_device *dev)
{
	/* IFLA_OVPN_MODE */
	return nla_total_size(sizeof(u8));
}

static int ovpn_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct ovpn_priv *ovpn = netdev_priv(dev);

	if (nla_put_u8(skb, IFLA_OVPN_MODE, ovpn->mode))
		return -EMSGSIZE;

	return 0;
}

static struct rtnl_link_ops ovpn_link_ops = {
	.kind = "ovpn",
	.netns_refund = false,
	.priv_size = sizeof(struct ovpn_priv),
	.setup = ovpn_setup,
	.policy = ovpn_policy,
	.maxtype = IFLA_OVPN_MAX,
	.newlink = ovpn_newlink,
	.get_size = ovpn_get_size,
	.fill_info = ovpn_fill_info,
};

static int __init ovpn_init(void)
{
	int err;

	ovpn_tcp_init();

	err = rtnl_link_register(&ovpn_link_ops);
	if (err) {
		pr_err("ovpn: can't register rtnl link ops: %d\n", err);
		return err;
	}

	err = ovpn_nl_register();
	if (err) {
		pr_err("ovpn: can't register netlink family: %d\n", err);
		goto unreg_rtnl;
	}

	return 0;

unreg_rtnl:
	rtnl_link_unregister(&ovpn_link_ops);
	return err;
}

static __exit void ovpn_cleanup(void)
{
	ovpn_nl_unregister();
	rtnl_link_unregister(&ovpn_link_ops);

	rcu_barrier();
}

module_init(ovpn_init);
module_exit(ovpn_cleanup);

MODULE_DESCRIPTION("OpenVPN data channel offload (ovpn)");
MODULE_AUTHOR("Antonio Quartulli <antonio@openvpn.net>");
MODULE_LICENSE("GPL");

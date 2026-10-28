#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 OpenVPN, Inc.
#
#	Author:	Antonio Quartulli <antonio@openvpn.net>
#
# Test the collect metadata (external) mode of an MP ovpn interface.
#
# Two clients configure the very same VPN addresses (5.5.5.2, fd55::2) and
# connect to the same server interface: peer 1 over an IPv4 underlay and
# peer 2 over an IPv6 underlay. Each client belongs to a different tenant
# and must reach its own tenant LAN, while both LANs use the same address
# space (192.168.0.1, fd66::1).
#
# The server tells tenants apart only by the peer ID carried in the tunnel
# metadata: fib rules match the RX "tun_id" and lwtunnel "encap ip id"
# routes select the TX peer.

#set -x
set -eE

OVPN_UDP_PEERS_FILE=collect_md_peers.txt
OVPN_NUM_PEERS=2

source ./common.sh

ovpn_test_finished=0

ovpn_test_exit() {
	ovpn_cleanup
	modprobe -r ovpn || true

	if [ "${ovpn_test_finished}" -eq 0 ]; then
		ktap_print_totals
	fi
}

ovpn_md_ns() {
	ip netns exec "$@"
}

# print a counter from the "ip -s -j link" output of <ns> <dev> <jq path>
ovpn_md_link_stat() {
	ip -n "${1}" -s -j link show dev "${2}" | jq -r ".[0].stats64.${3}"
}

# print the packet counter of the tc ingress filter with the given pref
ovpn_md_tc_pkts() {
	local filter="[.[] | select(.pref == ${1}) |
		       .options.actions[0].stats.packets // empty] | max // 0"

	ip netns exec ovpn_peer0 tc -s -j filter show dev tun0 ingress | \
		jq -r "${filter}"
}

ovpn_md_check_iface_flags() {
	ovpn_cmd_fail "collect_md is rejected on P2P interface" \
		ovpn_md_ns ovpn_peer0 "${OVPN_CLI}" new_iface tunbad P2P external
	ip -n ovpn_peer0 link del tunbad 2>/dev/null || true

	ovpn_cmd_ok "create collect_md MP interface" \
		ovpn_md_ns ovpn_peer0 "${OVPN_CLI}" new_iface tun0 MP external

	ip netns exec ovpn_peer0 "${OVPN_YNL}" --family rt-link --do getlink \
		--json '{"ifname": "tun0"}' --output-json | \
		jq -e '.linkinfo.data["collect-metadata"]' >/dev/null
}

ovpn_md_setup_underlay() {
	local p

	for p in 0 1 2; do
		ovpn_create_ns "${p}"
	done
	ip netns add ovpn_lan1
	ip netns add ovpn_lan2

	ip link add veth1 netns ovpn_peer0 type veth peer name veth1 \
		netns ovpn_peer1
	ip -n ovpn_peer0 addr add 10.10.1.1/24 dev veth1
	ip -n ovpn_peer1 addr add 10.10.1.2/24 dev veth1

	ip link add veth2 netns ovpn_peer0 type veth peer name veth2 \
		netns ovpn_peer2
	ip -n ovpn_peer0 addr add fd00:0:0:2::1/64 dev veth2 nodad
	ip -n ovpn_peer2 addr add fd00:0:0:2::2/64 dev veth2 nodad

	for p in 1 2; do
		ip -n ovpn_peer0 link set veth${p} up
		ip -n ovpn_peer${p} link set veth${p} up
	done
}

ovpn_md_setup_lans() {
	local t

	# two tenant LANs sharing the same address space, attached to the
	# server via lan1 and lan2
	for t in 1 2; do
		ip link add lan${t} netns ovpn_peer0 type veth peer name eth0 \
			netns ovpn_lan${t}
		ip -n ovpn_peer0 addr add 192.168.0.254/24 dev lan${t}
		ip -n ovpn_peer0 addr add fd66::fe/64 dev lan${t} nodad
		ip -n ovpn_peer0 link set lan${t} up

		ip -n ovpn_lan${t} addr add 192.168.0.1/24 dev eth0
		ip -n ovpn_lan${t} addr add fd66::1/64 dev eth0 nodad
		ip -n ovpn_lan${t} link set eth0 up
		ip -n ovpn_lan${t} route add default via 192.168.0.254
		ip -n ovpn_lan${t} -6 route add default via fd66::fe
	done
}

ovpn_md_setup_server() {
	local s t

	ip -n ovpn_peer0 link set tun0 up

	for s in net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 \
		 net.ipv4.conf.all.rp_filter=0 \
		 net.ipv4.conf.default.rp_filter=0; do
		ip netns exec ovpn_peer0 sysctl -qw "${s}"
	done
	for t in tun0 lan1 lan2; do
		ip netns exec ovpn_peer0 sysctl -qw \
			net.ipv4.conf.${t}.rp_filter=0
	done

	ovpn_cmd_ok "create collect_md peers" \
		ovpn_md_ns ovpn_peer0 "${OVPN_CLI}" new_multi_peer tun0 1 \
			ASYMM "${OVPN_UDP_PEERS_FILE}"
	for t in 1 2; do
		ovpn_cmd_ok "install server key for peer ${t}" \
			ovpn_md_ns ovpn_peer0 "${OVPN_CLI}" new_key tun0 \
				"${t}" 1 0 "${OVPN_ALG}" 0 data64.key
	done

	# per-tenant routing: RX tun_id -> tenant table, tenant table ->
	# TX tun_id for the overlapping client address
	for t in 1 2; do
		ip -n ovpn_peer0 rule add pref $((100 + t)) iif tun0 \
			tun_id ${t} lookup $((100 + t))
		ip -n ovpn_peer0 rule add pref $((110 + t)) iif lan${t} \
			lookup $((100 + t))
		ip -n ovpn_peer0 -6 rule add pref $((100 + t)) iif tun0 \
			tun_id ${t} lookup $((100 + t))
		ip -n ovpn_peer0 -6 rule add pref $((110 + t)) iif lan${t} \
			lookup $((100 + t))

		ip -n ovpn_peer0 route add 192.168.0.0/24 dev lan${t} \
			table $((100 + t))
		ip -n ovpn_peer0 route add 5.5.5.2/32 encap ip id ${t} \
			dev tun0 table $((100 + t))
		ip -n ovpn_peer0 -6 route add fd66::/64 dev lan${t} \
			table $((100 + t))
		ip -n ovpn_peer0 -6 route add fd55::2/128 encap ip6 id ${t} \
			dev tun0 table $((100 + t))
	done

	# per-peer RX metadata counters (all filters continue, so that every
	# packet hits all of them)
	ip netns exec ovpn_peer0 tc qdisc add dev tun0 clsact
	for t in 1 2; do
		ip netns exec ovpn_peer0 tc filter add dev tun0 ingress \
			pref ${t} protocol all flower enc_key_id ${t} \
			action continue
	done
	ip netns exec ovpn_peer0 tc filter add dev tun0 ingress pref 3 \
		protocol ip flower enc_key_id 1 src_ip 6.6.6.6 action continue
}

ovpn_md_setup_clients() {
	local p raddr

	for p in 1 2; do
		if [ ${p} -eq 1 ]; then
			raddr=10.10.1.1
		else
			raddr=fd00:0:0:2::1
		fi

		ovpn_cmd_ok "create client ${p} interface" \
			ovpn_md_ns ovpn_peer${p} "${OVPN_CLI}" new_iface \
				tun${p} P2P
		# both clients use the very same VPN addresses
		ip -n ovpn_peer${p} addr add 5.5.5.2/24 dev tun${p}
		ip -n ovpn_peer${p} addr add fd55::2/64 dev tun${p} nodad
		ip -n ovpn_peer${p} link set tun${p} up
		ip -n ovpn_peer${p} route add 192.168.0.0/24 dev tun${p}
		ip -n ovpn_peer${p} -6 route add fd66::/64 dev tun${p}

		ovpn_cmd_ok "create client ${p} peer" \
			ovpn_md_ns ovpn_peer${p} "${OVPN_CLI}" new_peer \
				tun${p} $((p + 9)) ${p} 1 ${raddr} 1
		ovpn_cmd_ok "install client ${p} key" \
			ovpn_md_ns ovpn_peer${p} "${OVPN_CLI}" new_key \
				tun${p} $((p + 9)) 1 0 "${OVPN_ALG}" 1 data64.key
	done
}

ovpn_md_prepare_network() {
	ovpn_md_setup_underlay
	ovpn_md_check_iface_flags
	ovpn_md_setup_lans
	ovpn_md_setup_server
	ovpn_md_setup_clients
}

ovpn_md_reject_vpn_ip() {
	ovpn_cmd_fail "VPN IP is rejected in collect_md mode" \
		ovpn_md_ns ovpn_peer0 "${OVPN_CLI}" new_peer tun0 3 13 1000 \
			10.10.1.2 1 5.5.5.9
}

# ping from client <p> to <dst> and check that only lan<p> forwarded it
ovpn_md_tenant_ping() {
	local p="$1"
	local dst="$2"
	local other=$((3 - p))
	local mine_before mine_after other_before other_after

	mine_before=$(ovpn_md_link_stat ovpn_peer0 lan${p} tx.packets)
	other_before=$(ovpn_md_link_stat ovpn_peer0 lan${other} tx.packets)

	ovpn_md_ns ovpn_peer${p} ping -qc 10 -i 0.1 -w 5 "${dst}"

	mine_after=$(ovpn_md_link_stat ovpn_peer0 lan${p} tx.packets)
	other_after=$(ovpn_md_link_stat ovpn_peer0 lan${other} tx.packets)

	if [ $((mine_after - mine_before)) -lt 10 ]; then
		printf 'tenant %s: expected >= 10 packets on lan%s, got %s\n' \
			"${p}" "${p}" $((mine_after - mine_before))
		return 1
	fi
	# allow for unrelated neighbour discovery noise on the other LAN
	if [ $((other_after - other_before)) -gt 2 ]; then
		printf 'tenant %s: leaked %s packets to lan%s\n' "${p}" \
			$((other_after - other_before)) "${other}"
		return 1
	fi
}

ovpn_md_overlap_traffic() {
	local p

	for p in 1 2; do
		ovpn_md_tenant_ping ${p} 192.168.0.1
		ovpn_md_tenant_ping ${p} fd66::1
	done
}

ovpn_md_rx_metadata() {
	local p pkts

	# every echo request above was received with the peer ID as tun_id
	for p in 1 2; do
		pkts=$(ovpn_md_tc_pkts ${p})
		if [ "${pkts}" -lt 20 ]; then
			printf 'enc_key_id %s matched %s packets, expected >= 20\n' \
				"${p}" "${pkts}"
			return 1
		fi
	done
}

ovpn_md_no_rpf() {
	local pkts

	# a source address never configured on the server side is still
	# delivered (no RPF) and is tagged with the right peer ID
	ip -n ovpn_peer1 addr add 6.6.6.6/32 dev tun1
	ovpn_md_ns ovpn_peer1 ping -qc 3 -i 0.1 -W 1 -I 6.6.6.6 \
		192.168.0.1 >/dev/null 2>&1 || true

	pkts=$(ovpn_md_tc_pkts 3)
	if [ "${pkts}" -lt 3 ]; then
		printf 'spoofed source matched %s packets, expected >= 3\n' \
			"${pkts}"
		return 1
	fi
}

# send traffic over a route with the given encap arguments and check
# that it is dropped by tun0 for lack of a valid peer
ovpn_md_tx_drop() {
	local prefix="$1"
	local before after

	shift
	ip -n ovpn_peer0 route add "${prefix}.0/24" "$@" dev tun0

	before=$(ovpn_md_link_stat ovpn_peer0 tun0 tx.dropped)
	ovpn_md_ns ovpn_peer0 ping -qc 3 -i 0.1 -W 1 "${prefix}.1" \
		>/dev/null 2>&1 || true
	after=$(ovpn_md_link_stat ovpn_peer0 tun0 tx.dropped)

	if [ $((after - before)) -lt 3 ]; then
		printf 'route %s/24 %s: expected >= 3 TX drops, got %s\n' \
			"${prefix}.0" "$*" $((after - before))
		return 1
	fi
}

ovpn_md_tx_invalid() {
	# no metadata at all
	ovpn_md_tx_drop 10.99.0
	# metadata pointing to a non-existing peer
	ovpn_md_tx_drop 10.98.0 encap ip id 3
	# tun_id not fitting a peer ID (must not be truncated to peer 0/1)
	ovpn_md_tx_drop 10.97.0 encap ip id $(( (1 << 24) + 1 ))
}

ovpn_md_del_ntf_stats() {
	local json pkts

	ovpn_setup_listener 0
	sleep 1
	ovpn_cmd_ok "delete peer 1" \
		ovpn_md_ns ovpn_peer0 "${OVPN_CLI}" del_peer tun0 1
	sleep 1
	json="${OVPN_TMP_JSONS[0]}"
	ovpn_stop_listener 0 1

	# the deletion notification carries the final counters of the peer
	pkts=$(jq -s '[.[] | select(.name == "peer-del-ntf" and
			.msg.peer.id == 1)][0].msg.peer["vpn-rx-packets"] // 0' \
		"${json}")
	rm -f "${json}"
	if [ "${pkts}" -lt 20 ]; then
		printf 'peer-del-ntf reported %s VPN RX packets, expected >= 20\n' \
			"${pkts}"
		return 1
	fi
}

trap ovpn_test_exit EXIT
trap ovpn_stage_err ERR

ktap_print_header
ktap_set_plan 7

ovpn_cleanup
modprobe -q ovpn || true

ovpn_run_stage "setup overlapping tenants on collect_md interface" \
	ovpn_md_prepare_network
ovpn_run_stage "reject VPN IP for collect_md peer" ovpn_md_reject_vpn_ip
ovpn_run_stage "overlapping tenants reach their own LAN" \
	ovpn_md_overlap_traffic
ovpn_run_stage "RX packets carry peer ID as tun_id" ovpn_md_rx_metadata
ovpn_run_stage "no RPF in collect_md mode" ovpn_md_no_rpf
ovpn_run_stage "drop TX packets without valid peer metadata" \
	ovpn_md_tx_invalid
ovpn_run_stage "peer-del-ntf reports final counters" ovpn_md_del_ntf_stats

ovpn_test_finished=1
ktap_finished

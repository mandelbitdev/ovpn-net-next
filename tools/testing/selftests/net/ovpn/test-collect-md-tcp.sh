#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 OpenVPN, Inc.
#
#	Author:	Antonio Quartulli <antonio@openvpn.net>
#
# Test the collect metadata (external) mode of an MP ovpn interface with TCP
# peers.
#
# Four clients connect to the server over TCP, two over an IPv4 underlay and
# two over an IPv6 one. The server keeps every peer socket in a separate
# "ovpn-cli tcp_peer" process, so that each one can be closed on its own.
# TX on the server is selected by the "encap ip id" of the routes, RX
# packets carry the peer ID as tun_id.

#set -x
set -eE

OVPN_PROTO=TCP
OVPN_NUM_PEERS=4

source ./common.sh

ovpn_test_finished=0

ovpn_test_exit() {
	ovpn_cleanup
	modprobe -r ovpn || true

	if [ "${ovpn_test_finished}" -eq 0 ]; then
		ktap_print_totals
	fi
}

# server peer p has ID p and sends with ID p + 9, the client the other way
# around. Odd clients use IPv4, even ones IPv6.
ovpn_mdt_server_addr() {
	if [ $(($1 % 2)) -eq 1 ]; then
		echo "10.10.${1}.1"
	else
		echo "fd00:0:0:${1}::1"
	fi
}

ovpn_mdt_setup() {
	local p saddr

	for p in $(seq 0 ${OVPN_NUM_PEERS}); do
		ovpn_create_ns "${p}"
	done

	for p in $(seq 1 ${OVPN_NUM_PEERS}); do
		ip link add veth${p} netns ovpn_peer0 type veth peer name \
			veth${p} netns ovpn_peer${p}
		ip -n ovpn_peer0 addr add 10.10.${p}.1/24 dev veth${p}
		ip -n ovpn_peer${p} addr add 10.10.${p}.2/24 dev veth${p}
		ip -n ovpn_peer0 addr add fd00:0:0:${p}::1/64 dev veth${p} \
			nodad
		ip -n ovpn_peer${p} addr add fd00:0:0:${p}::2/64 dev veth${p} \
			nodad
		ip -n ovpn_peer0 link set veth${p} up
		ip -n ovpn_peer${p} link set veth${p} up
	done

	ovpn_cmd_ok "create collect_md MP interface" \
		ip netns exec ovpn_peer0 "${OVPN_CLI}" new_iface tun0 MP external
	ip -n ovpn_peer0 addr add 5.5.5.1/24 dev tun0
	ip -n ovpn_peer0 addr add fd55::1/64 dev tun0 nodad
	ip -n ovpn_peer0 link set tun0 up

	ip netns exec ovpn_peer0 tc qdisc add dev tun0 clsact
	for p in $(seq 1 ${OVPN_NUM_PEERS}); do
		ip netns exec ovpn_peer0 tc filter add dev tun0 ingress \
			pref ${p} protocol all flower enc_key_id ${p} \
			action continue
	done

	ovpn_setup_listener 0
	sleep 1

	for p in $(seq 1 ${OVPN_NUM_PEERS}); do
		saddr=$(ovpn_mdt_server_addr ${p})

		ovpn_tcp_peer_start s${p} ovpn_peer0 tun0 ${p} $((p + 9)) \
			listen :: $((1000 + p))
		ovpn_tcp_peer_reply s${p}
		[ "${OVPN_TP_REPLY}" == "listening" ]

		ovpn_cmd_ok "create client ${p} interface" \
			ip netns exec ovpn_peer${p} "${OVPN_CLI}" new_iface \
				tun${p} P2P
		ip -n ovpn_peer${p} addr add 5.5.5.$((p + 1))/24 dev tun${p}
		ip -n ovpn_peer${p} addr add fd55::$((p + 1))/64 dev tun${p} \
			nodad
		ip -n ovpn_peer${p} link set tun${p} up

		ovpn_tcp_peer_start c${p} ovpn_peer${p} tun${p} $((p + 9)) \
			${p} connect "${saddr}" $((1000 + p))
		ovpn_tcp_peer_reply c${p}
		[ "${OVPN_TP_REPLY}" == "ready" ]
		ovpn_tcp_peer_reply s${p}
		[ "${OVPN_TP_REPLY}" == "ready" ]

		ovpn_cmd_ok "install server key for peer ${p}" \
			ip netns exec ovpn_peer0 "${OVPN_CLI}" new_key tun0 \
				${p} 1 0 "${OVPN_ALG}" 0 data64.key
		ovpn_cmd_ok "install client ${p} key" \
			ip netns exec ovpn_peer${p} "${OVPN_CLI}" new_key \
				tun${p} $((p + 9)) 1 0 "${OVPN_ALG}" 1 data64.key

		ip -n ovpn_peer0 route add 5.5.5.$((p + 1))/32 encap ip id ${p} \
			dev tun0
		ip -n ovpn_peer0 -6 route add fd55::$((p + 1))/128 encap ip6 \
			id ${p} dev tun0
	done
}

ovpn_mdt_peer_get_all() {
	local peers ids

	peers=$(ovpn_peer0_get)
	ovpn_log "${peers}"

	ids=$(jq -s -c '[.[].id] | sort' <<<"${peers}")
	if [ "${ids}" != "[1,2,3,4]" ]; then
		printf 'PEER_GET dump returned peers %s\n' "${ids}"
		return 1
	fi
	# TCP peers report their TX ID and local port, no remote address
	if [ "$(jq -s '[.[] | select(.["tx-id"] != .id + 9 or
			.["local-port"] != .id + 1000 or
			has("remote-ipv4") or has("remote-ipv6"))] | length' \
		<<<"${peers}")" -ne 0 ]; then
		printf 'unexpected peer attributes in %s\n' "${peers}"
		return 1
	fi

	ovpn_peer0_get 3 | jq -e '.id == 3' >/dev/null
}

ovpn_mdt_traffic() {
	local p pkts

	for p in $(seq 1 ${OVPN_NUM_PEERS}); do
		# client -> server and back
		ip netns exec ovpn_peer${p} ping -qc 5 -i 0.1 -w 5 5.5.5.1
		ip netns exec ovpn_peer${p} ping -qc 5 -i 0.1 -w 5 fd55::1
		# server -> client and back, through the encap route
		ip netns exec ovpn_peer0 ping -qc 5 -i 0.1 -w 5 \
			5.5.5.$((p + 1))
		ip netns exec ovpn_peer0 ping -qc 5 -i 0.1 -w 5 \
			fd55::$((p + 1))
		# large packets, spanning several TCP segments
		ip netns exec ovpn_peer0 ping -qc 5 -i 0.1 -s 3000 -w 5 \
			5.5.5.$((p + 1))
	done

	# every packet from client p was tagged with tun_id p
	for p in $(seq 1 ${OVPN_NUM_PEERS}); do
		pkts=$(ovpn_peer0_tc_pkts ${p})
		if [ "${pkts}" -lt 25 ]; then
			printf 'enc_key_id %s matched %s packets, expected >= 25\n' \
				"${p}" "${pkts}"
			return 1
		fi
	done
}

ovpn_mdt_iperf() {
	local iperf_pid

	ovpn_run_bg iperf_pid ip netns exec ovpn_peer0 iperf3 -1 -s
	sleep 1
	ovpn_cmd_ok "iperf client 1 -> server" \
		ip netns exec ovpn_peer1 iperf3 -Z -t 2 -c 5.5.5.1
	wait "${iperf_pid}" || return 1

	ovpn_run_bg iperf_pid ip netns exec ovpn_peer0 iperf3 -1 -s
	sleep 1
	ovpn_cmd_ok "iperf server -> client 2" \
		ip netns exec ovpn_peer2 iperf3 -Z -t 2 -R -c fd55::1
	wait "${iperf_pid}" || return 1
}

# non-DATA_V2 packets reach the userspace owning the socket, both ways
ovpn_mdt_control() {
	local p

	for p in $(seq 1 ${OVPN_NUM_PEERS}); do
		ovpn_tcp_peer_expect c${p} sent send ${p} 200 2000
		ovpn_tcp_peer_expect s${p} "recv ${p} " recv ${p} 2000
		ovpn_tcp_peer_expect s${p} sent send $((p + 100)) 1200 2000
		ovpn_tcp_peer_expect c${p} "recv $((p + 100)) " \
			recv $((p + 100)) 2000
	done
}

# the client closes: the server sees EOF, its peer survives until the
# socket is closed, then it goes with TRANSPORT_DISCONNECT and its final
# counters
ovpn_mdt_client_close() {
	local pkts

	ovpn_tcp_peer_expect c1 closed close
	ovpn_tcp_peer_expect s1 eof eof 3000

	ovpn_peer0_get 1 | jq -e '.id == 1' >/dev/null
	if [ "$(ovpn_peer0_count_del_ntf 1)" -ne 0 ]; then
		echo "peer 1 deleted by the FIN of the client"
		return 1
	fi

	ovpn_tcp_peer_expect s1 closed close
	ovpn_peer0_wait_del_ntf 1 transport-disconnect
	pkts=$(jq -r '.["vpn-rx-packets"] // 0' <<<"${OVPN_DEL_NTF}")
	if [ "${pkts}" -lt 25 ]; then
		printf 'peer-del-ntf reported %s VPN RX packets, expected >= 25\n' \
			"${pkts}"
		return 1
	fi

	ovpn_cmd_fail "peer 1 is gone" ovpn_peer0_get 1
	ovpn_tcp_peer_stop c1
	ovpn_tcp_peer_stop s1
}

# PEER_DEL detaches the socket, which goes back to a plain TCP socket owned
# by userspace: closing it later doesn't notify anything
ovpn_mdt_peer_del() {
	ovpn_cmd_ok "delete peer 2" \
		ip netns exec ovpn_peer0 "${OVPN_CLI}" del_peer tun0 2
	ovpn_peer0_wait_del_ntf 2 userspace

	# the client still frames its packets, the server reads the raw
	# stream now: one packet sent alone is read back as is
	ovpn_tcp_peer_expect c2 sent send 7 100 2000
	ovpn_tcp_peer_expect s2 "recv 7 " recv 7 2000

	ovpn_tcp_peer_expect s2 closed close
	ovpn_tcp_peer_expect c2 eof eof 3000
	sleep 0.5
	if [ "$(ovpn_peer0_count_del_ntf 2)" -ne 1 ]; then
		echo "closing a detached socket notified a deletion again"
		return 1
	fi
	ovpn_tcp_peer_stop c2
	ovpn_tcp_peer_stop s2
}

# a TCP peer expires like an UDP one
ovpn_mdt_expire() {
	ovpn_cmd_ok "set peer 3 keepalive" \
		ip netns exec ovpn_peer0 "${OVPN_CLI}" set_peer tun0 3 1 2
	ovpn_peer0_wait_del_ntf 3 expired
	ovpn_tcp_peer_stop s3
	ovpn_tcp_peer_stop c3
}

ovpn_mdt_survivor() {
	local before after

	ovpn_mdt_ids=$(ovpn_peer0_get | jq -s -c '[.[].id]')
	if [ "${ovpn_mdt_ids}" != "[4]" ]; then
		printf 'peers left: %s, expected [4]\n' \
			"${ovpn_mdt_ids}"
		return 1
	fi

	before=$(ovpn_link_stat ovpn_peer0 tun0 tx.dropped)
	ip netns exec ovpn_peer4 ping -qc 5 -i 0.1 -w 5 5.5.5.1
	ip netns exec ovpn_peer0 ping -qc 5 -i 0.1 -w 5 fd55::5
	# routes to deleted peers drop
	ip netns exec ovpn_peer0 ping -qc 3 -i 0.1 -W 1 5.5.5.2 \
		>/dev/null 2>&1 && return 1
	after=$(ovpn_link_stat ovpn_peer0 tun0 tx.dropped)
	if [ $((after - before)) -lt 3 ]; then
		printf 'expected >= 3 TX drops to a deleted peer, got %s\n' \
			$((after - before))
		return 1
	fi
}

trap ovpn_test_exit EXIT
trap ovpn_stage_err ERR

ktap_print_header
ktap_set_plan 9

ovpn_cleanup
modprobe -q ovpn || true

ovpn_run_stage "setup TCP peers on collect_md interface" ovpn_mdt_setup
ovpn_run_stage "PEER_GET reports the TCP peers" ovpn_mdt_peer_get_all
ovpn_run_stage "data in both directions with peer ID metadata" \
	ovpn_mdt_traffic
ovpn_run_stage "iperf over TCP peers" ovpn_mdt_iperf
ovpn_run_stage "control packets reach userspace both ways" \
	ovpn_mdt_control
ovpn_run_stage "client close: EOF, then close(fd) deletes the peer" \
	ovpn_mdt_client_close
ovpn_run_stage "PEER_DEL detaches the TCP socket" ovpn_mdt_peer_del
ovpn_run_stage "TCP peer expires" ovpn_mdt_expire
ovpn_run_stage "remaining peer unaffected" ovpn_mdt_survivor

ovpn_stop_listener 0
ovpn_test_finished=1
ktap_finished

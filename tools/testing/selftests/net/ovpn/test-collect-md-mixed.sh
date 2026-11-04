#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 OpenVPN, Inc.
#
#	Author:	Antonio Quartulli <antonio@openvpn.net>
#
# Test one collect metadata (external) MP ovpn interface serving UDP and TCP
# peers at the same time:
#  - peer 1: UDP over IPv4, peer 2: UDP over IPv6 (one shared UDP socket)
#  - peer 3: TCP over IPv4, peer 4: TCP over IPv6 (one socket each)
# Peer IDs are unique across transports, and deleting peers of one transport
# doesn't disturb the others.

#set -x
set -eE

OVPN_UDP_PEERS_FILE=collect_md_peers.txt
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

# odd peers use IPv4, even ones IPv6
ovpn_mix_server_addr() {
	if [ $(($1 % 2)) -eq 1 ]; then
		echo "10.10.${1}.1"
	else
		echo "fd00:0:0:${1}::1"
	fi
}

ovpn_mix_client_iface() {
	local p="$1"

	ovpn_cmd_ok "create client ${p} interface" \
		ip netns exec ovpn_peer${p} "${OVPN_CLI}" new_iface tun${p} P2P
	ip -n ovpn_peer${p} addr add 5.5.5.$((p + 1))/24 dev tun${p}
	ip -n ovpn_peer${p} addr add fd55::$((p + 1))/64 dev tun${p} nodad
	ip -n ovpn_peer${p} link set tun${p} up
}

ovpn_mix_keys() {
	local p="$1"

	ovpn_cmd_ok "install server key for peer ${p}" \
		ip netns exec ovpn_peer0 "${OVPN_CLI}" new_key tun0 ${p} 1 0 \
			"${OVPN_ALG}" 0 data64.key
	ovpn_cmd_ok "install client ${p} key" \
		ip netns exec ovpn_peer${p} "${OVPN_CLI}" new_key tun${p} \
			$((p + 9)) 1 0 "${OVPN_ALG}" 1 data64.key
	ip -n ovpn_peer0 route add 5.5.5.$((p + 1))/32 encap ip id ${p} dev tun0
	ip -n ovpn_peer0 -6 route add fd55::$((p + 1))/128 encap ip6 id ${p} \
		dev tun0
}

ovpn_mix_setup() {
	local p

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

	# UDP peers 1 and 2, sharing the UDP socket bound to port 1
	ovpn_cmd_ok "create UDP peers" \
		ip netns exec ovpn_peer0 "${OVPN_CLI}" new_multi_peer tun0 1 \
			ASYMM "${OVPN_UDP_PEERS_FILE}"
	for p in 1 2; do
		ovpn_mix_client_iface ${p}
		ovpn_cmd_ok "create client ${p} UDP peer" \
			ip netns exec ovpn_peer${p} "${OVPN_CLI}" new_peer \
				tun${p} $((p + 9)) ${p} 1 \
				"$(ovpn_mix_server_addr ${p})" 1
		ovpn_mix_keys ${p}
	done

	# TCP peers 3 and 4
	for p in 3 4; do
		ovpn_tcp_peer_start s${p} ovpn_peer0 tun0 ${p} $((p + 9)) \
			listen :: $((1000 + p))
		ovpn_tcp_peer_reply s${p}
		[ "${OVPN_TP_REPLY}" == "listening" ]

		ovpn_mix_client_iface ${p}
		ovpn_tcp_peer_start c${p} ovpn_peer${p} tun${p} $((p + 9)) \
			${p} connect "$(ovpn_mix_server_addr ${p})" $((1000 + p))
		ovpn_tcp_peer_reply c${p}
		[ "${OVPN_TP_REPLY}" == "ready" ]
		ovpn_tcp_peer_reply s${p}
		[ "${OVPN_TP_REPLY}" == "ready" ]

		ovpn_mix_keys ${p}
	done
}

ovpn_mix_peer_get() {
	local peers

	peers=$(ovpn_peer0_get)
	ovpn_log "${peers}"

	if [ "$(jq -s -c '[.[].id] | sort' <<<"${peers}")" != "[1,2,3,4]" ]; then
		printf 'unexpected peers: %s\n' "${peers}"
		return 1
	fi
	# UDP peers have a remote endpoint, TCP peers don't
	jq -s -e '[.[] | select(.id <= 2 and
		(has("remote-ipv4") or has("remote-ipv6")))] | length == 2' \
		<<<"${peers}" >/dev/null
	jq -s -e '[.[] | select(.id >= 3 and
		(has("remote-ipv4") or has("remote-ipv6") |
		 not))] | length == 2' <<<"${peers}" >/dev/null
}

# ping <p> both ways, over IPv4 and IPv6
ovpn_mix_ping() {
	local p="$1"

	ip netns exec ovpn_peer${p} ping -qc 5 -i 0.1 -w 5 5.5.5.1
	ip netns exec ovpn_peer${p} ping -qc 5 -i 0.1 -w 5 fd55::1
	ip netns exec ovpn_peer0 ping -qc 5 -i 0.1 -w 5 5.5.5.$((p + 1))
	ip netns exec ovpn_peer0 ping -qc 5 -i 0.1 -w 5 fd55::$((p + 1))
}

ovpn_mix_traffic() {
	local p pids=() pkts

	for p in $(seq 1 ${OVPN_NUM_PEERS}); do
		ovpn_mix_ping ${p}
	done

	# all transports at once
	for p in $(seq 1 ${OVPN_NUM_PEERS}); do
		ip netns exec ovpn_peer0 ping -qfc 200 -s 1200 -w 10 \
			5.5.5.$((p + 1)) >/dev/null &
		pids+=($!)
	done
	for p in "${pids[@]}"; do
		wait "${p}"
	done

	for p in $(seq 1 ${OVPN_NUM_PEERS}); do
		pkts=$(ovpn_peer0_tc_pkts ${p})
		if [ "${pkts}" -lt 220 ]; then
			printf 'enc_key_id %s matched %s packets, expected >= 220\n' \
				"${p}" "${pkts}"
			return 1
		fi
	done
}

ovpn_mix_id_clash() {
	# an UDP peer can't take the ID of a TCP peer
	ovpn_cmd_fail "UDP peer with the ID of TCP peer 3" \
		ip netns exec ovpn_peer0 "${OVPN_CLI}" new_peer tun0 3 12 1000 \
			10.10.1.2 1

	# and vice versa
	ovpn_tcp_peer_start s5 ovpn_peer0 tun0 1 10 listen :: 1005
	ovpn_tcp_peer_reply s5
	[ "${OVPN_TP_REPLY}" == "listening" ]
	# the client side uses its own interface, P2P interfaces have only one
	# peer
	ip netns exec ovpn_peer3 "${OVPN_CLI}" new_iface tun5 P2P >/dev/null
	ovpn_tcp_peer_start c5 ovpn_peer3 tun5 99 1 connect 10.10.3.1 1005
	ovpn_tcp_peer_reply c5 || true
	if ovpn_tcp_peer_reply s5 2>/dev/null; then
		echo "TCP peer with the ID of UDP peer 1 accepted"
		return 1
	fi
	ovpn_tcp_peer_stop s5
	ovpn_tcp_peer_stop c5
	ip netns exec ovpn_peer3 "${OVPN_CLI}" del_iface tun5 >/dev/null

	if [ "$(ovpn_peer0_count_del_ntf 1)" -ne 0 ]; then
		echo "the clash deleted UDP peer 1"
		return 1
	fi
	ovpn_mix_ping 1
	ovpn_mix_ping 3
}

ovpn_mix_tcp_close() {
	ovpn_tcp_peer_expect s3 closed close
	ovpn_peer0_wait_del_ntf 3 transport-disconnect
	ovpn_tcp_peer_stop s3
	ovpn_tcp_peer_stop c3

	ovpn_mix_ping 1
	ovpn_mix_ping 2
	ovpn_mix_ping 4
}

ovpn_mix_udp_del() {
	ovpn_cmd_ok "delete UDP peer 1" \
		ip netns exec ovpn_peer0 "${OVPN_CLI}" del_peer tun0 1
	ovpn_peer0_wait_del_ntf 1 userspace

	ovpn_mix_ping 2
	ovpn_mix_ping 4
	ovpn_tcp_peer_expect c4 sent send 1 200 2000
	ovpn_tcp_peer_expect s4 "recv 1 " recv 1 2000
}

# deleting the interface tears down the peers of both transports; the
# server keeps the detached TCP socket
ovpn_mix_teardown() {
	ip -n ovpn_peer0 link set tun0 down
	ovpn_cmd_ok "delete server interface" \
		ip netns exec ovpn_peer0 "${OVPN_CLI}" del_iface tun0
	ovpn_peer0_wait_del_ntf 2 teardown
	ovpn_peer0_wait_del_ntf 4 teardown

	ovpn_tcp_peer_expect s4 closed close
	# the client may have sent something (i.e. IPv6 ND through tun4) to
	# the detached socket, which then resets the connection on close
	ovpn_tcp_peer_cmd c4 5 eof 3000
	if [[ "${OVPN_TP_REPLY}" != "eof" && \
	      "${OVPN_TP_REPLY}" != "error 104" ]]; then
		printf 'client 4: connection not closed: %s\n' \
			"${OVPN_TP_REPLY}"
		return 1
	fi
	ovpn_tcp_peer_stop s4
	ovpn_tcp_peer_stop c4
}

trap ovpn_test_exit EXIT
trap ovpn_stage_err ERR

ktap_print_header
ktap_set_plan 7

ovpn_cleanup
modprobe -q ovpn || true

ovpn_run_stage "setup UDP and TCP peers on one collect_md interface" \
	ovpn_mix_setup
ovpn_run_stage "PEER_GET reports peers of both transports" \
	ovpn_mix_peer_get
ovpn_run_stage "traffic over UDP and TCP peers" ovpn_mix_traffic
ovpn_run_stage "peer IDs are unique across transports" ovpn_mix_id_clash
ovpn_run_stage "TCP peer close leaves the others alone" ovpn_mix_tcp_close
ovpn_run_stage "UDP peer deletion leaves the others alone" ovpn_mix_udp_del
ovpn_run_stage "interface deletion tears down both transports" \
	ovpn_mix_teardown

ovpn_stop_listener 0
ovpn_test_finished=1
ktap_finished

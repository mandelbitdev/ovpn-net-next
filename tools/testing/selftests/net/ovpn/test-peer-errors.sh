#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 OpenVPN, Inc.
#
#	Author:	Antonio Quartulli <antonio@openvpn.net>
#
# Test how ovpn handles packets failing to decrypt, replayed packets and the
# explicit exit notification, with crafted DATA_V2 packets ("ovpn-cli
# inject" over UDP, "tcp_peer data" over TCP):
#  - peer 1 (UDP): per-peer decryption and replay error counters, in
#    PEER_GET and PEER_DEL_NTF
#  - peer 2 (UDP): a key with a decryption failure limit stops decrypting
#    once the limit is reached and a KEY_SWAP_NTF is sent, once
#  - peer 3 (UDP): an authenticated OCC EXIT message deletes the peer, a
#    forged one doesn't
#  - peer 4 (TCP): a packet for a missing key is dropped, a packet failing
#    to decrypt deletes the peer
# The server interface is a collect_md MP interface, as TCP peers have no
# VPN address.

#set -x
set -eE

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

# server address of peer <p>: peer 2 uses IPv6, the others IPv4
ovpn_err_saddr() {
	if [ "$1" -eq 2 ]; then
		echo "fd00:0:0:${1}::1"
	else
		echo "10.10.${1}.1"
	fi
}

# print attribute <attr> of server peer <p> (0 if missing)
ovpn_err_peer_attr() {
	ovpn_peer0_get "$1" | jq -r ".[\"$2\"] // 0"
}

# inject <p> <pkt_id> <payload> [count]: send crafted DATA_V2 packets from
# client <p> to its server peer, with the key of the client, from the port
# of the client's peer socket
ovpn_err_inject() {
	ip netns exec ovpn_peer${1} "${OVPN_CLI}" inject tun${1} data64.key 1 \
		0 ${1} ${2} ${3} "$(ovpn_err_saddr ${1})" $((1000 + ${1})) 1 \
		${4:-1}
}

ovpn_err_ping() {
	ip netns exec ovpn_peer${1} ping -qc 3 -i 0.1 -w 3 5.5.5.1
}

ovpn_err_count_ntf() {
	# YNL prints decoding errors along with the JSON objects
	grep '^{' "${OVPN_TMP_JSONS[0]}" | \
		jq -s "[.[] | select(.name == \"${1}\" and
			.msg.${2}.\"peer-id\" == ${3})] | length"
}

ovpn_err_setup() {
	local p limit

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
	ip -n ovpn_peer0 link set tun0 up

	ovpn_setup_listener 0
	sleep 1

	for p in $(seq 1 ${OVPN_NUM_PEERS}); do
		ovpn_cmd_ok "create client ${p} interface" \
			ip netns exec ovpn_peer${p} "${OVPN_CLI}" new_iface \
				tun${p} P2P
		ip -n ovpn_peer${p} addr add 5.5.5.$((p + 1))/24 dev tun${p}
		ip -n ovpn_peer${p} link set tun${p} up
		ip -n ovpn_peer0 route add 5.5.5.$((p + 1))/32 encap ip id ${p} \
			dev tun0
	done

	# UDP peers, one server socket each (port 1000 + p)
	for p in 1 2 3; do
		ovpn_cmd_ok "create server UDP peer ${p}" \
			ip netns exec ovpn_peer0 "${OVPN_CLI}" new_peer tun0 \
				${p} $((p + 9)) $((1000 + p)) \
				"${ovpn_err_caddr[${p}]}" 1
		ovpn_cmd_ok "create client UDP peer ${p}" \
			ip netns exec ovpn_peer${p} "${OVPN_CLI}" new_peer \
				tun${p} $((p + 9)) ${p} 1 \
				"$(ovpn_err_saddr ${p})" $((1000 + p))
	done

	# TCP peer 4
	ovpn_tcp_peer_start s4 ovpn_peer0 tun0 4 13 listen 0.0.0.0 1004
	ovpn_tcp_peer_reply s4
	[ "${OVPN_TP_REPLY}" == "listening" ]
	ovpn_tcp_peer_start c4 ovpn_peer4 tun4 13 4 connect 10.10.4.1 1004
	ovpn_tcp_peer_reply c4
	[ "${OVPN_TP_REPLY}" == "ready" ]
	ovpn_tcp_peer_reply s4
	[ "${OVPN_TP_REPLY}" == "ready" ]

	for p in $(seq 1 ${OVPN_NUM_PEERS}); do
		limit=""
		[ ${p} -eq 2 ] && limit=3
		ovpn_cmd_ok "install server key for peer ${p}" \
			ip netns exec ovpn_peer0 "${OVPN_CLI}" new_key tun0 \
				${p} 1 0 "${OVPN_ALG}" 0 data64.key ${limit}
		ovpn_cmd_ok "install client ${p} key" \
			ip netns exec ovpn_peer${p} "${OVPN_CLI}" new_key \
				tun${p} $((p + 9)) 1 0 "${OVPN_ALG}" 1 data64.key
	done

	for p in $(seq 1 ${OVPN_NUM_PEERS}); do
		ovpn_err_ping ${p}
	done
}

ovpn_err_counters() {
	local dec rep

	ovpn_err_inject 1 0 garbage 5

	# a valid packet with a fresh ID, then the very same packet again
	ovpn_err_inject 1 100000 keepalive
	ovpn_err_inject 1 100000 keepalive
	sleep 0.5

	dec=$(ovpn_err_peer_attr 1 link-rx-decrypt-errors)
	rep=$(ovpn_err_peer_attr 1 link-rx-replay-errors)
	if [ "${dec}" -ne 5 ] || [ "${rep}" -ne 1 ]; then
		printf 'peer 1: %s decryption and %s replay errors, expected 5 and 1\n' \
			"${dec}" "${rep}"
		return 1
	fi

	# the other peers are not charged
	if [ "$(ovpn_err_peer_attr 3 link-rx-decrypt-errors)" -ne 0 ]; then
		echo "peer 3 charged with the errors of peer 1"
		return 1
	fi

	# the final counters come with the deletion notification
	ovpn_cmd_ok "delete peer 1" \
		ip netns exec ovpn_peer0 "${OVPN_CLI}" del_peer tun0 1
	ovpn_peer0_wait_del_ntf 1 userspace
	dec=$(jq -r '.["link-rx-decrypt-errors"] // 0' <<<"${OVPN_DEL_NTF}")
	rep=$(jq -r '.["link-rx-replay-errors"] // 0' <<<"${OVPN_DEL_NTF}")
	if [ "${dec}" -ne 5 ] || [ "${rep}" -ne 1 ]; then
		printf 'peer-del-ntf: %s decryption and %s replay errors, expected 5 and 1\n' \
			"${dec}" "${rep}"
		return 1
	fi
}

ovpn_err_fail_limit() {
	local dropped

	# below the limit nothing changes
	ovpn_err_inject 2 0 garbage 2
	ovpn_err_ping 2
	sleep 0.5
	if [ "$(ovpn_err_count_ntf key-swap-ntf keyconf 2)" -ne 0 ]; then
		echo "key swap notified below the limit"
		return 1
	fi

	# the limit is reached: valid packets are dropped from now on
	ovpn_err_inject 2 0 garbage 1
	sleep 0.5
	if ovpn_err_ping 2 >/dev/null 2>&1; then
		echo "key still decrypting after reaching its failure limit"
		return 1
	fi

	# more failures don't notify again
	ovpn_err_inject 2 0 garbage 5
	sleep 0.5
	if [ "$(ovpn_err_count_ntf key-swap-ntf keyconf 2)" -ne 1 ]; then
		printf 'expected one key-swap-ntf for peer 2, got %s:\n' \
			"$(ovpn_err_count_ntf key-swap-ntf keyconf 2)"
		cat "${OVPN_TMP_JSONS[0]}"
		return 1
	fi

	# a new key brings the peer back
	ovpn_cmd_ok "install new server key for peer 2" \
		ip netns exec ovpn_peer0 "${OVPN_CLI}" new_key tun0 2 2 1 \
			"${OVPN_ALG}" 0 data64.key 3
	ovpn_cmd_ok "swap server keys of peer 2" \
		ip netns exec ovpn_peer0 "${OVPN_CLI}" swap_keys tun0 2
	ovpn_cmd_ok "install new client 2 key" \
		ip netns exec ovpn_peer2 "${OVPN_CLI}" new_key tun2 11 2 1 \
			"${OVPN_ALG}" 1 data64.key
	ovpn_cmd_ok "swap client 2 keys" \
		ip netns exec ovpn_peer2 "${OVPN_CLI}" swap_keys tun2 11
	ovpn_err_ping 2
}

ovpn_err_exit() {
	# not authenticated: just a decryption error
	ovpn_err_inject 3 0 garbage 1
	sleep 0.5
	ovpn_peer0_get 3 >/dev/null
	ovpn_err_ping 3

	ovpn_err_inject 3 100000 exit
	ovpn_peer0_wait_del_ntf 3 exit
	ovpn_cmd_fail "peer 3 is gone" ovpn_peer0_get 3
}

ovpn_err_tcp() {
	# key ID 5 doesn't exist: the packet is dropped, the peer stays
	ovpn_tcp_peer_expect c4 "data sent" data 5 4 100
	sleep 0.5
	ovpn_peer0_get 4 >/dev/null
	ovpn_err_ping 4

	# a packet failing to decrypt can't be skipped in a stream
	ovpn_tcp_peer_expect c4 "data sent" data 0 4 100
	ovpn_peer0_wait_del_ntf 4 decrypt-error
	if [ "$(jq -r '.["link-rx-decrypt-errors"] // 0' \
		<<<"${OVPN_DEL_NTF}")" -ne 1 ]; then
		printf 'unexpected counters in %s\n' "${OVPN_DEL_NTF}"
		return 1
	fi

	ovpn_tcp_peer_expect s4 closed close
	ovpn_tcp_peer_stop s4
	ovpn_tcp_peer_stop c4
}

declare -A ovpn_err_caddr=(
	[1]=10.10.1.2
	[2]=fd00:0:0:2::2
	[3]=10.10.3.2
)

trap ovpn_test_exit EXIT
trap ovpn_stage_err ERR

ktap_print_header
ktap_set_plan 5

ovpn_cleanup
modprobe -q ovpn || true

ovpn_run_stage "setup UDP and TCP peers" ovpn_err_setup
ovpn_run_stage "per-peer decryption and replay error counters" \
	ovpn_err_counters
ovpn_run_stage "authenticated exit notification deletes the peer" \
	ovpn_err_exit
ovpn_run_stage "TCP: missing key dropped, decryption error fatal" \
	ovpn_err_tcp
ovpn_run_stage "key decryption failure limit" ovpn_err_fail_limit

ovpn_stop_listener 0
ovpn_test_finished=1
ktap_finished

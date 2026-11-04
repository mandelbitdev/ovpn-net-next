#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 OpenVPN, Inc.
#
#	Author:	Antonio Quartulli <antonio@openvpn.net>
#
# A userspace writer on a TCP peer socket must not stall while the data path
# keeps the connection busy.
#
# sendmsg() fails with -EAGAIN while ovpn is still sending a data packet
# (out_msg) because the TCP send buffer is full. An event loop then waits
# for EPOLLOUT with edge-triggered epoll (i.e. asio): it must be woken up
# once ovpn is done with its message, otherwise control packets (TLS
# renegotiation, keepalive replies...) are stuck until something else
# happens on the socket.
#
# Each round fills the send buffer of the server peer socket while the
# client drops every segment (nft): first with data packets, then with a
# burst of control packets from userspace, so that one of them always finds
# a message pending. Then it lifts the block: the control packets must
# reach the client within a few seconds and the writer must be woken up. A
# round where the writer timed out while a sendmsg() would have succeeded
# is a lost wakeup.
# The rounds are then repeated while a UDP flood keeps the data path busy.

#set -x
set -eE

OVPN_PROTO=TCP
OVPN_NUM_PEERS=1

source ./common.sh

OVPN_TXW_ROUNDS=${OVPN_TXW_ROUNDS:-8}
OVPN_TXW_TIMEOUT_MS=${OVPN_TXW_TIMEOUT_MS:-4000}
# control packets queued in a row per round, enough to fill the send buffer
OVPN_TXW_BURST=${OVPN_TXW_BURST:-40}

ovpn_test_finished=0

ovpn_test_exit() {
	ovpn_cleanup
	modprobe -r ovpn || true

	if [ "${ovpn_test_finished}" -eq 0 ]; then
		ktap_print_totals
	fi
}

ovpn_txw_setup() {
	local p

	for p in 0 1; do
		ovpn_create_ns ${p}
		ovpn_cmd_ok "create interface tun${p}" \
			ip netns exec ovpn_peer${p} "${OVPN_CLI}" new_iface \
				tun${p} P2P
		ip -n ovpn_peer${p} addr add 5.5.5.$((p + 1))/24 dev tun${p}
		ip -n ovpn_peer${p} link set tun${p} up
	done

	ip link add veth1 netns ovpn_peer0 type veth peer name veth1 \
		netns ovpn_peer1
	ip -n ovpn_peer0 addr add 10.10.1.1/24 dev veth1
	ip -n ovpn_peer1 addr add 10.10.1.2/24 dev veth1
	ip -n ovpn_peer0 link set veth1 up
	ip -n ovpn_peer1 link set veth1 up

	# a small, fixed send buffer on the server socket fills quickly
	ovpn_tcp_peer_start s ovpn_peer0 tun0 1 10 listen 0.0.0.0 1000 16384
	ovpn_tcp_peer_reply s
	[ "${OVPN_TP_REPLY}" == "listening" ]
	ovpn_tcp_peer_start c ovpn_peer1 tun1 10 1 connect 10.10.1.1 1000
	ovpn_tcp_peer_reply c
	[ "${OVPN_TP_REPLY}" == "ready" ]
	ovpn_tcp_peer_reply s
	[ "${OVPN_TP_REPLY}" == "ready" ]

	ip netns exec ovpn_peer0 "${OVPN_CLI}" new_key tun0 1 1 0 \
		"${OVPN_ALG}" 0 data64.key
	ip netns exec ovpn_peer1 "${OVPN_CLI}" new_key tun1 10 1 0 \
		"${OVPN_ALG}" 1 data64.key

	ip netns exec ovpn_peer0 ping -qc 3 -i 0.1 -w 5 5.5.5.2

	ip netns exec ovpn_peer1 nft add table inet ovpn_txw
	ip netns exec ovpn_peer1 nft add chain inet ovpn_txw in \
		'{ type filter hook input priority 0; }'
}

ovpn_txw_block() {
	ip netns exec ovpn_peer1 nft add rule inet ovpn_txw in \
		tcp sport 1000 drop
}

ovpn_txw_unblock() {
	ip netns exec ovpn_peer1 nft flush chain inet ovpn_txw in
}

# check the reply of the server to "send <seq>"; returns 0 if the writer was
# woken up after -EAGAIN, 2 if it never had to wait, 1 on failure
ovpn_txw_check_sent() {
	local seq="$1"
	local wakeups idle

	ovpn_tcp_peer_reply s $((OVPN_TXW_TIMEOUT_MS / 1000 + 5)) || return 1
	case "${OVPN_TP_REPLY}" in
	"stall ${seq} 1 "*)
		read -r _ _ _ wakeups idle <<<"${OVPN_TP_REPLY}"
		printf 'packet %s: writer not done after %s ms with the socket writable: %s wakeups, none in the last %s us%s\n' \
			"${seq}" "${OVPN_TXW_TIMEOUT_MS}" "${wakeups}" "${idle}" \
			"$([ "${idle}" -gt 1000000 ] && echo ' (lost wakeup)')"
		return 1
		;;
	"stall ${seq} 0 "*)
		printf 'packet %s: socket not writable after %s ms: %s\n' \
			"${seq}" "${OVPN_TXW_TIMEOUT_MS}" "${OVPN_TP_REPLY}"
		return 1
		;;
	"sent ${seq} "*)
		;;
	*)
		printf 'packet %s: send failed: %s\n' "${seq}" \
			"${OVPN_TP_REPLY}"
		return 1
		;;
	esac

	[ "$(awk '{print $4}' <<<"${OVPN_TP_REPLY}")" -gt 0 ] || return 2
}

# one round: returns 0 on success, 1 on failure, 2 if the writer never had
# to wait (inconclusive)
ovpn_txw_round() {
	local seq="$1"
	local flood="${2:-1}"
	local i rc waited=0

	ovpn_txw_block
	# fill the socket send buffer with data packets nobody acks
	[ "${flood}" -eq 1 ] && ip netns exec ovpn_peer0 python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(300):
    try:
        s.sendto(b"x" * 1300, ("5.5.5.2", 9))
    except OSError:
        pass
'

	ovpn_tcp_peer_send_cmd c recv "${seq}" $((OVPN_TXW_TIMEOUT_MS + 3000))
	# if the data packets didn't fill the send buffer, the control packets
	# do: one of them finds a pending message and has to wait
	for i in $(seq 1 ${OVPN_TXW_BURST}); do
		ovpn_tcp_peer_send_cmd s send $((seq * 100 + i)) 1300 \
			"${OVPN_TXW_TIMEOUT_MS}"
	done
	ovpn_tcp_peer_send_cmd s send "${seq}" 200 "${OVPN_TXW_TIMEOUT_MS}"
	sleep 0.3
	ovpn_txw_unblock

	for i in $(seq 1 ${OVPN_TXW_BURST}) 0; do
		rc=0
		if [ "${i}" -eq 0 ]; then
			ovpn_txw_check_sent "${seq}" || rc=$?
		else
			ovpn_txw_check_sent $((seq * 100 + i)) || rc=$?
		fi
		[ "${rc}" -eq 1 ] && return 1
		[ "${rc}" -eq 0 ] && waited=1
	done

	ovpn_tcp_peer_reply c $((OVPN_TXW_TIMEOUT_MS / 1000 + 8)) || return 1
	if [[ "${OVPN_TP_REPLY}" != "recv ${seq} "* ]]; then
		printf 'round %s: control packet not received: %s\n' "${seq}" \
			"${OVPN_TP_REPLY}"
		return 1
	fi

	[ "${waited}" -eq 1 ] || return 2
}

ovpn_txw_rounds() {
	local i rc waited=0

	for i in $(seq 1 "${OVPN_TXW_ROUNDS}"); do
		rc=0
		ovpn_txw_round "${i}" || rc=$?
		case ${rc} in
		0) waited=$((waited + 1)) ;;
		2) ;;
		*) return 1 ;;
		esac
		# let the connection drain
		sleep 0.5
	done

	ovpn_log "the writer waited for EPOLLOUT in ${waited}/${OVPN_TXW_ROUNDS} rounds"
	if [ "${waited}" -eq 0 ] && [ "${OVPN_TXW_ROUNDS}" -gt 0 ]; then
		echo "the writer never had to wait: the test didn't exercise anything"
		return 1
	fi
}

# the same rounds while a UDP flood keeps the data path busy, so that the
# writer competes with data packets once the block is lifted
ovpn_txw_saturated() {
	local i rc waited=0 flood_pid

	ip netns exec ovpn_peer1 iperf3 -s -D -1 -p 5201 >/dev/null 2>&1
	sleep 0.5
	ovpn_run_bg flood_pid ip netns exec ovpn_peer0 iperf3 -u -b 0 -l 1300 \
		-t 30 -c 5.5.5.2
	sleep 1

	for i in $(seq 1 "${OVPN_TXW_ROUNDS}"); do
		rc=0
		ovpn_txw_round $((50 + i)) 0 || rc=$?
		case ${rc} in
		0) waited=$((waited + 1)) ;;
		2) ;;
		*) kill "${flood_pid}" 2>/dev/null; return 1 ;;
		esac
		sleep 0.5
	done

	kill "${flood_pid}" 2>/dev/null || true
	wait "${flood_pid}" 2>/dev/null || true
	ovpn_log "under load the writer waited in ${waited}/${OVPN_TXW_ROUNDS} rounds"
	if [ "${waited}" -eq 0 ] && [ "${OVPN_TXW_ROUNDS}" -gt 0 ]; then
		echo "the writer never had to wait under load"
		return 1
	fi
}

trap ovpn_test_exit EXIT
trap ovpn_stage_err ERR

ktap_print_header
ktap_set_plan 3

ovpn_cleanup
modprobe -q ovpn || true

ovpn_run_stage "setup TCP peers" ovpn_txw_setup
ovpn_run_stage "writer woken up once the pending data packet is sent" \
	ovpn_txw_rounds
ovpn_run_stage "control packets delivered while data saturates TCP" \
	ovpn_txw_saturated

ovpn_test_finished=1
ktap_finished

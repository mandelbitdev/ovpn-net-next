#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2020-2025 OpenVPN, Inc.
#
#	Author:	Antonio Quartulli <antonio@openvpn.net>
#		Ralf Lici <ralf@mandelbit.com>

#set -x
# shellcheck disable=SC2329
set -eE

OVPN_PROTO=UDP

source ./common.sh

ovpn_test_finished=0
declare -a OVPN_BIND_TCPDUMP_PIDS=()

ovpn_test_exit() {
	local pid

	for pid in "${OVPN_BIND_TCPDUMP_PIDS[@]}"; do
		kill -TERM "${pid}" 2>/dev/null || true
		wait "${pid}" 2>/dev/null || true
	done
	OVPN_BIND_TCPDUMP_PIDS=()

	ovpn_cleanup
	modprobe -r ovpn || true

	if [ "${ovpn_test_finished}" -eq 0 ]; then
		ktap_print_totals
	fi
}

ovpn_bind_prepare_network() {
	ovpn_cmd_ok "create namespace peer1" ip netns add ovpn_peer1
	ovpn_cmd_ok "create namespace peer2" ip netns add ovpn_peer2

	ovpn_cmd_ok "create first underlay link" \
		ip link add veth1 netns ovpn_peer1 type veth peer name \
			veth1 netns ovpn_peer2
	ovpn_cmd_ok "create second underlay link" \
		ip link add veth2 netns ovpn_peer1 type veth peer name \
			veth2 netns ovpn_peer2

	ovpn_cmd_ok "configure peer1 first underlay address" \
		ip -n ovpn_peer1 addr add 10.10.10.1/24 dev veth1
	ovpn_cmd_ok "bring up peer1 first underlay link" \
		ip -n ovpn_peer1 link set veth1 up
	ovpn_cmd_ok "configure peer1 second underlay address" \
		ip -n ovpn_peer1 addr add 20.20.20.1/24 dev veth2
	ovpn_cmd_ok "bring up peer1 second underlay link" \
		ip -n ovpn_peer1 link set veth2 up

	ovpn_cmd_ok "configure peer2 first underlay address" \
		ip -n ovpn_peer2 addr add 10.10.10.2/24 dev veth1
	ovpn_cmd_ok "bring up peer2 first underlay link" \
		ip -n ovpn_peer2 link set veth1 up
	ovpn_cmd_ok "configure peer2 second underlay address" \
		ip -n ovpn_peer2 addr add 20.20.20.2/24 dev veth2
	ovpn_cmd_ok "bring up peer2 second underlay link" \
		ip -n ovpn_peer2 link set veth2 up

	# Some test cases intentionally bind peer1 to a device that does not
	# match the route-selected underlay, so allow asymmetric underlay paths.
	ovpn_cmd_ok "disable peer1 global rp_filter" \
		ip netns exec ovpn_peer1 sysctl -w \
			net.ipv4.conf.all.rp_filter=0
	ovpn_cmd_ok "disable peer1 veth1 rp_filter" \
		ip netns exec ovpn_peer1 sysctl -w \
			net.ipv4.conf.veth1.rp_filter=0
	ovpn_cmd_ok "disable peer1 veth2 rp_filter" \
		ip netns exec ovpn_peer1 sysctl -w \
			net.ipv4.conf.veth2.rp_filter=0

	# Keep peer2 from answering ARP for one underlay address on the other
	# underlay device; mismatch cases rely on the two L2 paths staying
	# distinct.
	ovpn_cmd_ok "enable peer2 strict global ARP replies" \
		ip netns exec ovpn_peer2 sysctl -w \
			net.ipv4.conf.all.arp_ignore=1
	ovpn_cmd_ok "enable peer2 strict veth1 ARP replies" \
		ip netns exec ovpn_peer2 sysctl -w \
			net.ipv4.conf.veth1.arp_ignore=1
	ovpn_cmd_ok "enable peer2 strict veth2 ARP replies" \
		ip netns exec ovpn_peer2 sysctl -w \
			net.ipv4.conf.veth2.arp_ignore=1

	ovpn_cmd_ok "create peer1 ovpn interface" \
		ip netns exec ovpn_peer1 "${OVPN_CLI}" new_iface tun1 P2P
	ovpn_cmd_ok "create peer2 ovpn interface" \
		ip netns exec ovpn_peer2 "${OVPN_CLI}" new_iface tun2 P2P

	ovpn_cmd_ok "configure peer1 ovpn address" \
		ip -n ovpn_peer1 addr add 5.5.5.1 dev tun1
	ovpn_cmd_ok "start peer1 ovpn interface" \
		ip -n ovpn_peer1 link set tun1 up
	ovpn_cmd_ok "configure peer2 ovpn address" \
		ip -n ovpn_peer2 addr add 5.5.5.2 dev tun2
	ovpn_cmd_ok "start peer2 ovpn interface" \
		ip -n ovpn_peer2 link set tun2 up

	ovpn_cmd_ok "install peer1 ovpn route" \
		ip -n ovpn_peer1 route add 5.5.5.0/24 dev tun1
	ovpn_cmd_ok "install peer2 ovpn route" \
		ip -n ovpn_peer2 route add 5.5.5.0/24 dev tun2
}

ovpn_bind_configure_peers() {
	local dev1="$1"
	local dev2="$2"
	local raddr4_peer1="$3"
	local raddr4_peer2="$4"

	ip netns exec ovpn_peer1 "${OVPN_CLI}" del_peer tun1 1 \
		>/dev/null 2>&1 || true
	ip netns exec ovpn_peer2 "${OVPN_CLI}" del_peer tun2 10 \
		>/dev/null 2>&1 || true

	# Close any active userspace socket before installing a new peer pair.
	ovpn_kill_cli

	ovpn_cmd_ok "create peer1 bound peer on ${dev1}" \
		ip netns exec ovpn_peer1 "${OVPN_CLI}" new_peer tun1 \
			"${dev1}" 1 10 1 "${raddr4_peer1}" 1
	ovpn_cmd_ok "install peer1 key" \
		ip netns exec ovpn_peer1 "${OVPN_CLI}" new_key tun1 1 1 0 \
			"${OVPN_ALG}" 0 data64.key
	ovpn_cmd_ok "create peer2 bound peer on ${dev2}" \
		ip netns exec ovpn_peer2 "${OVPN_CLI}" new_peer tun2 \
			"${dev2}" 10 1 1 "${raddr4_peer2}" 1
	ovpn_cmd_ok "install peer2 key" \
		ip netns exec ovpn_peer2 "${OVPN_CLI}" new_key tun2 10 1 0 \
			"${OVPN_ALG}" 1 data64.key

	ovpn_cmd_ok "set peer1 timeout" \
		ip netns exec ovpn_peer1 "${OVPN_CLI}" set_peer tun1 1 60 120
	ovpn_cmd_ok "set peer2 timeout" \
		ip netns exec ovpn_peer2 "${OVPN_CLI}" set_peer tun2 10 60 120
}

ovpn_bind_start_capture() {
	local dev="$1"
	local count="$2"
	local filter="$3"
	local pid
	local tcpdump_timeout="2s"

	ovpn_run_bg pid timeout "${tcpdump_timeout}" \
		ip netns exec ovpn_peer1 tcpdump --immediate-mode -p -ni \
			"${dev}" -c "${count}" "${filter}" -n -q
	OVPN_BIND_TCPDUMP_PIDS+=("${pid}")
}

ovpn_bind_run_positive_case() {
	local dev1="$1"
	local dev2="$2"
	local raddr4_peer1="$3"
	local raddr4_peer2="$4"
	local expected_dev="$5"
	local unexpected_dev="$6"
	local filter
	local header1="0x48000001"
	local header2="0x4800000a"
	local ping_start_delay="0.3"

	ovpn_bind_configure_peers "${dev1}" "${dev2}" "${raddr4_peer1}" \
		"${raddr4_peer2}"
	filter="$(printf '(%s) or (%s)' \
		"$(ovpn_build_capture_filter "${header1}" "${raddr4_peer1}")" \
		"$(ovpn_build_capture_filter "${header2}" "${raddr4_peer2}")")"

	# The expected device must carry matching ovpn data packets.
	ovpn_bind_start_capture "${expected_dev}" 1 "${filter}"

	# The unexpected device must not carry even one matching data packet.
	ovpn_bind_start_capture "${unexpected_dev}" 1 "${filter}"

	sleep "${ping_start_delay}"
	ovpn_cmd_ok "send tunnel traffic from peer1 to peer2" \
		ip netns exec ovpn_peer1 ping -qfc 10 -w 3 5.5.5.2

	# Reaching -c is success for the expected capture and failure for the
	# unexpected one; timeout means the opposite.
	ovpn_cmd_ok "capture packets on ${expected_dev}" \
		wait "${OVPN_BIND_TCPDUMP_PIDS[0]}"
	OVPN_BIND_TCPDUMP_PIDS=("${OVPN_BIND_TCPDUMP_PIDS[@]:1}")

	ovpn_cmd_fail "capture packets on ${unexpected_dev}" \
		wait "${OVPN_BIND_TCPDUMP_PIDS[0]}"
	OVPN_BIND_TCPDUMP_PIDS=("${OVPN_BIND_TCPDUMP_PIDS[@]:1}")
}

ovpn_bind_run_sender_negative_case() {
	local dev1="$1"
	local raddr4_peer1="$2"
	local raddr4_peer2="$3"
	local unexpected_dev="$4"
	local filter
	local header="0x4800000a"
	local ping_start_delay="0.3"

	ovpn_bind_configure_peers "${dev1}" any "${raddr4_peer1}" \
		"${raddr4_peer2}"
	filter="$(ovpn_build_capture_filter "${header}" "${raddr4_peer1}")"

	# The route-selected device must not carry peer1 egress data when
	# peer1 is bound to the other underlay device.
	ovpn_bind_start_capture "${unexpected_dev}" 1 "${filter}"

	sleep "${ping_start_delay}"
	ovpn_cmd_fail "fail tunnel traffic with mismatched peer1 bind_dev" \
		ip netns exec ovpn_peer1 ping -qfc 10 -w 3 5.5.5.2
	ovpn_cmd_fail "capture packets on ${unexpected_dev}" \
		wait "${OVPN_BIND_TCPDUMP_PIDS[0]}"
	OVPN_BIND_TCPDUMP_PIDS=("${OVPN_BIND_TCPDUMP_PIDS[@]:1}")
}

ovpn_bind_run_receiver_negative_case() {
	local dev2="$1"
	local raddr4_peer1="$2"
	local raddr4_peer2="$3"
	local capture_dev="$4"
	local filter
	local header="0x4800000a"
	local ping_start_delay="0.3"

	ovpn_bind_configure_peers any "${dev2}" "${raddr4_peer1}" \
		"${raddr4_peer2}"
	filter="$(ovpn_build_capture_filter "${header}" "${raddr4_peer1}")"

	# The mismatched ingress device should carry peer1 data packets, but
	# the receiver-side bind mismatch must prevent ping replies.
	ovpn_bind_start_capture "${capture_dev}" 1 "${filter}"

	sleep "${ping_start_delay}"
	ovpn_cmd_fail "fail tunnel traffic with mismatched peer2 bind_dev" \
		ip netns exec ovpn_peer1 ping -qfc 10 -w 3 5.5.5.2
	ovpn_cmd_ok "capture mismatched ingress on ${capture_dev}" \
		wait "${OVPN_BIND_TCPDUMP_PIDS[0]}"
	OVPN_BIND_TCPDUMP_PIDS=("${OVPN_BIND_TCPDUMP_PIDS[@]:1}")
}

trap ovpn_test_exit EXIT
trap ovpn_stage_err ERR

ktap_print_header
ktap_set_plan 9

ovpn_cleanup
modprobe -q ovpn || true

ovpn_run_stage "setup network topology" ovpn_bind_prepare_network
ovpn_run_stage "peer1 bind_dev=veth1 routes over veth1" \
	ovpn_bind_run_positive_case \
	veth1 any 10.10.10.2 10.10.10.1 veth1 veth2
ovpn_run_stage "peer1 bind_dev=veth2 routes over veth2" \
	ovpn_bind_run_positive_case \
	veth2 any 20.20.20.2 20.20.20.1 veth2 veth1
ovpn_run_stage "peer2 bind_dev=veth1 replies over veth1" \
	ovpn_bind_run_positive_case \
	any veth1 10.10.10.2 10.10.10.1 veth1 veth2
ovpn_run_stage "peer2 bind_dev=veth2 replies over veth2" \
	ovpn_bind_run_positive_case \
	any veth2 20.20.20.2 20.20.20.1 veth2 veth1
ovpn_run_stage "peer1 bind_dev=veth1 blocks veth2 egress" \
	ovpn_bind_run_sender_negative_case \
	veth1 20.20.20.2 20.20.20.1 veth2
ovpn_run_stage "peer1 bind_dev=veth2 blocks veth1 egress" \
	ovpn_bind_run_sender_negative_case \
	veth2 10.10.10.2 10.10.10.1 veth1
ovpn_run_stage "peer2 bind_dev=veth1 rejects veth2 ingress" \
	ovpn_bind_run_receiver_negative_case \
	veth1 20.20.20.2 20.20.20.1 veth2
ovpn_run_stage "peer2 bind_dev=veth2 rejects veth1 ingress" \
	ovpn_bind_run_receiver_negative_case \
	veth2 10.10.10.2 10.10.10.1 veth1

ovpn_test_finished=1
ktap_finished

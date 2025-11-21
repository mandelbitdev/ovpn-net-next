#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2020-2025 OpenVPN, Inc.
#
#	Author:	Ralf Lici <ralf@mandelbit.com>
#		Antonio Quartulli <antonio@openvpn.net>

#set -x
set -e

source ./common.sh

bind_cleanup() {
	rm -f /tmp/ovpn-bind1.log /tmp/ovpn-bind2.log || true

	ip netns exec peer1 "${OVPN_CLI}" del_peer tun1 1 2>/dev/null || true
	ip netns exec peer2 "${OVPN_CLI}" del_peer tun2 10 2>/dev/null || true

	# close any active socket
	killall "$(basename "${OVPN_CLI}")" 2>/dev/null || true
}
trap bind_cleanup EXIT

cleanup

modprobe -q ovpn || true

# setup a P2P session between peer1 and peer2

ip netns add peer1
ip netns add peer2

ip link add veth1 netns peer1 type veth peer name veth1 netns peer2
ip link add veth2 netns peer1 type veth peer name veth2 netns peer2

ip -n peer1 addr add 10.10.10.1/24 dev veth1
ip -n peer1 link set veth1 up
ip -n peer2 addr add 10.10.10.2/24 dev veth1
ip -n peer2 link set veth1 up

ip -n peer1 addr add 20.20.20.1/24 dev veth2
ip -n peer1 link set veth2 up
ip -n peer2 addr add 20.20.20.2/24 dev veth2
ip -n peer2 link set veth2 up

ip netns exec peer1 sysctl -w net.ipv4.conf.all.rp_filter=0
ip netns exec peer1 sysctl -w net.ipv4.conf.veth1.rp_filter=0
ip netns exec peer1 sysctl -w net.ipv4.conf.veth2.rp_filter=0

ip -n peer1 route add 10.10.10.2/32 dev veth2

ip netns exec peer1 "${OVPN_CLI}" new_iface tun1 P2P
ip netns exec peer2 "${OVPN_CLI}" new_iface tun2 P2P

ip -n peer1 addr add 5.5.5.1/24 dev tun1
ip -n peer1 link set tun1 up
ip -n peer2 addr add 5.5.5.2/24 dev tun2
ip -n peer2 link set tun2 up

run_bind_test() {
	dev=${1}
	laddr=${2}
	raddr4_peer1=${3}
	raddr4_peer2=${4}

	bind_cleanup

	ip netns exec peer1 "${OVPN_CLI}" new_peer tun1 "${dev}" 1 10 \
		"${laddr}" 1 "${raddr4_peer1}" 1
	ip netns exec peer1 "${OVPN_CLI}" new_key tun1 1 1 0 "${ALG}" 0 \
		data64.key
	ip netns exec peer2 "${OVPN_CLI}" new_peer tun2 "${dev}" 10 1 any 1 \
		"${raddr4_peer2}" 1
	ip netns exec peer2 "${OVPN_CLI}" new_key tun2 10 1 0 "${ALG}" 1 \
		data64.key

	ip netns exec peer1 "${OVPN_CLI}" set_peer tun1 1 60 120
	ip netns exec peer2 "${OVPN_CLI}" set_peer tun2 10 60 120

	if [ "${laddr}" != "any" ]; then
		host="and src host ${laddr}"
	fi

	timeout 2 ip netns exec peer1 tcpdump -nqi veth1 udp "${host}" and \
		port 1 > /tmp/ovpn-bind1.log 2>/dev/null &
	tcpdump1_pid=$!
	timeout 2 ip netns exec peer1 tcpdump -nqi veth2 udp "${host}" and \
		port 1 > /tmp/ovpn-bind2.log 2>/dev/null &
	tcpdump2_pid=$!

	sleep 0.5

	ip netns exec peer1 ping -qfc 50 -w 1 5.5.5.2

	wait ${tcpdump1_pid} || true
	wait ${tcpdump2_pid} || true
}

# test without binding to local address or interface (traffic flows through
# veth2 with src 20.20.20.1 because of the /32 routing rule)
echo "No binding"
run_bind_test any any 10.10.10.2 10.10.10.1
[ "$(grep -c -i udp /tmp/ovpn-bind1.log)" -eq 0 ]
[ "$(grep -c -i udp /tmp/ovpn-bind2.log)" -ge 100 ]
[ "$(grep -c "10.10.10.1\.1 >" /tmp/ovpn-bind2.log)" -eq 0 ]
[ "$(grep -c "20.20.20.1\.1 >" /tmp/ovpn-bind2.log)" -ge 50 ]

# test with SO_BINDTODEVICE to veth1 (overrides route rule)
echo "Bind to veth1"
run_bind_test veth1 any 10.10.10.2 10.10.10.1
[ "$(grep -c -i udp /tmp/ovpn-bind1.log)" -ge 100 ]
[ "$(grep -c -i udp /tmp/ovpn-bind2.log)" -eq 0 ]

# test with binding to local address 10.10.10.1
echo "Bind to 10.10.10.1"
run_bind_test any 10.10.10.1 10.10.10.2 10.10.10.1
[ "$(grep -c -i udp /tmp/ovpn-bind1.log)" -eq 0 ]
[ "$(grep -c "10.10.10.1\.1 >" /tmp/ovpn-bind2.log)" -ge 50 ]
[ "$(grep -c "20.20.20.1\.1 >" /tmp/ovpn-bind2.log)" -eq 0 ]

bind_cleanup
cleanup

modprobe -r ovpn || true

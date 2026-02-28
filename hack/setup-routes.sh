#!/usr/bin/env bash

# Testbed setup for SIIT (Stateless IP/ICMP Translation) eBPF program
set -o nounset

client_ip=10.0.0.2
server_ip=fd00::2
ipv4=""
pool=""
delete=false

print_help() {
  echo "usage: "
  echo "--pool (siit pool)"
  echo "--ipv4"
}

parse_flags() {
  while test $# -gt 0; do
    case "$1" in
    --ipv4)
      shift
      ipv4="${1}"
      ;;
    --pool)
      shift
      pool="${1}"
      ;;
    --delete)
      delete=true
      ;;
    --help | -h)
      print_help
      exit 1
      ;;

    esac
    shift
  done
}
parse_flags "$@"

if $delete; then
  echo "Cleaning up existing namespaces (if any)..."
  ip netns del ns_client 2>/dev/null || true
  ip netns del ns_router 2>/dev/null || true
  ip netns del ns_server 2>/dev/null || true
  exit 0
fi

(
  set -x
  echo "Creating namespaces..."
  ip netns add ns_client
  ip netns add ns_router
  ip netns add ns_server

  echo "Creating veth pairs..."
  # veth_c (client) <---> veth_cr (router ingress from client)
  ip link add veth_c type veth peer name veth_cr
  # veth_s (server) <---> veth_sr (router ingress from server)
  ip link add veth_s type veth peer name veth_sr

  echo "Assigning interfaces to namespaces..."
  ip link set veth_c netns ns_client
  ip link set veth_cr netns ns_router
  ip link set veth_sr netns ns_router
  ip link set veth_s netns ns_server

  echo "Bringing up loopback interfaces..."
  ip -n ns_client link set lo up
  ip -n ns_router link set lo up
  ip -n ns_server link set lo up

  echo "Configuring Client (IPv4: 10.0.0.2/24)..."
  ip -n ns_client link set veth_c up
  ip -n ns_client addr add ${client_ip}/24 dev veth_c
  # Default route to the router
  ip -n ns_client route add default via 10.0.0.254
  # Explicitly route the virtual SIIT IP to the router so it resolves the MAC correctly
  ip -n ns_client route add ${ipv4}/32 via 10.0.0.254

  echo "Configuring Router (IPv4: 10.0.0.254/24 | IPv6: fd00::1/64)..."
  ip -n ns_router link set veth_cr up
  ip -n ns_router addr add 10.0.0.254/24 dev veth_cr
  # route response traffic back to client
  ip -n ns_router route add ${ipv4}/32 dev siit-peer

  ip -n ns_router link set veth_sr up
  ip -n ns_router addr add fd00::1/64 dev veth_sr
  # ip -n ns_router route add ${ipv4} dev siit
  ip -n ns_router route add ${pool} dev siit

  # Enable IP forwarding inside the router namespace
  ip netns exec ns_router sysctl -qw net.ipv4.ip_forward=1
  ip netns exec ns_router sysctl -qw net.ipv6.conf.all.forwarding=1

  echo "Configuring Server (IPv6: fd00::2/64)..."
  ip -n ns_server link set veth_s up
  ip -n ns_server addr add ${server_ip}/64 dev veth_s
  # The server needs to know how to reply to the SIIT pool (the translated IPv4 client IPs)
  ip -n ns_server route add ${pool} via fd00::1
)

echo "Setup complete!"
echo "--------------------------------------------------------"
echo "Topology Details:"
echo " Client (ns_client)       Router (ns_router)        Server (ns_server)"
echo " [ 10.0.0.2 ] -------- [ 10.0.0.254 | fd00::1 ] -------- [ fd00::2 ]"
echo "                         (eBPF goes here)"
echo "--------------------------------------------------------"

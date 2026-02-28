#!/usr/bin/env bash

namespaces=($@)

function cleanup() {
  echo "dropping iptables log rule"
  for ns in "${namespaces[@]}"; do
    ip netns exec $ns iptables -D FORWARD 1
  done
}

for ns in "${namespaces[@]}"; do
  ip netns exec $ns iptables -I FORWARD 1 -m conntrack --ctstate INVALID -j LOG --log-prefix "INVALID_DROPPED: "
done
trap cleanup SIGINT
echo "watching dmesg..."
dmesg -w | grep INVALID_DROPPED

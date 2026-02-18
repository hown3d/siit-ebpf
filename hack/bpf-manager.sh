#!/usr/bin/env bash

ipv4="192.168.1.1"
ipv6="2a05:b540:cadd::2"
dst_ipv6="2a05:b540:cadd::4"
pool="2a05:b540:dead:beef::/96"

manager_image=$1
if [[ -z $1 ]]; then
  echo "set manager image"
  exit 1
fi

function pwru() {
  docker build -t cilium/pwru https://github.com/cilium/pwru.git
  docker run --privileged --name pwru -d --pid=host -v /sys/kernel/debug/:/sys/kernel/debug/ cilium/pwru \
    pwru \
    --filter-trace-tc \
    "host 10.0.0.1 or host ${dst_ipv6}"
}

function netns() {
  local container=$1
  local net=container:${container}
  if [[ -z ${container} ]]; then
    net=host
  fi
  docker run --rm --net=${net} nicolaka/netshoot lsns -t net -o NS -n -r
}

function veth_of_container() {
  local id=$1
  local iface=$2
  link=$(docker exec ${id} cat /sys/class/net/${iface}/iflink)
  veth=$(docker run --rm --network=host -v /sys/class/net:/sys/class/net debian sh -c "grep -l ${link} /sys/class/net/veth*/ifindex")
  veth=$(echo ${veth} | sed -e 's;^.*net/\(.*\)/ifindex$;\1;')
  echo ${veth}
}

docker network create --subnet="192.168.0.0/16" customer
docker network create --subnet="2a05:b540:cadd::/64" --ipv6 management
customer_network_id=$(docker network ls -f name=customer --format json | jq -r ".ID")
management_network_id=$(docker network ls -f name=management --format json | jq -r ".ID")

docker run -d --name tcpdump \
  --network management \
  --ip6="${dst_ipv6}" \
  nicolaka/netshoot \
  tcpdump -A "host 10.0.0.1 or host ${dst_ipv6}"

docker run -d --name pause --network management --ip6="${ipv6}" registry.k8s.io/pause:3.6
pwru

docker network connect --ip="${ipv4}" customer pause

#--ipc=container:pause
docker run -d --name manager \
  --net=container:pause \
  --pid=container:pause \
  --privileged -d \
  -v /sys/kernel/tracing:/sys/kernel/tracing \
  ${manager_image} \
  -host-ipv4="${ipv4}" -host-ipv6="${ipv6}" \
  -pool=${pool} \
  -ipv4="10.0.0.1" -ipv6="${dst_ipv6}"

containers=(
  "manager"
  "tcpdump"
)
ifaces=(
  "eth0"
  "eth1"
)

echo "host netns $(netns)"
for container in ${containers[@]}; do
  ns=$(netns ${container})
  echo "${container} netns: $ns"

  id=$(docker container inspect --format "{{.ID}}" ${container})
  for iface in ${ifaces[@]}; do
    veth=$(veth_of_container ${id} ${iface})
    if [[ -n ${veth}] ]]; then
      echo "${container} ${iface} veth: ${veth}"
    fi
  done
done

docker run --privileged --network host nicolaka/netshoot sh -c "ip r add 10.0.0.1/32 via ${ipv4} dev br-${customer_network_id} || true"
docker run --privileged --network host nicolaka/netshoot sh -c "ip -f inet6 route add ${pool} via ${ipv6} dev br-${management_network_id} || true"

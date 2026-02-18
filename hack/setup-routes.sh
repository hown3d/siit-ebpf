#!/usr/bin/env bash

set -o nounset
set -o pipefail

manager_ipv4="10.255.0.2"
manager_ipv6="2a05:b540:cadd::2"
ipv4=""
pool=""

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
    --help | -h)
      print_help
      exit 1
      ;;

    esac
    shift
  done
}

bridge_interface_for_docker_network() {
  local name=$1
  net_id=$(docker network ls --filter label=com.docker.compose.project=siit-ebpf --filter label=com.docker.compose.network="${name}" --format json | jq -r ".ID")
  echo "br-${net_id}"
}

parse_flags "$@"

ip r add "${ipv4}"/32 via "${manager_ipv4}" dev "$(bridge_interface_for_docker_network "ipv4")"
ip -f inet6 route add "${pool}" via "${manager_ipv6}" dev "$(bridge_interface_for_docker_network "ipv6")"

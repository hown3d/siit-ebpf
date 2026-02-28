#!/usr/bin/env bash
set -eo pipefail
if command -v pwru; then
  pwru "$@"
else
  if ! docker image ls | grep pwru; then
    docker build -t pwru https://github.com/cilium/pwru.git
  fi
  docker run --privileged -t --pid=host --network=host -v /sys/kernel:/sys/kernel --rm --entrypoint=pwru pwru "$@"
fi

# pwru:
#   init: true
#   build:
#     context: https://github.com/cilium/pwru.git
#   privileged: true
#   tty: true
#   entrypoint: pwru
#   command:
#     - --filter-trace-tc
#     - "host 10.0.0.1 or host 2a05:b540:cadd::4 or net fe80:dead:beef::/96"
#   volumes:
#     - /sys/kernel/debug/:/sys/kernel/debug/
#   pid: host
#   network_mode: host
#

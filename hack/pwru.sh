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

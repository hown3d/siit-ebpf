#!/usr/bin/env bash
set -eo pipefail

if command -v bpftool; then
  bpftool "$@"
else
  if ! docker image ls | grep bpftool; then
    docker build -t bpftool https://github.com/libbpf/bpftool.git
  fi

  docker run -v /sys/kernel:/sys/kernel bpftool "$@"
fi

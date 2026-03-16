#!/usr/bin/env bash

set -eo pipefail

# docker build --platform=linux/${ARCH} -t cilium/ebpf-builder https://github.com/cilium/ebpf.git#main:testdata/docker
# cat <<EOF | docker build -f - --platform=linux/${ARCH} -t cilium/ebpf-builder-gnu .
# FROM cilium/ebpf-builder
# RUN apt-get update
# RUN apt-get install -y file
# EOF

tmp=$(mktemp -d)
echo $tmp
# Download and process vmlinux and btf_testmod
crane export --platform=linux/${ARCH} "ghcr.io/cilium/ci-kernels:$KERNEL_VERSION" | tar -x -C "$tmp"

docker run --platform=linux/${ARCH} -v $tmp:$tmp -i libbpf /usr/local/bin/extract-vmlinux "$tmp/boot/vmlinuz" >"$tmp/vmlinux"

docker run --platform=linux/${ARCH} -v $tmp:$tmp -i libbpf file "$tmp/vmlinux"
docker run --platform=linux/${ARCH} -v $tmp:$tmp -i libbpf objcopy --dump-section .BTF=/dev/stdout "$tmp/vmlinux" /dev/null | gzip >"$tmp/vmlinux.btf.gz"

mv $tmp/vmlinux.btf.gz internal/bpf/testdata/vmlinux.btf.gz

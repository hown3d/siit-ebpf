package bpf

//go:generate go tool github.com/cilium/ebpf/cmd/bpf2go -tags linux siit siit/siit.c -- -I./siit/include/
//go:generate go tool gentypes ./testdata/vmlinux.btf.gz

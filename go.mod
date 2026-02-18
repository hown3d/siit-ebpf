module github.com/hown3d/siit-ebpf

go 1.25.3

tool github.com/cilium/ebpf/cmd/bpf2go

require (
	github.com/cilium/ebpf v0.20.0
	github.com/google/gopacket v1.1.19
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/sys v0.41.0
	k8s.io/klog/v2 v2.130.1
)

require (
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sync v0.18.0 // indirect
)

module github.com/hown3d/siit-ebpf

go 1.25.3

tool (
	github.com/cilium/ebpf/cmd/bpf2go
	github.com/hown3d/siit-ebpf/internal/bpf/testdata/gentypes
)

require (
	connectrpc.com/connect v1.19.1
	connectrpc.com/grpcreflect v1.3.0
	connectrpc.com/validate v0.6.0
	github.com/cilium/ebpf v0.20.0
	github.com/go-logr/logr v1.4.3
	github.com/google/gopacket v1.1.19
	github.com/lorenzosaino/go-sysctl v0.3.1
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/sync v0.18.0
	golang.org/x/sys v0.41.0
	google.golang.org/protobuf v1.36.11
	k8s.io/klog/v2 v2.130.1
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.9-20250912141014-52f32327d4b0.1 // indirect
	buf.build/go/protovalidate v1.0.0 // indirect
	cel.dev/expr v0.24.0 // indirect
	github.com/BurntSushi/toml v1.1.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/google/cel-go v0.26.1 // indirect
	github.com/stoewer/go-strcase v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/exp v0.0.0-20250911091902-df9299821621 // indirect
	golang.org/x/exp/typeparams v0.0.0-20220613132600-b0d781184e0d // indirect
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616 // indirect
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	golang.org/x/tools v0.38.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250922171735-9219d122eba9 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250922171735-9219d122eba9 // indirect
	honnef.co/go/tools v0.3.2 // indirect
)

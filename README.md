# SIIT (Stateless IP/ICMP Translation) in eBPF

## Get started locally

> [!WARNING]
> If you are not on linux, make sure that you run the marked commands inside your Linux VM

1. `make build` builds the manager binary
2. setup the Testbed: Linux: `make setup-routes`
3. Linux: `make NETNS=ns_router run`

### Testbed

The Testbed is configured to use 3 network namespaces for isolation for:

- Manager
- Server
- Client

### Manager

The manager (also known as router) is running inside this namespace.
All traffic from the client and server namespace flow through this namespace to ensure SIIT can happen on the siit device created by the manager binary>

### Client

This namespace is used for sending packets from a client to ensure it is not able to directly talk to the server

### Server

A Python HTTP server is listening here on every IPv6 address with port 80.

## Development

This projects uses [cilium/epbf](https://github.com/cilium/ebpf) library to load the SIIT program into the kernel.

### Compiling eBPF code

A [Dockerfile](./Dockerfile) is setup to run compilation steps inside a container:

```bash
make go-generate
```

### Debugging traffic

There are several make targets that you can run:

```
# tcpdump captures traffic from the client/server network or pool range
$ make tcpdump # can be run inside network namespaces with ip netns exec <ns_router/ns_server/ns_client>

# pwru can be used to trace packets through the kernel
$ make pwru
```

You can debug fib_lookups of the kernel using a provided bpftrace script:

```
sudo bpftrace ./internal/bpf/testutil/fib_lookup_trace.bpftrace.d
```

### Tests

Integration tests for the ebpf program are located at [./internal/bpf/bpf_test.go](./internal/bpf/bpf_test.go)
Run using `make ebpf-test`, which will run the tests inside a docker container.

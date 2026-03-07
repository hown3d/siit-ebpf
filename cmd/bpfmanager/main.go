package main

import (
	"context"
	"flag"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/hown3d/siit-ebpf/internal/bpf"
)

var (
	ipv4 = flag.String("ipv4", "", "ipv4 address to map to ipv6")
	ipv6 = flag.String("ipv6", "", "ipv6 address")
	pool = flag.String("pool", "", "pool used for address translation")
)

func main() {
	flag.Parse()
	ctx := setupSignalHandler()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("error removing memlock, neccessary for ebpf: %s", err)
	}

	pool := netip.MustParsePrefix(*pool)

	manager, err := bpf.NewManager(pool)
	if err != nil {
		log.Fatal(err)
	}
	defer manager.Close()

	if err := manager.SetupLinks(); err != nil {
		log.Fatal(err)
	}

	err = manager.AddEntry(bpf.Entry{
		IPv4: netip.MustParseAddr(*ipv4),
		IPv6: netip.MustParseAddr(*ipv6),
	})
	if err != nil {
		log.Fatal(err)
	}

	<-ctx.Done()
}

var shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

// setupSignalHandler registers for SIGTERM and SIGINT. A context is returned
// which is canceled on one of these signals. If a second signal is caught, the program
// is terminated with exit code 1.
func setupSignalHandler() context.Context {
	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 2)
	signal.Notify(c, shutdownSignals...)
	go func() {
		<-c
		cancel()
		<-c
		os.Exit(1) // second signal. Exit directly.
	}()

	return ctx
}

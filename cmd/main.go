package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/go-logr/logr"
	"github.com/hown3d/siit-ebpf/internal/api"
	"github.com/hown3d/siit-ebpf/internal/bpf"
)

var (
	ipv4           = flag.String("ipv4", "", "ipv4 address to map to ipv6")
	ipv6           = flag.String("ipv6", "", "ipv6 address")
	pool           = flag.String("pool", "", "pool used for address translation")
	grpcReflection = flag.Bool("grpc-reflection", false, "enable grpc reflection")
	tcpAddr        = flag.String("tcp-addr", "", "serve API on tcp address rather than unix socket")
)

func main() {
	flag.Parse()
	ctx := setupSignalHandler()
	if err := run(ctx); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("error removing memlock, neccessary for ebpf: %s", err)
	}

	logOpts := slog.HandlerOptions{
		AddSource: true,
		Level:     slog.Level(-1),
	}
	handler := slog.NewJSONHandler(os.Stderr, &logOpts)
	log := logr.FromSlogHandler(handler)

	pool := netip.MustParsePrefix(*pool)

	manager, err := bpf.NewManager(log.WithName("bpf-manager"), pool)
	if err != nil {
		log.Error(err, "creating manager")
		return err
	}
	defer manager.Close()

	if err := manager.SetupLinks(); err != nil {
		return err
	}

	err = manager.AddEntry(bpf.Entry{
		IPv4: netip.MustParseAddr(*ipv4),
		IPv6: netip.MustParseAddr(*ipv6),
	})
	if err != nil {
		return err
	}

	opts := []api.Option{}
	if *grpcReflection {
		opts = append(opts, api.WithReflection())
	}
	if *tcpAddr != "" {
		opts = append(opts, api.WithTCPListener(*tcpAddr))
	}

	a, err := api.New(manager, opts...)
	if err != nil {
		return fmt.Errorf("setup API: %w", err)
	}
	if err := a.Serve(ctx); err != nil {
		return fmt.Errorf("error serving: %w", err)
	}
	return nil
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

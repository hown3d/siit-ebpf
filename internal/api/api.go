package api

import (
	"context"
	"log"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/grpcreflect"
	"connectrpc.com/validate"
	"github.com/hown3d/siit-ebpf/internal/bpf"
	"github.com/hown3d/siit-ebpf/pkg/apis/siit/v1alpha1/v1alpha1connect"
	"golang.org/x/sync/errgroup"
)

const SocketPath = "/run/siit.sock"

type API struct {
	lis    net.Listener
	server *http.Server

	// options
	reflection bool
	addr       string
}

type Option func(*API)

func WithReflection() Option {
	return func(a *API) {
		a.reflection = true
	}
}

func WithTCPListener(addr string) Option {
	return func(a *API) {
		a.addr = addr
	}
}

func New(manager *bpf.Manager, opts ...Option) (*API, error) {
	eamtService := &EAMTService{manager: manager}
	mux := http.NewServeMux()
	path, handler := v1alpha1connect.NewEAMTServiceHandler(
		eamtService,
		// Validation via Protovalidate is almost always recommended
		connect.WithInterceptors(validate.NewInterceptor()),
	)
	mux.Handle(path, handler)
	p := new(http.Protocols)
	p.SetHTTP1(true)
	// Use h2c so we can serve HTTP/2 without TLS.
	p.SetUnencryptedHTTP2(true)

	a := &API{
		addr:   SocketPath,
		server: &http.Server{Handler: mux, Protocols: p},
	}
	for _, o := range opts {
		o(a)
	}

	if err := a.setupListener(); err != nil {
		return nil, err
	}
	if a.reflection {
		log.Println("enabling reflection")
		setupReflection(mux)
	}
	return a, nil
}

func (a *API) Serve(ctx context.Context) error {
	log.Println("serving on", a.lis.Addr())
	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return a.server.Serve(a.lis)
	})
	g.Go(func() error {
		<-gCtx.Done()
		timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return a.server.Shutdown(timeoutCtx)
	})

	return g.Wait()
}

func setupReflection(mux *http.ServeMux) {
	reflector := grpcreflect.NewStaticReflector(
		v1alpha1connect.EAMTServiceName,
	)
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))
}

func (a *API) setupListener() error {
	network := "unix"
	if a.addr != SocketPath {
		network = "tcp"
	}
	lis, err := net.Listen(network, a.addr)
	if err != nil {
		return err
	}
	a.lis = lis
	return nil
}

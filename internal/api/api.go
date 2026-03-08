package api

import (
	"context"
	"log"
	"net"
	"net/http"

	"connectrpc.com/connect"
	"connectrpc.com/validate"
	"github.com/hown3d/siit-ebpf/internal/bpf"
	siit "github.com/hown3d/siit-ebpf/pkg/apis/siit/v1alpha1"
	"github.com/hown3d/siit-ebpf/pkg/apis/siit/v1alpha1/helpers"
	"github.com/hown3d/siit-ebpf/pkg/apis/siit/v1alpha1/v1alpha1connect"
	"golang.org/x/sync/errgroup"
)

type EAMTService struct {
	manager *bpf.Manager
}

var _ v1alpha1connect.EAMTServiceHandler = (*EAMTService)(nil)

// Create implements v1alpha1connect.EAMTServiceHandler.
func (e *EAMTService) Create(_ context.Context, req *siit.CreateRequest) (*siit.CreateResponse, error) {
	// TODO: support multiple pools
	entry, err := bpfEntryFromProto(req.Entry)
	if err != nil {
		return nil, err
	}
	if err := e.manager.AddEntry(entry); err != nil {
		return nil, err
	}
	return &siit.CreateResponse{}, nil
}

// Delete implements v1alpha1connect.EAMTServiceHandler.
func (e *EAMTService) Delete(_ context.Context, req *siit.DeleteRequest) (*siit.DeleteResponse, error) {
	// TODO: support multiple pools
	entry, err := bpfEntryFromProto(req.Entry)
	if err != nil {
		return nil, err
	}
	if err := e.manager.DeleteEntry(entry); err != nil {
		return nil, err
	}
	return &siit.DeleteResponse{}, nil
}

// List implements v1alpha1connect.EAMTServiceHandler.
func (e *EAMTService) List(context.Context, *siit.ListRequest) (*siit.ListResponse, error) {
	entries, err := e.manager.ListEntries()
	if err != nil {
		return nil, err
	}
	eamtEntries := make([]*siit.EAMTEntry, 0, len(entries))
	for _, e := range entries {
		eamtEntries = append(eamtEntries, &siit.EAMTEntry{
			Ipv4: helpers.IPv4ToProto(e.IPv4),
			Ipv6: helpers.IPv6ToProto(e.IPv6),
		})
	}
	return &siit.ListResponse{
		Entries: eamtEntries,
	}, nil
}

func bpfEntryFromProto(protoEntry *siit.EAMTEntry) (bpf.Entry, error) {
	ip4, err := helpers.IPv4FromProto(protoEntry.Ipv4)
	if err != nil {
		return bpf.Entry{}, connect.NewError(connect.CodeInvalidArgument, err)
	}
	ip6, err := helpers.IPv6FromProto(protoEntry.Ipv6)
	if err != nil {
		return bpf.Entry{}, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return bpf.Entry{
		IPv4: ip4,
		IPv6: ip6,
	}, nil
}

type API struct {
	lis    net.Listener
	server *http.Server
}

func New(manager *bpf.Manager) (*API, error) {
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
	lis, err := net.ListenUnix("unix", &net.UnixAddr{
		Net:  "unix",
		Name: "/run/siit.sock",
	})
	if err != nil {
		return nil, err
	}
	return &API{
		lis:    lis,
		server: &http.Server{Handler: handler},
	}, nil
}

func (a *API) Serve(ctx context.Context) error {
	log.Println("serving on", a.lis.Addr())
	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return a.server.Serve(a.lis)
	})
	g.Go(func() error {
		<-gCtx.Done()
		return a.server.Shutdown(context.Background())
	})

	return g.Wait()
}

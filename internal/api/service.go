package api

import (
	"context"

	"connectrpc.com/connect"
	"github.com/hown3d/siit-ebpf/internal/bpf"
	siit "github.com/hown3d/siit-ebpf/pkg/apis/siit/v1alpha1"
	"github.com/hown3d/siit-ebpf/pkg/apis/siit/v1alpha1/helpers"
	"github.com/hown3d/siit-ebpf/pkg/apis/siit/v1alpha1/v1alpha1connect"
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

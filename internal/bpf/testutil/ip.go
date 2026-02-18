package testutil

import (
	"fmt"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func ConvertIP6ToIP4(v6 netip.Addr) netip.Addr {
	a16 := v6.As16()
	a4 := [4]byte(a16[12:16])
	return netip.AddrFrom4(a4)
}

func IPsFromFlow(flow gopacket.Flow) (src, dst netip.Addr, err error) {
	srcEp, dstEp := flow.Endpoints()
	src, err = ipFromEndpoint(srcEp)
	if err != nil {
		return src, dst, err
	}
	dst, err = ipFromEndpoint(dstEp)
	if err != nil {
		return src, dst, err
	}
	return
}

func ipFromEndpoint(ep gopacket.Endpoint) (netip.Addr, error) {
	switch t := ep.EndpointType(); t {
	case layers.EndpointIPv4:
		return netip.AddrFrom4([4]byte(ep.Raw())), nil
	case layers.EndpointIPv6:
		return netip.AddrFrom16([16]byte(ep.Raw())), nil
	default:
		return netip.Addr{}, fmt.Errorf("endpoint %s has unknown endpoint type: %s", ep, t)
	}
}

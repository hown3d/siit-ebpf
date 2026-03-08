package helpers

import (
	"errors"
	"net/netip"

	"github.com/hown3d/siit-ebpf/pkg/apis/siit/v1alpha1"
)

func IPv4FromProto(ip *v1alpha1.IPAddress) (netip.Addr, error) {
	ip4, err := netip.ParseAddr(ip.GetIpv4())
	if err != nil {
		return netip.Addr{}, err
	}
	if !ip4.Is4() {
		return netip.Addr{}, errors.New("ip4 address is not ipv4")
	}
	return ip4, nil
}

func IPv6FromProto(ip *v1alpha1.IPAddress) (netip.Addr, error) {
	ip6, err := netip.ParseAddr(ip.GetIpv6())
	if err != nil {
		return netip.Addr{}, err
	}
	if !ip6.Is6() {
		return netip.Addr{}, errors.New("ip6 address is not ipv6")
	}
	return ip6, nil
}

func IPv6ToProto(ip netip.Addr) *v1alpha1.IPAddress {
	return &v1alpha1.IPAddress{
		Ip: &v1alpha1.IPAddress_Ipv6{
			Ipv6: ip.String(),
		},
	}
}

func IPv4ToProto(ip netip.Addr) *v1alpha1.IPAddress {
	return &v1alpha1.IPAddress{
		Ip: &v1alpha1.IPAddress_Ipv4{
			Ipv4: ip.String(),
		},
	}
}

package link

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

func EnsureUp(l netlink.Link) error {
	if l.Attrs().Flags&net.FlagUp == 0 {
		if err := netlink.LinkSetUp(l); err != nil {
			return err
		}
	}
	return nil
}

func FindWithAddress(ip netip.Addr) (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	var netIP net.IP = ip.AsSlice()
	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if addr.IP.Equal(netIP) {
				return link, nil
			}
		}
	}
	return nil, fmt.Errorf("no link found with ip %s", ip)
}

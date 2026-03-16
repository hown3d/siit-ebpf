package bpf

import (
	"fmt"

	"github.com/hown3d/siit-ebpf/internal/mac"
	"github.com/hown3d/siit-ebpf/internal/sysctl"
	"github.com/vishvananda/netlink"
)

func setupBaseDevice() (netlink.Link, netlink.Link, error) {
	if err := setupVethPair(HostDevice, SecondHostDevice); err != nil {
		return nil, nil, fmt.Errorf("failed to setup veth pair: %w", err)
	}

	linkHost, err := netlink.LinkByName(HostDevice)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get link for %s: %w", HostDevice, err)
	}
	linkPeer, err := netlink.LinkByName(SecondHostDevice)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get link for %s: %w", SecondHostDevice, err)
	}

	if err := netlink.LinkSetARPOff(linkHost); err != nil {
		return nil, nil, fmt.Errorf("failed to set ARP off for %s: %w", linkHost.Attrs().Name, err)
	}
	if err := netlink.LinkSetARPOff(linkPeer); err != nil {
		return nil, nil, fmt.Errorf("failed to set ARP off for %s: %w", linkPeer.Attrs().Name, err)
	}

	return linkHost, linkPeer, nil
}

func setupVethPair(name, peerName string) error {
	// Create the veth pair if it doesn't exist.
	if _, err := netlink.LinkByName(name); err != nil {
		hostMac, err := mac.GenerateRandMAC()
		if err != nil {
			return fmt.Errorf("failed to generate random MAC address for host: %w", err)
		}
		peerMac, err := mac.GenerateRandMAC()
		if err != nil {
			return fmt.Errorf("failed to generate random MAC address for peer: %w", err)
		}

		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name:         name,
				HardwareAddr: hostMac,
				TxQLen:       1000,
			},
			PeerName:         peerName,
			PeerHardwareAddr: peerMac,
		}
		if err := netlink.LinkAdd(veth); err != nil {
			return fmt.Errorf("failed to add veth pair: %w", err)
		}
	}

	for _, linkName := range []string{name, peerName} {
		l, err := netlink.LinkByName(linkName)
		if err != nil {
			return fmt.Errorf("failed to get link by name %s: %w", name, err)
		}

		if err := netlink.LinkSetUp(l); err != nil {
			return fmt.Errorf("failed to set link %s up: %w", l.Attrs().Name, err)
		}
		if err := enableForwarding(l); err != nil {
			return fmt.Errorf("failed to enable forwarding on link %s: %w", l.Attrs().Name, err)
		}
	}

	return nil
}

func enableForwarding(link netlink.Link) error {
	ifName := link.Attrs().Name

	sysSettings := []sysctl.Sysctl{
		{Name: []string{"net", "ipv6", "conf", ifName, "forwarding"}, Val: "1", IgnoreErr: false},
		{Name: []string{"net", "ipv4", "conf", ifName, "forwarding"}, Val: "1", IgnoreErr: false},
		{Name: []string{"net", "ipv4", "conf", ifName, "rp_filter"}, Val: "0", IgnoreErr: false},
		{Name: []string{"net", "ipv4", "conf", ifName, "accept_local"}, Val: "1", IgnoreErr: false},
		{Name: []string{"net", "ipv4", "conf", ifName, "send_redirects"}, Val: "0", IgnoreErr: false},
	}
	if err := sysctl.ApplySettings(sysSettings); err != nil {
		return fmt.Errorf("failed to apply sysctl settings for %s: %w", ifName, err)
	}

	return nil
}

//go:build linux

package bpf

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hown3d/siit-ebpf/internal/bpf/testutil"
	"github.com/hown3d/siit-ebpf/internal/netns"
	"github.com/vishvananda/netlink"
)

const TC_ACT_OK = 0x0

var testPrefix = netip.MustParsePrefix("2001:db8:cafe::/96")

func TestManager_Siit46(t *testing.T) {
	kernelTraceReader, err := testutil.KernelTraceReader()
	if err != nil {
		t.Fatalf("creating kernel trace reader: %s", err)
	}

	m, err := NewManager(testPrefix)
	if err != nil {
		t.Fatalf("setup ebpf manager: %s", err)
	}

	t.Cleanup(func() {
		if err := kernelTraceReader.Clear(); err != nil {
			t.Logf("WARNING: unable to clear kernel traces: %s", err)
		}
		kernelTraceReader.Close()
		m.Close()
	})

	src := netip.MustParseAddr("10.0.2.1")
	expectedNewDst := netip.MustParseAddr("2001:db8::68")
	dst := netip.MustParseAddr("10.0.4.2")

	err = m.AddEntry(Entry{
		IPv4: dst,
		IPv6: expectedNewDst,
	})
	if err != nil {
		t.Fatal(err)
	}

	in, err := ipv4Packet(src, dst)
	if err != nil {
		t.Fatalf("building ipv4 packet: %s", err)
	}

	ns, err := netns.New()
	if err != nil {
		t.Fatalf("creating network namespace: %s", err)
	}

	v4Link := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: "v4",
		},
	}

	v6Link := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: "v6",
		},
	}

	var (
		outData []byte
		ret     uint32
	)
	if err := ns.Do(
		func() error {
			if err := m.SetupLinks(); err != nil {
				return err
			}
			if err := setupTestLink(v4Link); err != nil {
				return fmt.Errorf("setup v4 link: %w", err)
			}
			if err := setupTestLink(v6Link); err != nil {
				return fmt.Errorf("setup v6 link: %w", err)
			}

			v6Route := &netlink.Route{
				Family:    netlink.FAMILY_V6,
				LinkIndex: v6Link.Index,
				Dst: &net.IPNet{
					IP:   testPrefix.Addr().AsSlice(),
					Mask: net.CIDRMask(testPrefix.Bits(), testPrefix.Addr().BitLen()),
				},
			}
			t.Logf("setup v6 route: %s", v6Route)
			if err := netlink.RouteAdd(v6Route); err != nil {
				return fmt.Errorf("setup v6 route: %w", err)
			}

			if err := logRoutes(t, netlink.FAMILY_V6); err != nil {
				return fmt.Errorf("logging ipv6 routes: %w", err)
			}

			if err := logRoutes(t, netlink.FAMILY_V4); err != nil {
				return fmt.Errorf("logging ipv6 routes: %w", err)
			}

			ret, outData, err = m.bpfObjs.Siit.Test(in)
			if err != nil {
				t.Fatalf("testing ebpf program: %s", err)
			}

			return nil
		}); err != nil {
		t.Fatalf("setup links in network namespace: %s", err)
	}

	t.Cleanup(func() {
		ns.Close()
	})

	traces, err := io.ReadAll(kernelTraceReader)
	if err != nil {
		t.Logf("WARNING: failed to read kernel traces: %s", err)
	} else {
		t.Logf("ebpf program traces:\n%s", traces)
	}

	packet := testutil.DecodePacket(outData)
	t.Log("ebpf program ran, printing packet")
	t.Log(packet.Dump())
	if ret != TC_ACT_OK {
		t.Fatalf("ebpf program returned code != TC_ACT_OK: %d", ret)
	}

	flow := packet.NetworkLayer().NetworkFlow()
	t.Logf("new packet flow:\n%s", flow)

	newSrc, newDst, err := testutil.IPsFromFlow(flow)
	if err != nil {
		t.Errorf("error: parsing ips from flow: %s", err)
	}

	if !newSrc.Is6() {
		t.Errorf("error: new source %s is not ipv6", newSrc)
	}
	if !newDst.Is6() {
		t.Errorf("error: new dest %s is not ipv6", newSrc)
	}

	if newDst.Compare(expectedNewDst) != 0 {
		t.Errorf("error: new dest %s != expected %s", newDst, expectedNewDst)
	}

	if !testPrefix.Contains(newSrc) {
		t.Errorf("error: new source %s is not in test prefix %s", newSrc, testPrefix)
	}

	newSrcv4 := testutil.ConvertIP6ToIP4(newSrc)
	if newSrcv4.Compare(src) != 0 {
		t.Errorf("new src in v4 %s != expected %s", newSrcv4, src)
	}
}

func ipv4Packet(src, dst netip.Addr) ([]byte, error) {
	srcMac, err := net.ParseMAC("00:11:22:33:44:55")
	if err != nil {
		return nil, err
	}
	dstMac, err := net.ParseMAC("66:77:88:99:AA:BB")
	if err != nil {
		return nil, err
	}

	eth := &layers.Ethernet{
		// irrelevant, just to fill packet
		SrcMAC: srcMac,
		// irrelevant, just to fill packet
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{
		SrcIP:    src.AsSlice(),
		DstIP:    dst.AsSlice(),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		// Don't fragment
		FragOffset: syscall.IP_DF,
	}
	tcp := &layers.TCP{}
	opts := gopacket.SerializeOptions{
		FixLengths: true,
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, opts, eth, ipv4, tcp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ipv6Packet(src, dst netip.Addr) ([]byte, error) {
	srcMac, err := net.ParseMAC("00:11:22:33:44:55")
	if err != nil {
		return nil, err
	}
	dstMac, err := net.ParseMAC("66:77:88:99:AA:BB")
	if err != nil {
		return nil, err
	}

	eth := &layers.Ethernet{
		// irrelevant, just to fill packet
		SrcMAC: srcMac,
		// irrelevant, just to fill packet
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipv6 := &layers.IPv6{
		SrcIP:   src.AsSlice(),
		DstIP:   dst.AsSlice(),
		Version: 6,
	}
	tcp := &layers.TCP{}
	opts := gopacket.SerializeOptions{
		FixLengths: true,
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, opts, eth, ipv6, tcp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func setupTestLink(l netlink.Link) error {
	if err := netlink.LinkAdd(l); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return fmt.Errorf("failed to set link up: %w", err)
	}

	return enableForwarding(l)
}

func logRoutes(t *testing.T, family int) error {
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return err
	}
	for _, r := range routes {
		t.Logf("route %s", r)
	}
	return nil
}

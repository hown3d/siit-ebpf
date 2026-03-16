//go:build linux

package bpf

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/go-logr/logr/testr"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hown3d/siit-ebpf/internal/bpf/testutil"
	"github.com/hown3d/siit-ebpf/internal/mac"
	"github.com/hown3d/siit-ebpf/internal/netns"
	"github.com/vishvananda/netlink"
)

const (
	TC_ACT_OK       = 0x0
	TC_ACT_REDIRECT = 0x7
)

var testPrefix = netip.MustParsePrefix("64:ff9b:dead:beef::/96")

func TestManager_Siit46(t *testing.T) {
	kernelTraceReader, err := testutil.KernelTraceReader()
	if err != nil {
		t.Fatalf("creating kernel trace reader: %s", err)
	}

	m, err := NewManager(testr.New(t), testPrefix)
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
	expectedNewDst := netip.MustParseAddr("fd00::2")
	dst := netip.MustParseAddr("10.0.4.2")

	v4Mac := must(t, mac.GenerateRandMAC)
	v6PeerMac := must(t, mac.GenerateRandMAC)
	v6Mac := must(t, mac.GenerateRandMAC)
	dstMac := must(t, mac.GenerateRandMAC)
	t.Logf("v4 Mac %s", v4Mac)
	t.Logf("v6 Mac %s", v6Mac)
	t.Logf("v6 Peer Mac %s", v6PeerMac)
	t.Logf("dst mac %s", dstMac)

	srcInfo := packetInfo{
		mac: v4Mac,
		ip:  src,
	}
	dstInfo := packetInfo{
		ip: dst,
	}

	routerns, err := netns.New()
	if err != nil {
		t.Fatalf("creating router network namespace: %s", err)
	}

	serverns, err := netns.New()
	if err != nil {
		t.Fatalf("creating server network namespace: %s", err)
	}

	t.Cleanup(func() {
		routerns.Close()
		serverns.Close()
	})

	v6Link := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:         "v6-router",
			HardwareAddr: v6Mac,
		},
		PeerHardwareAddr: v6PeerMac,
		PeerName:         "v6-server",
	}

	if err := routerns.Do(func() error {
		if err := setupTestLink(v6Link); err != nil {
			t.Fatalf("creating testlink: %s", err)
		}

		v6PeerLink, err := netlink.LinkByName("v6-server")
		if err != nil {
			return err
		}
		if err := netlink.LinkSetNsFd(v6PeerLink, serverns.FD()); err != nil {
			return err
		}

		if err := m.SetupLinks(); err != nil {
			return fmt.Errorf("setup manager links: %w", err)
		}
		err = m.AddEntry(Entry{
			IPv4: dst,
			IPv6: expectedNewDst,
		})
		if err != nil {
			return fmt.Errorf("adding entry to manager: %w", err)
		}

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	t.Log("server network namespace links")
	if err := serverns.Do(func() error {
		return logLinks(t)
	}); err != nil {
		t.Fatal(err)
	}

	t.Log("router network namespace links")
	if err := routerns.Do(func() error {
		return logLinks(t)
	}); err != nil {
		t.Fatal(err)
	}

	var (
		packet gopacket.Packet
		ret    uint32
	)

	if err := routerns.Do(
		func() error {
			if err := netlink.RouteAdd(&netlink.Route{
				LinkIndex: v6Link.Index,
				Dst: &net.IPNet{
					IP:   expectedNewDst.AsSlice(),
					Mask: net.CIDRMask(expectedNewDst.BitLen(), expectedNewDst.BitLen()),
				},
			}); err != nil {
				return fmt.Errorf("creating v6 route: %w", err)
			}

			t.Log("v6 routes in router network namespace")
			if err := logRoutes(t, netlink.FAMILY_V6); err != nil {
				return fmt.Errorf("logging ipv6 routes: %w", err)
			}

			t.Log("v6 routes in router network namespace")
			if err := logRoutes(t, netlink.FAMILY_V4); err != nil {
				return fmt.Errorf("logging ipv6 routes: %w", err)
			}

			hostLink, err := netlink.LinkByName(SecondHostDevice)
			if err != nil {
				return fmt.Errorf("getting host link: %w", err)
			}

			in, err := ipv4Packet(srcInfo, dstInfo)
			if err != nil {
				t.Fatalf("building ipv4 packet: %s", err)
			}

			// TODO: at the moment fib_lookup returns BPF_FIB_LKUP_RET_NO_NEIGH because they kernel does not know about the Mac of expectedNewDst yet.
			// Create this entry in the neighbour table directly using netlink.NeighAdd.

			ret, packet, _, err = testEbpf(m.bpfObjs.Siit, in, uint32(hostLink.Attrs().Index))
			if err != nil {
				t.Fatalf("testing ebpf program: %s", err)
			}

			return nil
		}); err != nil {
		t.Fatalf("setup links in network namespace: %s", err)
	}

	traces, err := io.ReadAll(kernelTraceReader)
	if err != nil {
		t.Logf("WARNING: failed to read kernel traces: %s", err)
	} else {
		t.Logf("ebpf program traces:\n%s", traces)
	}

	if ret != TC_ACT_REDIRECT {
		t.Fatalf("ebpf program returned code != TC_ACT_REDIRECT: %d", ret)
	}

	ipFlow := packet.NetworkLayer().NetworkFlow()
	linkFlow := packet.LinkLayer().LinkFlow()
	t.Logf("new packet flow:\nlink: %s\nip: %s\n", linkFlow, ipFlow)

	newSrc, newDst, err := testutil.IPsFromFlow(ipFlow)
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

type packetInfo struct {
	mac net.HardwareAddr
	ip  netip.Addr
}

func ipv4Packet(src, dst packetInfo) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       src.mac,
		DstMAC:       dst.mac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{
		SrcIP:    src.ip.AsSlice(),
		DstIP:    dst.ip.AsSlice(),
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

func ipv6Packet(src, dst packetInfo) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       src.mac,
		DstMAC:       dst.mac,
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipv6 := &layers.IPv6{
		SrcIP:   src.ip.AsSlice(),
		DstIP:   dst.ip.AsSlice(),
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

func testEbpf(prog *ebpf.Program, in []byte, ifindex uint32) (uint32, gopacket.Packet, *skBuff, error) {
	const (
		// Number of bytes to pad the output buffer for BPF_PROG_TEST_RUN.
		// This is currently the maximum of spare space allocated for SKB
		// and XDP programs, and equal to XDP_PACKET_HEADROOM + NET_IP_ALIGN.
		outputPad = 256 + 2
	)

	out := make([]byte, len(in)+outputPad)
	skbuff := skBuff{
		Ifindex: ifindex,
	}
	outskBuff := skBuff{}
	opts := &ebpf.RunOptions{
		Data:       in,
		DataOut:    out,
		Context:    skbuff,
		ContextOut: &outskBuff,
	}

	ret, err := prog.Run(opts)
	if err != nil {
		return 0, nil, nil, err
	}
	packet := testutil.DecodePacket(opts.DataOut)
	return ret, packet, &outskBuff, nil
}

func setupTestLink(l netlink.Link) error {
	if err := netlink.LinkAdd(l); err != nil {
		return fmt.Errorf("adding link: %w", err)
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

func logLinks(t *testing.T) error {
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	for _, l := range links {
		t.Logf("link %s: index: %d", l.Attrs().Name, l.Attrs().Index)
	}
	return nil
}

func must[T any](t *testing.T, f func() (T, error)) T {
	obj, err := f()
	if err != nil {
		t.Fatal(err)
	}
	return obj
}

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
	"github.com/hown3d/siit-ebpf/internal/sysctl"
	"github.com/vishvananda/netlink"
)

const TC_ACT_OK = 0x0

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
	v6Mac := must(t, mac.GenerateRandMAC)
	dstMac := must(t, mac.GenerateRandMAC)

	srcInfo := packetInfo{
		mac: must(t, mac.GenerateRandMAC),
		ip:  src,
	}
	dstInfo := packetInfo{
		mac: dstMac,
		ip:  dst,
	}

	ns, err := netns.New()
	if err != nil {
		t.Fatalf("creating network namespace: %s", err)
	}

	in, err := ipv4Packet(srcInfo, dstInfo)
	if err != nil {
		t.Fatalf("building ipv4 packet: %s", err)
	}

	v4Link := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name:         "v4",
			HardwareAddr: v4Mac,
		},
	}

	v6Link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:         "v6",
			HardwareAddr: v6Mac,
		},
	}

	var (
		packet gopacket.Packet
		ret    uint32
	)
	if err := ns.Do(
		func() error {
			if err := m.SetupLinks(); err != nil {
				return err
			}
			err = m.AddEntry(Entry{
				IPv4: dst,
				IPv6: expectedNewDst,
			})
			if err != nil {
				return err
			}

			if err := sysctl.ApplySettings([]sysctl.Sysctl{{
				Name: []string{"net", "ipv4", "ip_forward"},
				Val:  "1",
			}}); err != nil {
				return fmt.Errorf("applying ip_forwarding sysctl: %w", err)
			}
			if err := setupTestLink(v4Link, src); err != nil {
				return fmt.Errorf("setup v4 link: %w", err)
			}
			if err := setupTestLink(v6Link, expectedNewDst); err != nil {
				return fmt.Errorf("setup v6 link: %w", err)
			}

			if err := logRoutes(t, netlink.FAMILY_V6); err != nil {
				return fmt.Errorf("logging ipv6 routes: %w", err)
			}

			if err := logRoutes(t, netlink.FAMILY_V4); err != nil {
				return fmt.Errorf("logging ipv6 routes: %w", err)
			}

			hostLink, err := netlink.LinkByName(SecondHostDevice)
			if err != nil {
				return fmt.Errorf("getting host link: %w", err)
			}

			ret, packet, err = testEbpf(m.bpfObjs.Siit, in, uint32(hostLink.Attrs().Index))
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

func testEbpf(prog *ebpf.Program, in []byte, ifindex uint32) (uint32, gopacket.Packet, error) {
	const (
		// Number of bytes to pad the output buffer for BPF_PROG_TEST_RUN.
		// This is currently the maximum of spare space allocated for SKB
		// and XDP programs, and equal to XDP_PACKET_HEADROOM + NET_IP_ALIGN.
		outputPad = 256 + 2
	)

	out := make([]byte, len(in)+outputPad)
	skbuff := skBuff{
		ifindex: ifindex,
	}
	opts := &ebpf.RunOptions{
		Data:    in,
		DataOut: out,
		Context: skbuff,
	}

	ret, err := prog.Run(opts)
	if err != nil {
		return 0, nil, err
	}
	packet := testutil.DecodePacket(opts.DataOut)
	return ret, packet, nil
}

func setupTestLink(l netlink.Link, addr netip.Addr) error {
	if err := netlink.LinkAdd(l); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return fmt.Errorf("failed to set link up: %w", err)
	}

	linkAddr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", addr.String(), 32))
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(l, linkAddr); err != nil {
		return err
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

func must[T any](t *testing.T, f func() (T, error)) T {
	obj, err := f()
	if err != nil {
		t.Fatal(err)
	}
	return obj
}

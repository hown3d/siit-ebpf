//go:build linux

package bpf

import (
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hown3d/siit-ebpf/internal/bpf/testutil"
	"github.com/vishvananda/netlink"
)

// return code of bpf_redirect if packet is redirected
const TC_ACT_REDIRECT = 0x7

var testPrefix = netip.MustParsePrefix("2001:db8:cafe::/96")

func TestManager_Siit46(t *testing.T) {
	kernelTraceReader, err := testutil.KernelTraceReader()
	if err != nil {
		t.Fatalf("creating kernel trace reader: %s", err)
	}

	v4Link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Index: 1,
		},
	}

	v6Link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Index: 2,
		},
	}

	m, err := NewManager(v4Link, v6Link, testPrefix)
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

	ret, outData, err := m.bpfObjs.Siit.Test(in)
	if err != nil {
		t.Fatalf("testing ebpf program: %s", err)
	}

	traces, err := io.ReadAll(kernelTraceReader)
	if err != nil {
		t.Logf("WARNING: failed to read kernel traces: %s", err)
	} else {
		t.Logf("ebpf program traces:\n%s", traces)
	}

	packet := testutil.DecodePacket(outData)
	t.Log("ebpf program ran, printing packet")
	t.Log(packet.Dump())
	if ret != TC_ACT_REDIRECT {
		t.Fatalf("ebpf program returned code != TC_ACT_REDIRECT: %d", ret)
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

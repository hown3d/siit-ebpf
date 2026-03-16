package bpf

import (
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/cilium/ebpf"
	ebpflink "github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

const (
	HostDevice       = "siit"
	SecondHostDevice = "siit-peer"
)

type Manager struct {
	pool    netip.Prefix
	log     logr.Logger
	bpfObjs *siitObjects
	// stores ip pairs for nat46
	ip4Map *ipMap[bpfIP4, bpfIP6]
	// stores ip pairs for nat64
	ip6Map *ipMap[bpfIP6, bpfIP4]
}

func ensureClsact(links ...netlink.Link) error {
	var err error
	for _, l := range links {
		clsact := netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: l.Attrs().Index,
				// Handles use the minor to indicate the namespace for their children.
				// If the children filters use the namespace as their major they are assigned to the corelating qdisc
				Handle: netlink.MakeHandle(0xffff, 0),
				Parent: netlink.HANDLE_CLSACT,
			},
		}
		err = errors.Join(err, netlink.QdiscReplace(&clsact))
	}

	return err
}

func (m *Manager) attachProgToFilter(l netlink.Link, prog *ebpf.Program) error {
	log := m.log.WithValues("program", prog.String())
	var progName string
	progInfo, err := prog.Info()
	if err == nil {
		progName = progInfo.Name
	}

	log.Info("attaching program as tcx")
	// Attach using tcx if available. This is seamless on interfaces with
	// existing tc programs since attaching tcx disables legacy tc evaluation.
	err = upsertTCXProgram(l, prog)
	if err == nil {
		// Don't fall back to legacy tc.
		return nil
	}
	if !errors.Is(err, ebpflink.ErrNotSupported) {
		// Unrecoverable error, surface to the caller.
		return fmt.Errorf("attaching tcx program %s: %w", progName, err)
	}

	log.Info("fallback to attaching program as tc")
	// tcx not available or disabled, fall back to legacy tc.
	if err := upsertTCProgram(log, l, prog, progName, 1); err != nil {
		return fmt.Errorf("attaching legacy tc program %s: %w", progName, err)
	}
	return nil
}

func upsertTCXProgram(device netlink.Link, prog *ebpf.Program) error {
	_, err := ebpflink.AttachTCX(ebpflink.TCXOptions{
		Interface: device.Attrs().Index,
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return err
	}

	// TODO: pin link in bpffs
	// pin := filepath.Join(bpffsDir, progName)
	// if err := l.Pin(pin); err != nil {
	// 	return nil, fmt.Errorf("pinning link at %s for program %s : %w", pin, progName, err)
	// }
	return nil
}

func upsertTCProgram(log logr.Logger, device netlink.Link, prog *ebpf.Program, progName string, prio uint16) error {
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: device.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  prio,
		},
		Fd:           prog.FD(),
		Name:         progName,
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		log.Info(fmt.Sprintf("filter %s already exist on interface %s, trying to replacing it ...", filter.Name, device))
		// it may already exist, try to replace it
		if err := netlink.FilterReplace(filter); err != nil {
			return fmt.Errorf("replacing tc filter for interface %s: %w", device.Attrs().Name, err)
		}
	}
	return nil
}

func setupBpfVariables(vars *siitVariables, p netip.Prefix) error {
	a16 := p.Addr().As16()
	var variableErrs error
	// write big endian here to ensure that we write in network order
	variableErrs = errors.Join(variableErrs, vars.IPV6POOL_0.Set(binary.BigEndian.Uint32(a16[0:4])))
	variableErrs = errors.Join(variableErrs, vars.IPV6POOL_1.Set(binary.BigEndian.Uint32(a16[4:8])))
	variableErrs = errors.Join(variableErrs, vars.IPV6POOL_2.Set(binary.BigEndian.Uint32(a16[8:12])))
	if variableErrs != nil {
		return fmt.Errorf("assign variables to program: %w", variableErrs)
	}
	return nil
}

var forbiddenPools = []netip.Prefix{
	// reserved for ipv6 link local addresses
	netip.MustParsePrefix("fe80::/10"),
}

func NewManager(log logr.Logger, pool netip.Prefix) (*Manager, error) {
	if pool.Bits() != 96 {
		return nil, errors.New("nat64Prefix must be /96")
	}

	for _, forbidden := range forbiddenPools {
		if forbidden.Overlaps(pool) {
			return nil, fmt.Errorf("cannot use pool %s as it overlaps with forbidden pool %s", pool, forbidden)
		}
	}

	// load program into kernel
	var objs siitObjects
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: (ebpf.LogLevelBranch | ebpf.LogLevelStats | ebpf.LogLevelInstruction),
		},
	}
	if err := loadSiitObjects(&objs, opts); err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			// print as %+v to get the full error log
			return nil, fmt.Errorf("verifier error from kernel: %+v", verifierErr)
		}
		return nil, fmt.Errorf("loading program into kernel: %w", err)
	}
	bpfClose := func() error {
		return objs.Close()
	}

	// TODO: route pool to siit device
	if err := setupBpfVariables(&objs.siitVariables, pool); err != nil {
		defer bpfClose()
		return nil, err
	}

	return &Manager{
		log:     log,
		bpfObjs: &objs,
		pool:    pool,
		ip6Map:  newIP6Map(objs.Ipv6AddressMappings),
		ip4Map:  newIP4Map(objs.Ipv4AddressMappings),
	}, nil
}

func (m *Manager) Close() error {
	return m.bpfObjs.Close()
}

func (m *Manager) SetupLinks() error {
	hostDev, peerDev, err := setupBaseDevice()
	if err != nil {
		return err
	}

	if err := ensureClsact(hostDev, peerDev); err != nil {
		return fmt.Errorf("ensuring clsact qdiscs on links: %w", err)
	}

	for _, l := range []netlink.Link{hostDev, peerDev} {
		klog.Infof("adding eBPF siit prog to the interface %s", l.Attrs().Name)
		if err := m.attachProgToFilter(l, m.bpfObjs.Siit); err != nil {
			return fmt.Errorf("error attaching program to interface %s: %w", l.Attrs().Name, err)
		}
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: hostDev.Attrs().Index,
		Dst: &net.IPNet{
			IP:   m.pool.Addr().AsSlice(),
			Mask: net.CIDRMask(m.pool.Bits(), m.pool.Addr().BitLen()),
		},
	}); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("add pool route: %w", err)
		}
	}

	return nil
}

type Entry struct {
	IPv4 netip.Addr
	IPv6 netip.Addr
}

func (e Entry) v4Route(link netlink.Link) *netlink.Route {
	return &netlink.Route{
		Family:    netlink.FAMILY_V4,
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   e.IPv4.AsSlice(),
			Mask: net.IPv4Mask(255, 255, 255, 255),
		},
	}
}

func (m *Manager) ListEntries() ([]Entry, error) {
	mapEntries, err := m.ip4Map.List()
	if err != nil {
		return nil, err
	}

	entries := make([]Entry, 0, len(mapEntries))
	for bpfIP4, bpfIP6 := range mapEntries {
		ip4, err := ipFromMarshaler(bpfIP4)
		if err != nil {
			return nil, fmt.Errorf("recieving ipv4 from entry: %w", err)
		}
		ip6, err := ipFromMarshaler(bpfIP6)
		if err != nil {
			return nil, fmt.Errorf("recieving ipv6 from entry: %w", err)
		}
		entries = append(entries, Entry{
			IPv4: ip4,
			IPv6: ip6,
		})
	}
	return entries, nil
}

func (m *Manager) AddEntry(e Entry) error {
	// TODO: setup routes to route ipv4 to siit device
	m.log.Info("adding entry", "ipv4", e.IPv4, "ipv6", e.IPv6)
	if err := addV4Route(e); err != nil {
		return err
	}
	var err error
	err = errors.Join(err, m.ip4Map.Add(e.IPv4, e.IPv6))
	err = errors.Join(err, m.ip6Map.Add(e.IPv6, e.IPv4))
	return err
}

func (m *Manager) DeleteEntry(e Entry) error {
	m.log.Info("deleting entry", "ipv4", e.IPv4, "ipv6", e.IPv6)
	if err := deleteV4Route(e); err != nil {
		return err
	}
	var err error
	err = errors.Join(err, m.ip4Map.Delete(e.IPv4))
	err = errors.Join(err, m.ip6Map.Delete(e.IPv6))
	return err
}

// addV4Route adds the entries ipv4 address to siit-peer device to allow processing responses.
// This must be on the peer device, as the outgoing device will be this if we push packets into the siit device.
// If not, the packet will be dropped by rpfilter
func addV4Route(e Entry) error {
	link, err := netlink.LinkByName(SecondHostDevice)
	if err != nil {
		return err
	}
	if err := netlink.RouteAdd(e.v4Route(link)); err != nil {
		if !os.IsExist(err) {
			return err
		}
	}
	return nil
}

func deleteV4Route(e Entry) error {
	link, err := netlink.LinkByName(SecondHostDevice)
	if err != nil {
		return err
	}
	return netlink.RouteDel(e.v4Route(link))
}

func ipFromMarshaler(m encoding.BinaryMarshaler) (netip.Addr, error) {
	raw, err := m.MarshalBinary()
	if err != nil {
		return netip.Addr{}, err
	}
	ip, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}, errors.New("invalid ip")
	}
	return ip, nil
}

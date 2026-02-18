package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	ebpflink "github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	"github.com/hown3d/siit-ebpf/internal/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

type Manager struct {
	log     logr.Logger
	v6Link  netlink.Link
	v4Link  netlink.Link
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

func attachProgToFilter(l netlink.Link, prog *ebpf.Program) error {
	var progName string
	progInfo, err := prog.Info()
	if err == nil {
		progName = progInfo.Name
	}

	klog.Infof("attaching program as tcx")
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

	klog.Infof("fallback to attaching program as tc")
	// tcx not available or disabled, fall back to legacy tc.
	if err := upsertTCProgram(l, prog, progName, 1); err != nil {
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

func upsertTCProgram(device netlink.Link, prog *ebpf.Program, progName string, prio uint16) error {
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
		klog.Infof("filter %s already exist on interface %s, trying to replacing it ...", filter.Name, device)
		// it may already exist, try to replace it
		if err := netlink.FilterReplace(filter); err != nil {
			return fmt.Errorf("replacing tc filter for interface %s: %w", device.Attrs().Name, err)
		}
	}
	return nil
}

func setupBpfVariables(vars *siitVariables, p netip.Prefix, v4Link, v6Link netlink.Link) error {
	a16 := p.Addr().As16()
	var variableErrs error
	// write big endian here to ensure that we write in network order
	variableErrs = errors.Join(variableErrs, vars.IPV6POOL_0.Set(binary.BigEndian.Uint32(a16[0:4])))
	variableErrs = errors.Join(variableErrs, vars.IPV6POOL_1.Set(binary.BigEndian.Uint32(a16[4:8])))
	variableErrs = errors.Join(variableErrs, vars.IPV6POOL_2.Set(binary.BigEndian.Uint32(a16[8:12])))
	variableErrs = errors.Join(variableErrs, vars.IPV4IFINDEX.Set(uint32(v4Link.Attrs().Index)))
	variableErrs = errors.Join(variableErrs, vars.IPV6IFINDEX.Set(uint32(v6Link.Attrs().Index)))
	if variableErrs != nil {
		return fmt.Errorf("assign variables to program: %w", variableErrs)
	}
	return nil
}

func NewManager(v4Link, v6Link netlink.Link, pool netip.Prefix) (*Manager, error) {
	if pool.Bits() != 96 {
		return nil, errors.New("nat64Prefix must be /96")
	}

	// load program into kernel
	var objs siitObjects
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: (ebpf.LogLevelBranch | ebpf.LogLevelStats),
		},
	}
	if err := loadSiitObjects(&objs, opts); err != nil {
		return nil, fmt.Errorf("loading program into kernel: %w", err)
	}
	bpfClose := func() error {
		return objs.Close()
	}

	if err := setupBpfVariables(&objs.siitVariables, pool, v4Link, v6Link); err != nil {
		defer bpfClose()
		return nil, err
	}

	return &Manager{
		log:     klog.NewKlogr().WithName("manager"),
		v6Link:  v6Link,
		v4Link:  v4Link,
		bpfObjs: &objs,
		ip6Map:  newIP6Map(objs.Ipv6AddressMappings),
		ip4Map:  newIP4Map(objs.Ipv4AddressMappings),
	}, nil
}

func (m *Manager) Close() error {
	return m.bpfObjs.Close()
}

func (m *Manager) SetupLinks() error {
	v4LinkName := m.v4Link.Attrs().Name
	v6LinkName := m.v6Link.Attrs().Name

	if err := ensureClsact(m.v4Link, m.v6Link); err != nil {
		return fmt.Errorf("ensuring clsact qdiscs on links: %w", err)
	}

	klog.Infof("adding eBPF siit prog to the interface %s", v6LinkName)
	if err := attachProgToFilter(m.v6Link, m.bpfObjs.Siit); err != nil {
		return fmt.Errorf("attaching nat64 program to interface %s: %w", v6LinkName, err)
	}

	klog.Infof("adding eBPF siit prog to the interface %s", v4LinkName)
	if err := attachProgToFilter(m.v4Link, m.bpfObjs.Siit); err != nil {
		return fmt.Errorf("attaching nat46 program to interface %s: %w", v4LinkName, err)
	}

	// set the interface up if necessary
	var err error
	err = errors.Join(err, link.EnsureUp(m.v4Link))
	err = errors.Join(err, link.EnsureUp(m.v6Link))
	return err
}

type Entry struct {
	IPv4 netip.Addr
	IPv6 netip.Addr
}

func (m *Manager) AddEntry(e Entry) error {
	m.log.Info("adding entry", "ipv4", e.IPv4, "ipv6", e.IPv6)
	var err error
	err = errors.Join(err, m.ip4Map.Add(e.IPv4, e.IPv6))
	err = errors.Join(err, m.ip6Map.Add(e.IPv6, e.IPv4))
	return err
}

func (m *Manager) DeleteEntry(e Entry) error {
	m.log.Info("deleting entry", "ipv4", e.IPv4, "ipv6", e.IPv6)
	var err error
	err = errors.Join(err, m.ip4Map.Delete(e.IPv4))
	err = errors.Join(err, m.ip6Map.Delete(e.IPv6))
	return err
}

package bpf

import (
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"structs"

	"github.com/cilium/ebpf"
)

// alias to allow MarshalBinary implementation
type (
	bpfIP4 siitInAddr
	bpfIP6 siitIn6Addr
)

// ebpf-go will use the binary implementations to read and write into maps.
// We must implement them to ensure we always write the ip addresses in network order
var (
	_ encoding.BinaryUnmarshaler = (*bpfIP4)(nil)
	_ encoding.BinaryUnmarshaler = (*bpfIP6)(nil)
	_ encoding.BinaryMarshaler   = bpfIP4{}
	_ encoding.BinaryMarshaler   = bpfIP6{}
)

func (i *bpfIP4) UnmarshalBinary(data []byte) error {
	_, err := binary.Decode(data, binary.BigEndian, &i.S_addr)
	return err
}

func (i *bpfIP6) UnmarshalBinary(data []byte) error {
	_, err := binary.Decode(data, binary.BigEndian, &i.In6U.U6Addr8)
	return err
}

func (i bpfIP4) MarshalBinary() (data []byte, err error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, i.S_addr)
	return buf, nil
}

func (i bpfIP6) MarshalBinary() (data []byte, err error) {
	buf := make([]byte, 0, 16)
	return binary.Append(buf, binary.BigEndian, i.In6U.U6Addr8)
}

type ipMap[K, V comparable] struct {
	keyFunc func(netip.Addr) (K, error)
	valFunc func(netip.Addr) (V, error)

	ebpfMap *ebpf.Map
}

func newIP4Map(ebpfMap *ebpf.Map) *ipMap[bpfIP4, bpfIP6] {
	return &ipMap[bpfIP4, bpfIP6]{
		ebpfMap: ebpfMap,
		keyFunc: ip4ToBpfType,
		valFunc: ip6ToBpfType,
	}
}

func newIP6Map(ebpfMap *ebpf.Map) *ipMap[bpfIP6, bpfIP4] {
	return &ipMap[bpfIP6, bpfIP4]{
		ebpfMap: ebpfMap,
		keyFunc: ip6ToBpfType,
		valFunc: ip4ToBpfType,
	}
}

func (m *ipMap[K, V]) Add(src, dst netip.Addr) error {
	key, err := m.keyFunc(src)
	if err != nil {
		return fmt.Errorf("building map key from ip %s: %w	", src, err)
	}
	val, err := m.valFunc(dst)
	if err != nil {
		return fmt.Errorf("building map value from ip %s: %w	", dst, err)
	}
	if err := m.ebpfMap.Update(key, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("updating ebpf map entry: %w", err)
	}
	return nil
}

func (m *ipMap[K, V]) Delete(src netip.Addr) error {
	key, err := m.keyFunc(src)
	if err != nil {
		return err
	}
	if err := m.ebpfMap.Delete(key); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

func (m *ipMap[K, V]) List() (map[K]V, error) {
	key := new(K)
	val := new(V)

	keyVal := make(map[K]V)

	iter := m.ebpfMap.Iterate()
	for iter.Next(key, val) {
		keyVal[*key] = *val
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}
	return keyVal, nil
}

// ip4ToBpfType translates an netip.Addr to the bpf representation of ipv4
func ip4ToBpfType(ip netip.Addr) (bpfIP4, error) {
	if !ip.Is4() {
		return bpfIP4{}, errors.New("ip must be ipv4")
	}

	return bpfIP4{
		// network order
		S_addr: binary.BigEndian.Uint32(ip.AsSlice()),
	}, nil
}

// ip6ToBpfType translates an netip.Addr to the bpf representation of ipv6
func ip6ToBpfType(ip netip.Addr) (bpfIP6, error) {
	if !ip.Is6() {
		return bpfIP6{}, errors.New("ip must be ipv6")
	}

	return bpfIP6{
		In6U: struct {
			_       structs.HostLayout
			U6Addr8 [16]uint8
		}{
			U6Addr8: ip.As16(),
		},
	}, nil
}

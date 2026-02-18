package testutil

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func DecodePacket(b []byte) gopacket.Packet {
	return gopacket.NewPacket(b, layers.LayerTypeEthernet, gopacket.Default)
}

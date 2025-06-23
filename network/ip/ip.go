package ip

import "network-stack/network"

type Addr interface {
	network.Addr

	Version() uint
}

type Packet interface {
	network.Packet

	SrcAddr() Addr
	DstAddr() Addr
	NextProtocol() NextProto
}

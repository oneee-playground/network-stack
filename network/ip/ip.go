package ip

import "network-stack/network"

type Addr interface {
	network.Addr

	Version() uint
}

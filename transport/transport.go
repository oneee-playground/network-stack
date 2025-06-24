package transport

import (
	"network-stack/network"
)

type Addr interface {
	NetworkAddr() network.Addr
	Port() uint16
	String() string
}

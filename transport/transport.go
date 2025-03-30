package transport

import "network-stack/network"

type Protocol string

const (
	TCP Protocol = "tcp"
	// UDP Protocol = "udp"
)

type Addr interface {
	NetworkAddr() network.Addr
	Identifier() any // Extra identifier (e.g. port, SPI)
	String() string
}

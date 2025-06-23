package network

type Addr interface {
	String() string
	Raw() []byte
}

type Packet interface {
	Metadata() any
	Payload() []byte
}

type Interface interface {
	// Send sends the packet outbound.
	Send(pack Packet)
	// HandlePack registers handler function.
	// When network packet is received, handler is invoked.
	// The handler function should be non-blocking.
	HandlePack(handler func(pack Packet))
}

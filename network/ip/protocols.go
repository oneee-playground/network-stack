package ip

// Reference: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
type NextProto uint8

const (
	NextProtoICMP NextProto = 1
	NextProtoTCP  NextProto = 6
)

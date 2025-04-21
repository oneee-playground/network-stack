package tls

import (
	"strconv"
)

type Version uint16

const (
	VersionTLS12 Version = 0x0303
	VersionTLS13 Version = 0x0304
)

func NewVersion(b [2]uint8) Version {
	v := uint16(b[0] << 8)
	v |= uint16(b[1])
	return Version(v)
}

func (v Version) Bytes() []byte {
	b := make([]byte, 2)
	b[0] = uint8(v)
	b[1] = uint8(v >> 8)
	return b
}

func (v Version) String() string {
	switch v {
	case VersionTLS12:
		return "TLS 1.2"
	case VersionTLS13:
		return "TLS 1.3"
	}

	return strconv.FormatUint(uint64(v), 16)
}


package common

import (
	"network-stack/session/tls/internal/util"
	"strconv"
)

type Version uint16

const (
	VersionTLS11 Version = 0x0302
	VersionTLS12 Version = 0x0303
	VersionTLS13 Version = 0x0304
)

type tlsMode uint8

const (
	ModeClient tlsMode = 1
	ModeServer tlsMode = 2
)

func NewVersion(b [2]uint8) Version {
	v := uint16(b[0]) << 8
	v |= uint16(b[1])
	return Version(v)
}

func (Version) FromBytes(b []byte) (out util.VectorConv, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, util.ErrVectorShort
	}

	out = NewVersion([2]uint8(b))

	return out, b[2:], nil
}

func (v Version) Bytes() []byte {
	b := make([]byte, 2)
	b[0] = uint8(v >> 8)
	b[1] = uint8(v)
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

var _ (util.VectorConv) = Version(0)

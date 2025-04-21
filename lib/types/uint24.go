package types

import (
	"encoding/binary"
	"strconv"
)

type Uint24 struct{ data [3]uint8 } // Stored in big endian.

// NOTE: This truncates most significant byte from u32.
func NewUint24(u32 uint32) Uint24 {
	b := [3]uint8{
		uint8(u32 >> 16),
		uint8(u32 >> 8),
		uint8(u32),
	}
	return Uint24From(b, false)
}

// littleEndian is true when b is ordered in little-endian.
func Uint24From(b [3]uint8, littleEndian bool) Uint24 {
	if littleEndian {
		b = [3]uint8{b[2], b[1], b[0]}
	}

	return Uint24{data: b}
}

func (u24 Uint24) Raw(littleEndian bool) [3]uint8 {
	d := u24.data
	if littleEndian {
		return [3]uint8{d[2], d[1], d[0]}
	}
	return d
}

func (u24 Uint24) String() string {
	return strconv.FormatUint(uint64(u24.Uint32()), 10)
}

func (u24 Uint24) Uint32() uint32 {
	b := append([]byte{0}, u24.data[:]...)
	return binary.BigEndian.Uint32(b)
}

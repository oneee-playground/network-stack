package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewUint24(t *testing.T) {
	u24 := NewUint24(0x123456)
	assert.Equal(t, [3]uint8{0x12, 0x34, 0x56}, u24.data)
}

func TestNewUint24Truncate(t *testing.T) {
	u32 := uint32(0x12345678)
	u24 := NewUint24(u32)
	assert.Equal(t, [3]uint8{0x34, 0x56, 0x78}, u24.data)
}

func TestUint24From(t *testing.T) {
	expected := [3]uint8{0x12, 0x34, 0x56}

	u24 := Uint24From([3]uint8{0x12, 0x34, 0x56}, false) // big endian
	assert.Equal(t, expected, u24.data)

	u24 = Uint24From([3]uint8{0x56, 0x34, 0x12}, true) // little endian
	assert.Equal(t, expected, u24.data)

}

func TestUint24Raw(t *testing.T) {
	u24 := NewUint24(0x123456)

	assert.Equal(t, [3]uint8{0x56, 0x34, 0x12}, u24.Raw(true))  // little endian
	assert.Equal(t, [3]uint8{0x12, 0x34, 0x56}, u24.Raw(false)) // big endian
}

func TestUint24String(t *testing.T) {
	u24 := NewUint24(0x123456)
	assert.Equal(t, "1193046", u24.String()) // 0x123456 in decimal is 1193046
}

func TestUint24Uint32(t *testing.T) {
	u32 := uint32(0x123456)
	u24 := NewUint24(u32)
	assert.Equal(t, u32, u24.Uint32())
}

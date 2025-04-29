package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewVersion(t *testing.T) {
	v := NewVersion([2]uint8{0x12, 0x34})
	assert.Equal(t, uint16(0x1234), uint16(v))
	assert.Equal(t, []byte{0x12, 0x34}, v.Bytes())
}

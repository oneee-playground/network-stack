package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const mockVectorMinLen = 2

type MockVector struct {
	data []byte
}

func (m MockVector) FromBytes(b []byte) (VerctorConv, []byte, error) {
	if len(b) < mockVectorMinLen {
		return nil, nil, ErrVectorShort
	}
	m.data = b[:mockVectorMinLen]
	return m, b[mockVectorMinLen:], nil
}

func (m MockVector) Bytes() []byte {
	return m.data
}

func TestVector(t *testing.T) {
	mock1 := &MockVector{data: []byte{0x01, 0x02}}
	mock2 := &MockVector{data: []byte{0x03, 0x04}}

	data := ToVector(1, []VerctorConv{mock1, mock2})
	expected := []byte{
		0x04,       // Length (4 bytes total)
		0x01, 0x02, // Mock 1 data
		0x03, 0x04, // Mock 2 data
	}
	require.Equal(t, expected, data)

	result, rest, err := FromVector[MockVector](1, data, false)
	assert.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, 2, len(result))
	assert.Equal(t, mock1, result[0])
	assert.Equal(t, mock2, result[1])
}

func TestVectorOpaque(t *testing.T) {
	data := ToVectorOpaque(1, []byte{0x01, 0x02, 0x03, 0x04})
	expected := []byte{
		0x04,                   // Length (4 bytes total)
		0x01, 0x02, 0x03, 0x04, // Data
	}
	require.Equal(t, expected, data)

	opaque, rest, err := FromVectorOpaque(1, data, false)
	assert.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, data, opaque)
}

func TestGetLength(t *testing.T) {
	data := []byte{0x00, 0x04, 0x01, 0x02, 0x03, 0x04}

	length, rest, err := getLength(2, data)
	assert.NoError(t, err)
	assert.Equal(t, uint(4), length)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, rest)
}

func TestFromVectorShort(t *testing.T) {
	data := []byte{0x00, 0x02, 0x01} // Length is 2, but only 1 byte of data

	_, _, err := FromVectorOpaque(2, data, false)
	assert.ErrorIs(t, err, ErrVectorShort)
}

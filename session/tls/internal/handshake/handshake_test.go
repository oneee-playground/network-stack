package handshake

import (
	"testing"

	"network-stack/lib/types"
	"network-stack/session/tls/common"

	"github.com/stretchr/testify/assert"
)

type mockHandshake struct {
	typ handshakeType
	d   []byte
}

func (m *mockHandshake) messageType() handshakeType { return m.typ }
func (m *mockHandshake) length() types.Uint24       { return types.NewUint24(uint32(len(m.d))) }
func (m *mockHandshake) data() []byte               { return m.d }
func (m *mockHandshake) fillFrom(b []byte) error    { m.d = b; return nil }

func TestHandshakeToBytes(t *testing.T) {
	hs := &mockHandshake{typ: 0, d: []byte("hello, handshake")}
	expected := []byte{
		0x00,
		0x00, 0x00, 0x10,
		'h', 'e', 'l', 'l', 'o', ',', ' ', 'h', 'a', 'n', 'd', 's', 'h', 'a', 'k', 'e',
	}

	raw := ToBytes(hs)
	assert.Equal(t, expected, raw)
}

func TestHandshakeFromBytes(t *testing.T) {
	raw := []byte{
		0x00,
		0x00, 0x00, 0x10,
		'h', 'e', 'l', 'l', 'o', ',', ' ', 'h', 'a', 'n', 'd', 's', 'h', 'a', 'k', 'e',
	}

	hs := &mockHandshake{typ: 0}
	expected := &mockHandshake{typ: 0, d: []byte("hello, handshake")}

	assert.NoError(t, FromBytes(raw, hs))
	assert.Equal(t, expected, hs)
}

func TestHandshakeFromBytesNeedMoreBytes(t *testing.T) {
	raw := []byte{
		0x00,
		0x00, 0x00, 0x10,
		'h', 'e', 'l', 'l', 'o', ',', ' ', 'h', 'a', 'n', 'd', 's', 'h', 'a', 'k', 'e',
	}

	hs := &mockHandshake{typ: 0}
	expected := &mockHandshake{typ: 0, d: []byte("hello, handshake")}

	err := FromBytes(raw[:len(raw)-1], hs)
	assert.ErrorIs(t, err, common.ErrNeedMoreBytes)

	assert.NoError(t, FromBytes(raw, hs))
	assert.Equal(t, expected, hs)
}

func TestHandshakeFromBytesWrongType(t *testing.T) {
	raw := []byte{
		0x01,
		0x00, 0x00, 0x10,
		'h', 'e', 'l', 'l', 'o', ',', ' ', 'h', 'a', 'n', 'd', 's', 'h', 'a', 'k', 'e',
	}

	hs := &mockHandshake{typ: 0}

	err := FromBytes(raw, hs)
	assert.ErrorIs(t, err, ErrNotExpectedHandshakeType)
}

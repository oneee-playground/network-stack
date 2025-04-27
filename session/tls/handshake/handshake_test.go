package handshake

import (
	"sync"
	"testing"

	"network-stack/lib/types"
	"network-stack/transport"
	"network-stack/transport/pipe"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/suite"
)

type mockHandshake struct {
	typ handshakeType
	d   []byte
}

func (m *mockHandshake) messageType() handshakeType { return m.typ }
func (m *mockHandshake) length() types.Uint24       { return types.NewUint24(uint32(len(m.d))) }
func (m *mockHandshake) data() []byte               { return m.d }
func (m *mockHandshake) fillFrom(b []byte) error    { m.d = b; return nil }

type HandshakeCodecTestSuite struct {
	suite.Suite

	codec  *handshakeCodec
	c1, c2 transport.Conn
}

func TestHandshakeCodecTestSuite(t *testing.T) {
	suite.Run(t, new(HandshakeCodecTestSuite))
}

func (s *HandshakeCodecTestSuite) SetupTest() {
	s.c1, s.c2 = pipe.NewPair("a", "b", clock.New())

	s.codec = newHandshakeCodec(s.c1)
}

func (s *HandshakeCodecTestSuite) TestEncodeDecode() {
	orig := &mockHandshake{typ: 0, d: []byte("hello, handshake")}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		codec := newHandshakeCodec(s.c2)

		// Decode the handshake message
		decoded := &mockHandshake{typ: 0}
		s.Require().NoError(codec.decode(decoded))
		s.Equal(orig.typ, decoded.typ)
		s.Equal(orig.d, decoded.d)

		// Encode the handshake message
		s.Require().NoError(codec.encode(orig))
	}()

	// Encode the handshake message
	s.Require().NoError(s.codec.encode(orig))

	// Decode the handshake message
	decoded := &mockHandshake{typ: 0}
	s.Require().NoError(s.codec.decode(decoded))
	s.Equal(orig.typ, decoded.typ)
	s.Equal(orig.d, decoded.d)

	wg.Wait()
}

func (s *HandshakeCodecTestSuite) TestUnexpectedType() {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		codec := newHandshakeCodec(s.c2)
		err := codec.encode(&mockHandshake{typ: 0, d: []byte("hey")})
		s.ErrorIs(err, transport.ErrConnClosed)
	}()

	// Attempt to decode with a different handshake type
	decoded := &mockHandshake{typ: 1}
	err := s.codec.decode(decoded)
	s.ErrorIs(err, errNotExpectedHandshakeType)
	s.c1.Close()

	wg.Wait()
}

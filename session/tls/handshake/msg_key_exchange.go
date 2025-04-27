package handshake

import (
	"bytes"
	"network-stack/lib/types"
	"network-stack/session/tls/common"
	"network-stack/session/tls/handshake/extension"

	"github.com/pkg/errors"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
type clientHello struct {
	version            common.Version // Legacy. Always TLS 1.2
	random             [32]byte
	sessionID          []byte // Legacy. Random 32byte value on compatibility modem else zero-length vector.
	cipherSuites       []common.CipherSuite
	compressionMethods []byte // Legacy. It should be set to one zero-value byte. Meaning "null" compression method.
	extensions         extension.Extensions
}

var _ handshake = (*clientHello)(nil)

func (c *clientHello) messageType() handshakeType { return typeClientHello }

func (c *clientHello) data() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(c.version.Bytes())

	buf.Write(c.random[:])

	buf.Write(common.ToVectorOpaque(1, c.sessionID))
	buf.Write(common.ToVector(2, c.cipherSuites))
	buf.Write(common.ToVectorOpaque(1, c.compressionMethods))

	c.extensions.WriteTo(buf)

	return buf.Bytes()
}

func (c *clientHello) length() types.Uint24 {
	dLen := uint32(0)

	dLen += uint32(len(c.version.Bytes()))
	dLen += uint32(len(c.random))
	dLen += 1 + uint32(len(c.sessionID))
	dLen += 2 + uint32(2*len(c.cipherSuites)) // size of suite * num of suites.
	dLen += 1 + uint32(len(c.compressionMethods))
	dLen += 2 + uint32(c.extensions.Length())

	return types.NewUint24(dLen)
}

func (c *clientHello) fillFrom(b []byte) (err error) {
	if len(b) < 34 {
		return errors.New("insufficient data to read clientHello")
	}

	var v common.VerctorConv
	v, b, _ = c.version.FromBytes(b)
	c.version = v.(common.Version)

	copy(c.random[:], b[:32])
	b = b[32:]

	c.sessionID, b, err = common.FromVectorOpaque(1, b, true)
	if err != nil {
		return errors.Wrap(err, "reading sessionID")
	}

	c.cipherSuites, b, err = common.FromVector[common.CipherSuite](2, b, true)
	if err != nil {
		return errors.Wrap(err, "reading cipherSuites")
	}

	c.compressionMethods, b, err = common.FromVectorOpaque(1, b, true)
	if err != nil {
		return errors.Wrap(err, "reading compressionMethods")
	}

	c.extensions, err = extension.ExtensionsFromRaw(b)
	if err != nil {
		return errors.Wrap(err, "reading extensions")
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
type serverHello struct {
	version           common.Version // Legacy. Always TLS 1.2
	random            [32]byte
	sessionIDEcho     []byte // Legacy. Random 32byte value on compatibility modem else zero-length vector.
	cipherSuite       common.CipherSuite
	compressionMethod uint8 // Legacy. It should be set to one zero-value byte. Meaning "null" compression method.
	extensions        extension.Extensions
}

var downgradeTLS12 = [8]byte{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 01}
var downgradeTLS11 = [8]byte{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 00}

var _ handshake = (*serverHello)(nil)

func (s *serverHello) messageType() handshakeType { return typeServerHello }

func (s *serverHello) data() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(s.version.Bytes())

	buf.Write(s.random[:])

	buf.Write(common.ToVectorOpaque(1, s.sessionIDEcho))

	buf.Write(s.cipherSuite[:])

	buf.WriteByte(s.compressionMethod)

	s.extensions.WriteTo(buf)

	return buf.Bytes()
}

func (s *serverHello) length() types.Uint24 {
	dLen := uint32(0)

	dLen += uint32(len(s.version.Bytes()))
	dLen += uint32(len(s.random))
	dLen += 1 + uint32(len(s.sessionIDEcho))
	dLen += uint32(len(s.cipherSuite))
	dLen += 1 // Compression method.
	dLen += 2 + uint32(s.extensions.Length())

	return types.NewUint24(dLen)
}

func (s *serverHello) fillFrom(b []byte) (err error) {
	if len(b) < 38 {
		return errors.New("insufficient data to read serverHello")
	}

	var v common.VerctorConv
	v, b, err = s.version.FromBytes(b)
	if err != nil {
		return errors.Wrap(err, "reading version")
	}
	s.version = v.(common.Version)

	copy(s.random[:], b[:32])
	b = b[32:]

	s.sessionIDEcho, b, err = common.FromVectorOpaque(1, b, true)
	if err != nil {
		return errors.Wrap(err, "reading sessionIDEcho")
	}

	if len(b) < 2 {
		return errors.New("insufficient data to read cipherSuite")
	}
	s.cipherSuite = common.CipherSuite([2]uint8(b[0:2]))
	b = b[2:]

	if len(b) < 1 {
		return errors.New("insufficient data to read compressionMethod")
	}
	s.compressionMethod = b[0]
	b = b[1:]

	s.extensions, err = extension.ExtensionsFromRaw(b)
	if err != nil {
		return errors.Wrap(err, "reading extensions")
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4
var helloRetryRandom = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

func (s *serverHello) isHelloRetry() bool { return s.random == helloRetryRandom }
func (s *serverHello) toHelloRetry()      { s.random = helloRetryRandom }

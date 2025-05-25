package handshake

import (
	"encoding/binary"
	"network-stack/lib/types"
	"network-stack/session/tls/common"
	"network-stack/session/tls/common/ciphersuite"

	"github.com/pkg/errors"
)

type handshakeType uint8

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4
const (
	typeClientHello         handshakeType = 1
	typeServerHello         handshakeType = 2
	typeNewSessionTicket    handshakeType = 4
	typeEndOfEarlyData      handshakeType = 5
	typeEncryptedExtensions handshakeType = 8
	typeCertificate         handshakeType = 11
	typeCertificateRequest  handshakeType = 13
	typeCertificateVerify   handshakeType = 15
	typeFinished            handshakeType = 20
	typeKeyUpdate           handshakeType = 24
	typeMessageHash         handshakeType = 254
)

type Handshake interface {
	messageType() handshakeType
	length() types.Uint24
	data() []byte // NOTE: Read-Only.

	fillFrom(b []byte) error
}

var ErrNotExpectedHandshakeType = errors.New("handshake type differs from expected")

func FromBytes(raw []byte, h Handshake) error {
	if len(raw) < 4 {
		return common.ErrNeedMoreBytes
	}

	t := handshakeType(raw[0])
	l := binary.BigEndian.Uint32(append([]byte{0}, raw[1:4]...))

	if t != h.messageType() {
		return ErrNotExpectedHandshakeType
	}

	if len(raw[4:]) < int(l) {
		return common.ErrNeedMoreBytes
	}
	if len(raw[4:]) > int(l) {
		return errors.New("data longer than advertised")
	}

	if err := h.fillFrom(raw[4:]); err != nil {
		return errors.Wrap(err, "reading handshake message data")
	}

	return nil
}

func ToBytes(h Handshake) []byte {
	t := byte(h.messageType())
	l := h.length().Raw(false)

	metadata := append([]byte{t}, l[:]...)

	return append(metadata, h.data()...)
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.1
type messageHash struct {
	clientHelloHash []byte
}

func (m *messageHash) messageType() handshakeType { return typeMessageHash }
func (m *messageHash) data() []byte               { return m.clientHelloHash }
func (m *messageHash) fillFrom(b []byte) error    { panic("we don't use it") }
func (m *messageHash) length() types.Uint24 {
	return types.NewUint24(uint32(len(m.clientHelloHash)))
}

var _ Handshake = (*messageHash)(nil)

func MakeMessageHash(suite ciphersuite.Suite, hello *ClientHello) *messageHash {
	h := suite.Hash().New()
	h.Write(ToBytes(hello))
	helloHash := h.Sum(nil)

	return &messageHash{clientHelloHash: helloHash}
}

package handshake

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"network-stack/lib/types"
	"network-stack/transport"

	"github.com/pkg/errors"
)

type HandshakeOptions struct {
	// Reference: https://datatracker.ietf.org/doc/html/rfc8446#appendix-D.4
	DisableCompatibilityMode bool

	RandomSource RandomGen
}

type RandomGen interface {
	Random() [32]byte
}

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

type handshake interface {
	messageType() handshakeType
	length() types.Uint24
	data() []byte // NOTE: Read-Only.

	fillFrom(b []byte) error
}

type handshaker interface {
	do(ctx context.Context) error

	exchangeKeys() error
}

type handshakeCodec struct {
	bw *bufio.Writer

	r        io.Reader
	metadata []byte
}

func newHandshakeCodec(conn transport.Conn) *handshakeCodec {
	return &handshakeCodec{
		bw:       bufio.NewWriter(conn),
		r:        conn,
		metadata: nil,
	}
}

var errNotExpectedHandshakeType = errors.New("handshake type differs from expected")

func (h *handshakeCodec) decode(v handshake) error {
	if h.metadata == nil {
		h.metadata = make([]byte, 4)
		if _, err := io.ReadFull(h.r, h.metadata); err != nil {
			return errors.Wrap(err, "error while reading metadata")
		}
	}

	t := handshakeType(h.metadata[0])
	l := binary.BigEndian.Uint32(append([]byte{0}, h.metadata[1:4]...))
	_ = l

	if t != v.messageType() {
		return errNotExpectedHandshakeType
	}

	buf := make([]byte, l)
	if _, err := io.ReadFull(h.r, buf); err != nil {
		return errors.Wrap(err, "reading handshake data")
	}

	if err := v.fillFrom(buf); err != nil {
		return errors.Wrap(err, "reading handshake message data")
	}

	h.metadata = nil
	return nil
}

func (h *handshakeCodec) encode(v handshake) error {
	t := byte(v.messageType())
	l := v.length().Raw(false)

	metadata := append([]byte{t}, l[:]...)
	if _, err := h.bw.Write(metadata); err != nil {
		return errors.Wrap(err, "writing metadata")
	}

	if _, err := h.bw.Write(v.data()); err != nil {
		return errors.Wrap(err, "writing data")
	}

	if err := h.bw.Flush(); err != nil {
		return errors.Wrap(err, "flushing bytes from buf")
	}
	return nil
}

package handshake

import (
	"bufio"
	"encoding/binary"
	"io"
	"network-stack/lib/types"

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

type Encoder struct {
	bw *bufio.Writer
}

func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{
		bw: bufio.NewWriter(w),
	}
}

func (e *Encoder) Encode(v Handshake) error {
	t := byte(v.messageType())
	l := v.length().Raw(false)

	metadata := append([]byte{t}, l[:]...)
	if _, err := e.bw.Write(metadata); err != nil {
		return errors.Wrap(err, "writing metadata")
	}

	if _, err := e.bw.Write(v.data()); err != nil {
		return errors.Wrap(err, "writing data")
	}

	if err := e.bw.Flush(); err != nil {
		return errors.Wrap(err, "flushing bytes from buf")
	}
	return nil
}

type Decoder struct {
	r        io.Reader
	metadata []byte
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		r:        r,
		metadata: nil,
	}
}

var ErrNotExpectedHandshakeType = errors.New("handshake type differs from expected")

func (d *Decoder) Decode(v Handshake) error {
	if d.metadata == nil {
		d.metadata = make([]byte, 4)
		if _, err := io.ReadFull(d.r, d.metadata); err != nil {
			return errors.Wrap(err, "error while reading metadata")
		}
	}

	t := handshakeType(d.metadata[0])
	l := binary.BigEndian.Uint32(append([]byte{0}, d.metadata[1:4]...))
	_ = l

	if t != v.messageType() {
		return ErrNotExpectedHandshakeType
	}

	buf := make([]byte, l)
	if _, err := io.ReadFull(d.r, buf); err != nil {
		return errors.Wrap(err, "reading handshake data")
	}

	if err := v.fillFrom(buf); err != nil {
		return errors.Wrap(err, "reading handshake message data")
	}

	d.metadata = nil
	return nil
}

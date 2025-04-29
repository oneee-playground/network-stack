package tls

import (
	"bytes"
	"encoding/binary"
	"io"
	iolib "network-stack/lib/io"
	"network-stack/session/tls/internal/common"
	"network-stack/session/tls/internal/util"

	"github.com/pkg/errors"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
type contentType uint8

const (
	typeInvalid          contentType = 0
	typeChangeCipherSpec contentType = 20
	typeAlert            contentType = 21
	typeHandshake        contentType = 22
	typeApplicationData  contentType = 23
)

// This could be plainText, cipherText.
type tlsText struct {
	// In case of cipherText, it's always set to applicationData for compatibility.
	contentType contentType
	// Always set to TLS 1.2. For backward compatibility,
	// in case of initial ClientHello, it is set to TLS 1.0.
	recordVersion common.Version // legacy.
	length        uint16
	fragment      []byte
}

const maxRecordLen = 2 << 13 // 2 ^ 14

type tlsInnerPlainText struct {
	content     []byte
	contentType contentType
	zeros       []uint8 // padding.
}

func (t tlsInnerPlainText) bytes() []byte {
	b := append(t.content, byte(t.contentType))
	b = append(b, t.zeros...)
	return b
}

// This discards padding.
func (t *tlsInnerPlainText) fillFrom(b []byte) error {
	b = bytes.TrimRightFunc(b, func(r rune) bool { return r == 0x00 })
	if len(b) == 0 {
		return errors.New("short data")
	}

	t.content = b[:len(b)-1]
	t.contentType = contentType(b[len(b)-1])

	return nil
}

func (t *tlsText) ReadFrom(r io.Reader) (n int64, err error) {
	metadata := make([]byte, 5)

	metaLen, err := io.ReadFull(r, metadata)
	if err != nil {
		return int64(metaLen), errors.Wrap(err, "reading metadata")
	}

	t.contentType = contentType(metadata[0])
	t.recordVersion = common.Version(binary.BigEndian.Uint16(metadata[1:3]))
	t.length = binary.BigEndian.Uint16(metadata[3:5])

	if t.length > maxRecordLen {
		return int64(metaLen), errors.New("record length exceeds maximum allowed size")
	}

	t.fragment = make([]byte, t.length)
	fragLen, err := io.ReadFull(r, t.fragment)
	if err != nil {
		return int64(metaLen + fragLen), errors.Wrap(err, "reading fragment")
	}

	return int64(metaLen + fragLen), nil
}
func (t tlsText) WriteTo(w io.Writer) (n int64, err error) {
	metadata := append([]byte{byte(t.contentType)}, t.recordVersion.Bytes()...)
	metadata = append(metadata, util.ToBigEndianBytes(uint(t.length), 2)...)

	metaLen, err := iolib.WriteFull(w, metadata)
	if err != nil {
		return int64(metaLen), errors.Wrap(err, "writing metadata")
	}

	fragLen, err := iolib.WriteFull(w, t.fragment)
	if err != nil {
		return int64(metaLen + fragLen), errors.Wrap(err, "writing fragment")
	}

	return int64(metaLen + fragLen), nil
}

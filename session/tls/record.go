package tls

import (
	"bytes"
	"encoding/binary"
	"io"
	iolib "network-stack/lib/io"
	"network-stack/session/tls/common"
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
	contentType contentType
	// Always set to TLS 1.2.
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

func (t *tlsText) metadata() []byte {
	metadata := append([]byte{byte(t.contentType)}, t.recordVersion.Bytes()...)
	metadata = append(metadata, util.ToBigEndianBytes(uint(t.length), 2)...)
	return metadata
}

var errRecordTooLong = errors.New("record length exceeds maximum allowed size")

// read is the bytes read when err != nil.
func (t *tlsText) fillFrom(r io.Reader) (read []byte, err error) {
	metadata := make([]byte, 5)

	metaLen, err := io.ReadFull(r, metadata)
	if err != nil {
		return metadata[:metaLen], errors.Wrap(err, "reading metadata")
	}

	t.contentType = contentType(metadata[0])
	t.recordVersion = common.Version(binary.BigEndian.Uint16(metadata[1:3]))
	t.length = binary.BigEndian.Uint16(metadata[3:5])

	if t.length > maxRecordLen {
		return metadata[:metaLen], errRecordTooLong
	}

	t.fragment = make([]byte, t.length)
	fragLen, err := io.ReadFull(r, t.fragment)
	if err != nil {
		return append(metadata, t.fragment[:fragLen]...), errors.Wrap(err, "reading fragment")
	}

	return nil, nil
}

func (t tlsText) WriteTo(w io.Writer) (n int64, err error) {
	metaLen, err := iolib.WriteFull(w, t.metadata())
	if err != nil {
		return int64(metaLen), errors.Wrap(err, "writing metadata")
	}

	fragLen, err := iolib.WriteFull(w, t.fragment)
	if err != nil {
		return int64(metaLen + fragLen), errors.Wrap(err, "writing fragment")
	}

	return int64(metaLen + fragLen), nil
}

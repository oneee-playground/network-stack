package tls

import (
	"bytes"
	"testing"

	"network-stack/session/tls/internal/common"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLSInnerPlainTextBytes(t *testing.T) {
	innerText := tlsInnerPlainText{
		content:     []byte("Hello"),
		contentType: typeApplicationData,
		zeros:       []uint8{0x00, 0x00, 0x00}, // Padding
	}

	expected := []byte{'H', 'e', 'l', 'l', 'o', byte(typeApplicationData), 0x00, 0x00, 0x00}
	result := innerText.bytes()

	assert.Equal(t, expected, result)
}

func TestTLSInnerPlainTextFillFrom(t *testing.T) {
	raw := []byte{'H', 'e', 'l', 'l', 'o', byte(typeApplicationData), 0x00, 0x00, 0x00}

	var innerText tlsInnerPlainText
	err := innerText.fillFrom(raw)
	require.NoError(t, err)

	assert.Equal(t, []byte("Hello"), innerText.content)
	assert.Equal(t, typeApplicationData, innerText.contentType)
}

func TestTLSInnerPlainTextFillFromShort(t *testing.T) {
	raw := []byte{0x00, 0x00, 0x00} // only paddings.

	var innerText tlsInnerPlainText
	err := innerText.fillFrom(raw)
	require.Error(t, err)
}

func TestTLSTextReadFromWriteTo(t *testing.T) {
	data := tlsText{
		contentType:   typeApplicationData,
		recordVersion: common.Version(0x0303), // TLS 1.2
		length:        5,
		fragment:      []byte("Hello"),
	}
	raw := []byte{
		byte(typeApplicationData), // contentType
		0x03, 0x03,                // recordVersion (TLS 1.2)
		0x00, 0x05, // length (5)
		'H', 'e', 'l', 'l', 'o',
	}

	// Serialize the record using WriteTo
	var buf bytes.Buffer
	n, err := data.WriteTo(&buf)
	require.NoError(t, err)
	require.Equal(t, int64(10), n) // 5 bytes metadata + 5 bytes fragment
	require.Equal(t, raw, buf.Bytes())

	// Deserialize the record using ReadFrom
	var parsed tlsText
	n, err = parsed.ReadFrom(&buf)
	require.NoError(t, err)
	require.Equal(t, int64(10), n)

	assert.Equal(t, data, parsed)
}

func TestTLSTextReadFromInvalidLen(t *testing.T) {
	// Prepare a record with an invalid length (exceeds maxRecordLen)
	data := []byte{
		byte(typeApplicationData), // contentType
		0x03, 0x03,                // recordVersion (TLS 1.2)
		0x40, 0x01, // length (16385, exceeds maxRecordLen)
	}

	var parsed tlsText
	_, err := parsed.ReadFrom(bytes.NewReader(data))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "record length exceeds maximum allowed size")
}

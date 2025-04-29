package extension

import (
	"bytes"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockExtension struct {
	extType ExtensionType
	data    []byte
}

func (m *mockExtension) ExtensionType() ExtensionType {
	return m.extType
}

func (m *mockExtension) Length() uint16 {
	return uint16(len(m.data))
}

func (m *mockExtension) Data() []byte {
	return m.data
}

func (m *mockExtension) fillFrom(raw rawExtension) error {
	if len(raw.data) == 0 {
		return errors.New("err")
	}
	m.data = raw.data
	return nil
}

func TestExtensions(t *testing.T) {
	ext1 := mockExtension{extType: TypeServerCertType, data: []byte("hello")}
	ext2 := mockExtension{extType: TypeSupportedGroups, data: []byte{0x00, 0x1d}}

	extensions := ExtensionsFrom(&ext1, &ext2)

	assert.Equal(t, 2, len(extensions.raws))
	assert.Equal(t, TypeServerCertType, extensions.raws[0].t)
	assert.Equal(t, []byte("hello"), extensions.raws[0].data)
	assert.Equal(t, TypeSupportedGroups, extensions.raws[1].t)
	assert.Equal(t, []byte{0x00, 0x1d}, extensions.raws[1].data)

	// Length includes 4 bytes per extension (type + length) + data length.
	expectedLength := uint16(4 + len(ext1.data) + 4 + len(ext2.data))
	assert.Equal(t, expectedLength, extensions.Length())
}

func TestExtensionsFromRaw(t *testing.T) {
	raw := []byte{
		0x00, 0x15, // Total length (21 bytes)
		0x00, 0x00, // Extension type (TypeServerName)
		0x00, 0x0b, // Length (11 bytes)
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', // Data
		0x00, 0x0a, // Extension type (TypeSupportedGroups)
		0x00, 0x02, // Length (2 bytes)
		0x00, 0x1d, // Data
	}

	extensions, err := ExtensionsFromRaw(raw)
	require.NoError(t, err)

	// Validate the parsed extensions
	assert.Equal(t, 2, len(extensions.raws))
	assert.Equal(t, TypeServerName, extensions.raws[0].t)
	assert.Equal(t, []byte("example.com"), extensions.raws[0].data)
	assert.Equal(t, TypeSupportedGroups, extensions.raws[1].t)
	assert.Equal(t, []byte{0x00, 0x1d}, extensions.raws[1].data)
}

func TestExtensionsWriteTo(t *testing.T) {
	ext1 := mockExtension{extType: TypeServerName, data: []byte("example.com")}
	ext2 := mockExtension{extType: TypeSupportedGroups, data: []byte{0x00, 0x1d}}

	extensions := ExtensionsFrom(&ext1, &ext2)

	buf := bytes.NewBuffer(nil)
	n, err := extensions.WriteTo(buf)
	require.NoError(t, err)
	require.Equal(t, 2+extensions.Length(), uint16(n))

	expected := []byte{
		0x00, 0x15, // Total length (21 bytes)
		0x00, 0x00, // Extension type (TypeServerName)
		0x00, 0x0b, // Length (11 bytes)
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', // Data
		0x00, 0x0a, // Extension type (TypeSupportedGroups)
		0x00, 0x02, // Length (2 bytes)
		0x00, 0x1d, // Data
	}
	assert.Equal(t, expected, buf.Bytes())
}

func TestExtensionsExtract(t *testing.T) {
	ext1 := mockExtension{extType: TypeServerName, data: []byte("example.com")}
	ext2 := mockExtension{extType: TypeSupportedGroups, data: []byte{0x00, 0x1d}}

	extensions := ExtensionsFrom(&ext1, &ext2)

	extracted := mockExtension{extType: TypeServerName}

	err := extensions.Extract(&extracted)
	require.NoError(t, err)
	assert.Equal(t, []byte("example.com"), extracted.data)

	// Test extracting a non-existent extension.
	extracted.extType = TypeALPN
	err = extensions.Extract(&extracted)
	assert.ErrorIs(t, err, ErrNoMatchingExtension)
}

func testExtension(t *testing.T, input Extension, other Extension, wantType ExtensionType) {
	require.Equal(t, input.ExtensionType(), wantType)

	data := input.Data()
	require.Equal(t, uint16(len(data)), input.Length())

	raw := rawExtension{data: data}
	require.NoError(t, other.fillFrom(raw))

	assert.Equal(t, input, other)
	assert.Equal(t, input.Length(), other.Length())
	assert.Equal(t, input.Data(), other.Data())
}

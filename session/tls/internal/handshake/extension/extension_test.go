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

func (m *mockExtension) exists() bool { return m != nil }

func (m *mockExtension) Length() uint16 {
	return uint16(len(m.data))
}

func (m *mockExtension) Data() []byte {
	return m.data
}

func (*mockExtension) newFrom(raw Raw) (Extension, error) {
	var m mockExtension
	if len(raw.data) == 0 {
		return nil, errors.New("err")
	}
	m.data = raw.data
	return &m, nil
}

func TestToRaw(t *testing.T) {
	ext1 := mockExtension{extType: TypeServerCertType, data: []byte("hello")}
	ext2 := mockExtension{extType: TypeSupportedGroups, data: []byte{0x00, 0x1d}}

	raws := ToRaw(&ext1, &ext2)

	assert.Equal(t, 2, len(raws))
	assert.Equal(t, TypeServerCertType, raws[0].t)
	assert.Equal(t, []byte("hello"), raws[0].data)
	assert.Equal(t, TypeSupportedGroups, raws[1].t)
	assert.Equal(t, []byte{0x00, 0x1d}, raws[1].data)

	// Length includes 4 bytes per extension (type + length) + data length.
	expectedLength := uint16(4 + len(ext1.data) + 4 + len(ext2.data))
	assert.Equal(t, expectedLength, ByteLenRaw(raws))
}

func TestByteLen(t *testing.T) {
	ext1 := mockExtension{extType: TypeServerCertType, data: []byte("hello")}
	ext2 := mockExtension{extType: TypeSupportedGroups, data: []byte{0x00, 0x1d}}

	raws := ToRaw(&ext1, &ext2)
	assert.Equal(t, ByteLen(&ext1, &ext2), ByteLenRaw(raws))
}

func TestParse(t *testing.T) {
	b := []byte{
		0x00, 0x15, // Total length (21 bytes)
		0x00, 0x00, // Extension type (TypeServerName)
		0x00, 0x0b, // Length (11 bytes)
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', // Data
		0x00, 0x0a, // Extension type (TypeSupportedGroups)
		0x00, 0x02, // Length (2 bytes)
		0x00, 0x1d, // Data
	}

	raws, err := Parse(b, false)
	require.NoError(t, err)

	// Validate the parsed extensions
	assert.Equal(t, 2, len(raws))
	assert.Equal(t, TypeServerName, raws[0].t)
	assert.Equal(t, []byte("example.com"), raws[0].data)
	assert.Equal(t, TypeSupportedGroups, raws[1].t)
	assert.Equal(t, []byte{0x00, 0x1d}, raws[1].data)
}

func TestWriteRaws(t *testing.T) {
	ext1 := mockExtension{extType: TypeServerName, data: []byte("example.com")}
	ext2 := mockExtension{extType: TypeSupportedGroups, data: []byte{0x00, 0x1d}}

	raws := ToRaw(&ext1, &ext2)

	buf := bytes.NewBuffer(nil)
	require.NoError(t, WriteRaws(raws, buf))

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

func TestExtract(t *testing.T) {
	ext1 := mockExtension{extType: TypeServerName, data: []byte("example.com")}
	ext2 := mockExtension{extType: TypeSupportedGroups, data: []byte{0x00, 0x1d}}

	raws := ToRaw(&ext1, &ext2)

	expected := mockExtension{extType: TypeServerName}

	got, err := Extract(raws, &expected)
	require.NoError(t, err)
	assert.Equal(t, []byte("example.com"), got.data)

	// Test extracting a non-existent extension.
	expected.extType = TypeALPN
	got, err = Extract(raws, &expected)
	assert.NoError(t, err)
	assert.Equal(t, got, &expected)
}

func testExtension(t *testing.T, ext Extension, wantType ExtensionType) {
	require.Equal(t, ext.ExtensionType(), wantType)

	data := ext.Data()
	require.Equal(t, uint16(len(data)), ext.Length())

	require.True(t, ext.exists())

	raw := Raw{data: data}
	got, err := ext.newFrom(raw)
	require.NoError(t, err)
	require.True(t, got.exists())

	assert.Equal(t, ext, got)
	assert.Equal(t, ext.Length(), got.Length())
	assert.Equal(t, ext.Data(), got.Data())
}

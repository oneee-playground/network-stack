package extension

import (
	"bytes"
	"encoding/binary"
	"io"
	sliceutil "network-stack/lib/slice"
	"network-stack/session/tls/common"
	"network-stack/session/tls/internal/util"

	"github.com/pkg/errors"
)

type ExtensionType uint16

const (
	TypeServerName          ExtensionType = 0
	TypeMaxFragLength       ExtensionType = 1
	TypeStatusRequest       ExtensionType = 5
	TypeSupportedGroups     ExtensionType = 10
	TypeSignatureAlgos      ExtensionType = 13
	TypeUseSrtp             ExtensionType = 14
	TypeHeartbeat           ExtensionType = 15
	TypeALPN                ExtensionType = 16 // Application Layer Protocol Negotiation.
	TypeSignedCertTimestamp ExtensionType = 18
	TypeClientCertType      ExtensionType = 19
	TypeServerCertType      ExtensionType = 20
	TypePadding             ExtensionType = 21
	TypePreSharedKey        ExtensionType = 41
	TypeEarlyData           ExtensionType = 42
	TypeSupportedVersions   ExtensionType = 43
	TypeCookie              ExtensionType = 44
	TypePskKeyExchangeModes ExtensionType = 45
	TypeCertAuthorities     ExtensionType = 47
	TypeOidFilters          ExtensionType = 48
	TypePostHandshakeAuth   ExtensionType = 49
	TypeSignatureAlgosCert  ExtensionType = 50
	TypeKeyShare            ExtensionType = 51
)

func (e ExtensionType) Bytes() []byte {
	b := make([]byte, 2)
	b[0] = uint8(e >> 8)
	b[1] = uint8(e)
	return b
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
type Extension interface {
	ExtensionType() ExtensionType
	Length() uint16 // Length of data.
	Data() []byte

	exists() bool // checks if underlying value is nil.
	newFrom(raw Raw) (Extension, error)
}

type Raw raw

func (r Raw) Type() ExtensionType { return r.t }

type raw struct {
	t      ExtensionType
	length uint16
	data   []byte
}

var _ util.VectorConv = raw{}

func (r raw) Bytes() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(r.t.Bytes())
	buf.Write(util.ToBigEndianBytes(uint(r.length), 2))
	buf.Write(r.data)

	return buf.Bytes()
}

func (r raw) FromBytes(b []byte) (out util.VectorConv, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, common.ErrNeedMoreBytes
	}

	r.t = ExtensionType(binary.BigEndian.Uint16(b[0:2]))
	rest = b[2:]

	r.data, rest, err = util.FromVectorOpaque(2, rest, true)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading extension data")
	}
	r.length = uint16(len(r.data))

	return r, rest, nil
}

// ToRaw ignores nil extensions.
func ToRaw(exts ...Extension) []Raw {
	raws := make([]Raw, 0)
	for _, ext := range exts {
		if !ext.exists() {
			continue
		}
		raws = append(raws, Raw{
			t:      ext.ExtensionType(),
			length: ext.Length(),
			data:   ext.Data(),
		})
	}
	return raws
}

func Parse(b []byte, alloweRemain bool) ([]Raw, error) {
	raws, _, err := util.FromVector[raw](2, b, alloweRemain)
	if err != nil {
		return nil, errors.Wrap(err, "parsing extensions")
	}

	return sliceutil.Map(raws, func(r raw) Raw { return Raw(r) }), nil
}

func ByteLen(exts ...Extension) uint16 {
	l := uint16(0)
	for _, ext := range exts {
		if !ext.exists() {
			continue
		}
		l += 4 // extension type + length bytes.
		l += ext.Length()
	}
	return l
}

func WriteRaws(raws []Raw, w io.Writer) error {
	buf := bytes.NewBuffer(nil)

	// Write total length.
	buf.Write(util.ToBigEndianBytes(uint(ByteLenRaw(raws)), 2))

	for _, raw := range raws {
		buf.Write(raw.t.Bytes())
		buf.Write(util.ToBigEndianBytes(uint(raw.length), 2))
		buf.Write(raw.data)
	}

	_, err := buf.WriteTo(w)
	return err
}

func ByteLenRaw(raws []Raw) uint16 {
	l := uint16(0)
	for _, ext := range raws {
		l += 4 // extension type + length bytes.
		l += ext.length
	}
	return l
}

// tmpl.ExtensionType() must return a value.
// If extension is not found, Extract will return (tmpl, nil).
func Extract[T Extension](raws []Raw, tmpl T) (T, error) {
	for _, raw := range raws {
		if raw.t == tmpl.ExtensionType() {
			ext, err := tmpl.newFrom(raw)
			if err != nil {
				return tmpl, err
			}

			return ext.(T), nil
		}
	}

	return tmpl, nil
}

func Equal[T Extension](a, b T) bool {
	switch {
	case a.exists() != b.exists():
		return false
	case !a.exists() && !b.exists():
		return true
	default:
		// TODO: Make it more performant?
		// Like adding Equals for each extensions.
		return bytes.Equal(a.Data(), b.Data())
	}
}

package extension

import (
	"bytes"
	"encoding/binary"
	"io"
	"network-stack/session/tls/common"
	"network-stack/session/tls/internal/util"
	"slices"

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

	fillFrom(raw rawExtension) error
}

type Extensions struct{ raws []rawExtension }

type rawExtension struct {
	t      ExtensionType
	length uint16
	data   []byte
}

var _ util.VectorConv = rawExtension{}

func (r rawExtension) Bytes() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(r.t.Bytes())
	buf.Write(util.ToBigEndianBytes(uint(r.length), 2))
	buf.Write(r.data)

	return buf.Bytes()
}

func (r rawExtension) FromBytes(b []byte) (out util.VectorConv, rest []byte, err error) {
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

func ExtensionsFrom(exts ...Extension) Extensions {
	raws := make([]rawExtension, len(exts))
	for i, ext := range exts {
		raws[i] = rawExtension{
			t:      ext.ExtensionType(),
			length: ext.Length(),
			data:   ext.Data(),
		}
	}
	return Extensions{raws: raws}
}

func ExtensionsFromRaw(b []byte) (Extensions, error) {
	extensions, _, err := util.FromVector[rawExtension](2, b, false)
	if err != nil {
		return Extensions{}, errors.Wrap(err, "parsing extensions")
	}

	return Extensions{raws: extensions}, nil
}

// Length doesn't include the length of the length field (2 bytes) .
func (e Extensions) Length() (l uint16) {
	for _, ext := range e.raws {
		l += 4 // extension type + length bytes.
		l += ext.length
	}
	return
}

func (e Extensions) WriteTo(w io.Writer) (n int64, err error) {
	buf := bytes.NewBuffer(nil)

	// Write total length.
	buf.Write(util.ToBigEndianBytes(uint(e.Length()), 2))

	for _, raw := range e.raws {
		buf.Write(raw.t.Bytes())
		buf.Write(util.ToBigEndianBytes(uint(raw.length), 2))
		buf.Write(raw.data)
	}

	return buf.WriteTo(w)
}

var ErrNoMatchingExtension = errors.New("no matching extension")

func (e Extensions) Extract(v Extension) error {
	for _, raw := range e.raws {
		if raw.t == v.ExtensionType() {
			return v.fillFrom(raw)
		}
	}

	return ErrNoMatchingExtension
}

func (e Extensions) Clone() Extensions {
	return Extensions{raws: slices.Clone(e.raws)}
}

func (e *Extensions) Set(v Extension) {
	input := rawExtension{
		t:      v.ExtensionType(),
		length: v.Length(),
		data:   v.Data(),
	}

	for idx, raw := range e.raws {
		if raw.t == input.t {
			e.raws[idx] = input
			return
		}
	}

	// Not Found.
	e.raws = append(e.raws, input)
}

func (e *Extensions) Remove(t ExtensionType) (found bool) {
	for idx := 0; idx < len(e.raws); idx++ {
		raw := e.raws[idx]
		if raw.t == t {
			e.raws = append(e.raws[:idx], e.raws[idx+1:]...)
			return true
		}
	}

	return false
}

func (e *Extensions) Has(t ExtensionType) bool {
	return e.Index(t) != -1
}

func (e *Extensions) Index(t ExtensionType) int {
	return slices.IndexFunc(e.raws,
		func(ext rawExtension) bool {
			return ext.t == t
		},
	)
}

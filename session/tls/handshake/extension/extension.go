package extension

import (
	"bytes"
	"io"
	"network-stack/session/tls/common"

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
	buf.Write(common.ToBigEndianBytes(uint(e.Length()), 2))

	for _, raw := range e.raws {
		buf.Write(raw.t.Bytes())
		buf.Write(common.ToBigEndianBytes(uint(raw.length), 2))
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

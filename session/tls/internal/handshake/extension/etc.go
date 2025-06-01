package extension

import (
	"encoding/binary"
	"network-stack/session/tls/common"
	"network-stack/session/tls/common/signature"
	"network-stack/session/tls/internal/util"

	"github.com/pkg/errors"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
type SupportedVersionsCH struct{ Versions []common.Version }

var _ Extension = (*SupportedVersionsCH)(nil)

func (s *SupportedVersionsCH) ExtensionType() ExtensionType { return TypeSupportedVersions }
func (s *SupportedVersionsCH) exists() bool                 { return s != nil }

func (s *SupportedVersionsCH) Data() []byte {
	return util.ToVector(1, s.Versions)
}

func (s *SupportedVersionsCH) Length() uint16 {
	return 1 + uint16(len(s.Versions)*2) // length of versions + sizeof(Version) * num versions
}

func (*SupportedVersionsCH) newFrom(raw Raw) (Extension, error) {
	var s SupportedVersionsCH
	out, _, err := util.FromVector[common.Version](1, raw.data, false)
	if err != nil {
		return nil, errors.Wrap(err, "reading versions")
	}

	s.Versions = out
	return &s, nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
type SupportedVersionsSH struct{ SelectedVersion common.Version }

func (s *SupportedVersionsSH) ExtensionType() ExtensionType { return TypeSupportedVersions }
func (s *SupportedVersionsSH) exists() bool                 { return s != nil }

func (s *SupportedVersionsSH) Data() []byte {
	return s.SelectedVersion.Bytes()
}

func (s *SupportedVersionsSH) Length() uint16 {
	return 2
}

func (*SupportedVersionsSH) newFrom(raw Raw) (Extension, error) {
	var s SupportedVersionsSH
	if len(raw.data) != 2 {
		return nil, errors.New("length doesn't match expectations")
	}

	s.SelectedVersion = common.NewVersion([2]uint8(raw.data))

	return &s, nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.2
type Cookie struct {
	Cookie []byte
}

var _ Extension = (*Cookie)(nil)

func (c *Cookie) ExtensionType() ExtensionType { return TypeCookie }
func (c *Cookie) exists() bool                 { return c != nil }

func (c *Cookie) Data() []byte {
	return util.ToVectorOpaque(2, c.Cookie)
}

func (c *Cookie) Length() uint16 {
	return 2 + uint16(len(c.Cookie)) // length of cookie + actual cookie
}

func (*Cookie) newFrom(raw Raw) (Extension, error) {
	var c Cookie
	data, _, err := util.FromVectorOpaque(2, raw.data, false)
	if err != nil {
		return nil, errors.Wrap(err, "reading cookie")
	}

	c.Cookie = data
	return &c, nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.6
type PostHandshakeAuth struct{}

var _ Extension = (*PostHandshakeAuth)(nil)

func (p *PostHandshakeAuth) ExtensionType() ExtensionType { return TypePostHandshakeAuth }
func (p *PostHandshakeAuth) exists() bool                 { return p != nil }

func (p *PostHandshakeAuth) Data() []byte {
	return []byte{}
}

func (p *PostHandshakeAuth) Length() uint16 {
	return 0
}

func (*PostHandshakeAuth) newFrom(raw Raw) (Extension, error) {
	var p PostHandshakeAuth
	if raw.length > 0 {
		return nil, errors.New("expected to have zero length data")
	}
	return &p, nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.10
type EarlyDataNST struct { // New session ticket
	MaxEarlyDataSize uint32
}

var _ Extension = (*EarlyDataNST)(nil)

func (e *EarlyDataNST) ExtensionType() ExtensionType { return TypeEarlyData }
func (e *EarlyDataNST) exists() bool                 { return e != nil }
func (e *EarlyDataNST) Data() []byte                 { return util.ToBigEndianBytes(uint(e.MaxEarlyDataSize), 4) }
func (e *EarlyDataNST) Length() uint16               { return 4 }
func (*EarlyDataNST) newFrom(raw Raw) (Extension, error) {
	var e EarlyDataNST
	if len(raw.data) != 4 {
		return nil, errors.New("invalid length")
	}

	e.MaxEarlyDataSize = binary.BigEndian.Uint32(raw.data)
	return &e, nil
}

type EarlyDataEE struct{}

var _ Extension = (*EarlyDataEE)(nil)

func (e *EarlyDataEE) ExtensionType() ExtensionType { return TypeEarlyData }
func (e *EarlyDataEE) exists() bool                 { return e != nil }
func (e *EarlyDataEE) Data() []byte                 { return []byte{} }
func (e *EarlyDataEE) Length() uint16               { return 0 }
func (*EarlyDataEE) newFrom(raw Raw) (Extension, error) {
	var e EarlyDataEE
	if len(raw.data) > 0 {
		return nil, errors.New("data should be zero-length")
	}
	return &e, nil
}

type EarlyDataCH struct{}

var _ Extension = (*EarlyDataCH)(nil)

func (e *EarlyDataCH) ExtensionType() ExtensionType { return TypeEarlyData }
func (e *EarlyDataCH) exists() bool                 { return e != nil }
func (e *EarlyDataCH) Data() []byte                 { return []byte{} }
func (e *EarlyDataCH) Length() uint16               { return 0 }
func (*EarlyDataCH) newFrom(raw Raw) (Extension, error) {
	var e EarlyDataCH
	if len(raw.data) > 0 {
		return nil, errors.New("data should be zero-length")
	}
	return &e, nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
type SignatureAlgos struct {
	SupportedAlgos []signature.Scheme
}

var _ Extension = (*SignatureAlgos)(nil)

func (s *SignatureAlgos) ExtensionType() ExtensionType { return TypeSignatureAlgos }
func (s *SignatureAlgos) exists() bool                 { return s != nil }

func (s *SignatureAlgos) Data() []byte {
	return util.ToVector(2, s.SupportedAlgos)
}

func (s *SignatureAlgos) Length() uint16 {
	return 2 + uint16(len(s.SupportedAlgos)*2)
}

func (*SignatureAlgos) newFrom(raw Raw) (Extension, error) {
	var s SignatureAlgos
	schemes, _, err := util.FromVector[signature.Scheme](2, raw.data, false)
	if err != nil {
		return nil, errors.Wrap(err, "reading supported algorithms")
	}

	s.SupportedAlgos = schemes
	return &s, nil
}

type SignatureAlgosCert struct {
	SupportedAlgos []signature.Scheme
}

var _ Extension = (*SignatureAlgosCert)(nil)

func (s *SignatureAlgosCert) ExtensionType() ExtensionType { return TypeSignatureAlgosCert }
func (s *SignatureAlgosCert) exists() bool                 { return s != nil }

func (s *SignatureAlgosCert) Data() []byte {
	return util.ToVector(2, s.SupportedAlgos)
}

func (s *SignatureAlgosCert) Length() uint16 {
	return 2 + uint16(len(s.SupportedAlgos)*2)
}

func (*SignatureAlgosCert) newFrom(raw Raw) (Extension, error) {
	var s SignatureAlgosCert
	schemes, _, err := util.FromVector[signature.Scheme](2, raw.data, false)
	if err != nil {
		return nil, errors.Wrap(err, "reading supported algorithms")
	}

	s.SupportedAlgos = schemes
	return &s, nil
}

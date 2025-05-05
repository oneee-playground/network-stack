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

func (s *SupportedVersionsCH) ExtensionType() ExtensionType {
	return TypeSupportedVersions
}

func (s *SupportedVersionsCH) Data() []byte {
	return util.ToVector(1, s.Versions)
}

func (s *SupportedVersionsCH) Length() uint16 {
	return 1 + uint16(len(s.Versions)*2) // length of versions + sizeof(Version) * num versions
}

func (s *SupportedVersionsCH) fillFrom(raw rawExtension) error {
	out, _, err := util.FromVector[common.Version](1, raw.data, false)
	if err != nil {
		return errors.Wrap(err, "reading versions")
	}

	s.Versions = out
	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
type SupportedVersionsSH struct{ SelectedVersion common.Version }

func (s *SupportedVersionsSH) ExtensionType() ExtensionType {
	return TypeSupportedVersions
}

func (s *SupportedVersionsSH) Data() []byte {
	return s.SelectedVersion.Bytes()
}

func (s *SupportedVersionsSH) Length() uint16 {
	return 2
}

func (s *SupportedVersionsSH) fillFrom(raw rawExtension) error {
	if len(raw.data) != 2 {
		return errors.New("length doesn't match expectations")
	}

	s.SelectedVersion = common.NewVersion([2]uint8(raw.data))

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.2
type Cookie struct {
	Cookie []byte
}

var _ Extension = (*Cookie)(nil)

func (c *Cookie) ExtensionType() ExtensionType {
	return TypeCookie
}

func (c *Cookie) Data() []byte {
	return util.ToVectorOpaque(2, c.Cookie)
}

func (c *Cookie) Length() uint16 {
	return 2 + uint16(len(c.Cookie)) // length of cookie + actual cookie
}

func (c *Cookie) fillFrom(raw rawExtension) error {
	data, _, err := util.FromVectorOpaque(2, raw.data, false)
	if err != nil {
		return errors.Wrap(err, "reading cookie")
	}

	c.Cookie = data
	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.6
type PostHandshakeAuth struct{}

var _ Extension = (*PostHandshakeAuth)(nil)

func (p *PostHandshakeAuth) ExtensionType() ExtensionType {
	return TypePostHandshakeAuth
}

func (p *PostHandshakeAuth) Data() []byte {
	return []byte{}
}

func (p *PostHandshakeAuth) Length() uint16 {
	return 0
}

func (p *PostHandshakeAuth) fillFrom(raw rawExtension) error {
	if raw.length > 0 {
		return errors.New("expected to have zero length data")
	}
	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.10
type EarlyDataNST struct { // New session ticket
	MaxEarlyDataSize uint32
}

var _ Extension = (*EarlyDataNST)(nil)

func (e *EarlyDataNST) ExtensionType() ExtensionType { return TypeEarlyData }
func (e *EarlyDataNST) Data() []byte                 { return util.ToBigEndianBytes(uint(e.MaxEarlyDataSize), 4) }
func (e *EarlyDataNST) Length() uint16               { return 4 }
func (e *EarlyDataNST) fillFrom(raw rawExtension) error {
	if len(raw.data) != 4 {
		return errors.New("invalid length")
	}

	e.MaxEarlyDataSize = binary.BigEndian.Uint32(raw.data)
	return nil
}

type earlyDataEmpty struct{}

type EarlyDataCH struct{ earlyDataEmpty }
type EarlyDataEE struct{ earlyDataEmpty } // Encrypted extensions

var _ Extension = (*earlyDataEmpty)(nil)
var _ Extension = (*EarlyDataCH)(nil)
var _ Extension = (*EarlyDataEE)(nil)

func (e *earlyDataEmpty) ExtensionType() ExtensionType { return TypeEarlyData }
func (e *earlyDataEmpty) Data() []byte                 { return []byte{} }
func (e *earlyDataEmpty) Length() uint16               { return 0 }
func (e *earlyDataEmpty) fillFrom(raw rawExtension) error {
	if len(raw.data) > 0 {
		return errors.New("data should be zero-length")
	}
	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
type signatureSchemeList struct {
	SupportedAlogs []signature.Scheme
}

func (s *signatureSchemeList) ExtensionType() ExtensionType {
	panic("cannot be accessed")
}

func (s *signatureSchemeList) Data() []byte {
	return util.ToVector(2, s.SupportedAlogs)
}

func (s *signatureSchemeList) Length() uint16 {
	return 2 + uint16(len(s.SupportedAlogs)*2)
}

func (s *signatureSchemeList) fillFrom(raw rawExtension) error {
	schemes, _, err := util.FromVector[signature.Scheme](2, raw.data, false)
	if err != nil {
		return errors.Wrap(err, "reading supported algorithms")
	}

	s.SupportedAlogs = schemes
	return nil
}

var _ Extension = (*signatureSchemeList)(nil)

type SignatureAlgos struct{ signatureSchemeList }
type SignatureAlgosCert struct{ signatureSchemeList }

var _ Extension = (*SignatureAlgos)(nil)
var _ Extension = (*SignatureAlgosCert)(nil)

func (s *SignatureAlgos) ExtensionType() ExtensionType     { return TypeSignatureAlgos }
func (s *SignatureAlgosCert) ExtensionType() ExtensionType { return TypeSignatureAlgosCert }

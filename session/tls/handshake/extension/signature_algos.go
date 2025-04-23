package extension

import (
	"encoding/binary"
	"network-stack/session/tls/common"

	"github.com/pkg/errors"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
type SigScheme uint16

func (s SigScheme) Bytes() []byte {
	b := make([]byte, 2)
	b[0] = uint8(s >> 8)
	b[1] = uint8(s)
	return b
}

func (s SigScheme) FromBytes(b []byte) (out common.VerctorConv, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, common.ErrVectorShort
	}

	s = SigScheme(binary.BigEndian.Uint16(b))

	return s, b[2:], nil
}

var _ common.VerctorConv = SigScheme(0)

const (
	// RSASSA-PKCS1-v1_5 algorithms
	SigScheme_RSA_PKCS1_SHA256 SigScheme = 0x0401
	SigScheme_RSA_PKCS1_SHA384 SigScheme = 0x0501
	SigScheme_RSA_PKCS1_SHA512 SigScheme = 0x0601

	// ECDSA algorithms
	SigScheme_ECDSA_Secp256r1_SHA256 SigScheme = 0x0403
	SigScheme_ECDSA_Secp384r1_SHA384 SigScheme = 0x0503
	SigScheme_ECDSA_Secp521r1_SHA512 SigScheme = 0x0603

	// RSASSA-PSS algorithms with public key OID rsaEncryption
	SigScheme_RSA_PSS_RSAE_SHA256 SigScheme = 0x0804
	SigScheme_RSA_PSS_RSAE_SHA384 SigScheme = 0x0805
	SigScheme_RSA_PSS_RSAE_SHA512 SigScheme = 0x0806

	// EdDSA algorithms
	SigScheme_Ed25519 SigScheme = 0x0807
	SigScheme_Ed448   SigScheme = 0x0808

	// RSASSA-PSS algorithms with public key OID RSASSA-PSS
	SigScheme_RSA_PSS_PSS_SHA256 SigScheme = 0x0809
	SigScheme_RSA_PSS_PSS_SHA384 SigScheme = 0x080A
	SigScheme_RSA_PSS_PSS_SHA512 SigScheme = 0x080B

	// Legacy algorithms
	SigScheme_RSA_PKCS1_SHA1 SigScheme = 0x0201
	SigScheme_ECDSA_SHA1     SigScheme = 0x0203

	// Reserved Code Points
	// 0xFE00 ~ 0xFFFF
	_ SigScheme = 0xFE00
	_ SigScheme = 0xFFFF
)

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
type signatureSchemeList struct {
	SupportedAlogs []SigScheme
}

func (s *signatureSchemeList) ExtensionType() ExtensionType {
	panic("cannot be accessed")
}

func (s *signatureSchemeList) Data() []byte {
	return common.ToVector(2, s.SupportedAlogs)
}

func (s *signatureSchemeList) Length() uint16 {
	return 2 + uint16(len(s.SupportedAlogs)*2)
}

func (s *signatureSchemeList) fillFrom(raw rawExtension) error {
	schemes, _, err := common.FromVector[SigScheme](2, raw.data, false)
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

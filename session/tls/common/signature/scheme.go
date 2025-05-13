package signature

import (
	"crypto"
	"crypto/elliptic"
	"encoding/binary"
	"network-stack/session/tls/common"
	"network-stack/session/tls/internal/util"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
type Scheme uint16

func (s Scheme) Bytes() []byte {
	b := make([]byte, 2)
	b[0] = uint8(s >> 8)
	b[1] = uint8(s)
	return b
}

func (s Scheme) FromBytes(b []byte) (out util.VectorConv, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, common.ErrNeedMoreBytes
	}

	s = Scheme(binary.BigEndian.Uint16(b))

	return s, b[2:], nil
}

var _ util.VectorConv = Scheme(0)

var schemes = make(map[Scheme]Algorithm)

func register(algo Algorithm) Scheme { schemes[algo.ID()] = algo; return algo.ID() }

func Get(id Scheme) (Algorithm, bool) {
	algo, ok := schemes[id]
	return algo, ok
}

var (
	// RSASSA-PKCS1-v1.5 algorithms
	Scheme_RSA_PKCS1_SHA256 = register(Algorithm{0x0401, signerRSA_PKCS1v15{}, crypto.SHA256})
	Scheme_RSA_PKCS1_SHA384 = register(Algorithm{0x0501, signerRSA_PKCS1v15{}, crypto.SHA384})
	Scheme_RSA_PKCS1_SHA512 = register(Algorithm{0x0601, signerRSA_PKCS1v15{}, crypto.SHA512})

	// ECDSA algorithms
	Scheme_ECDSA_Secp256r1_SHA256 = register(Algorithm{0x0403, signerECDSA{elliptic.P256()}, crypto.SHA256})
	Scheme_ECDSA_Secp384r1_SHA384 = register(Algorithm{0x0503, signerECDSA{elliptic.P384()}, crypto.SHA384})
	Scheme_ECDSA_Secp521r1_SHA512 = register(Algorithm{0x0603, signerECDSA{elliptic.P521()}, crypto.SHA512})

	// RSASSA-PSS algorithms with public key OID rsaEncryption
	Scheme_RSA_PSS_RSAE_SHA256 = register(Algorithm{0x0804, signerRSA_PSS{}, crypto.SHA256})
	Scheme_RSA_PSS_RSAE_SHA384 = register(Algorithm{0x0805, signerRSA_PSS{}, crypto.SHA384})
	Scheme_RSA_PSS_RSAE_SHA512 = register(Algorithm{0x0806, signerRSA_PSS{}, crypto.SHA512})

	// EdDSA algorithms
	Scheme_Ed25519 = register(Algorithm{0x0807, signerEdDSA{}, crypto.Hash(0)})
	Scheme_Ed448   = 0x0808 // NOTE: Unimplemented in stdlib.

	// RSASSA-PSS algorithms with public key OID RSASSA-PSS
	// NOTE: This won't verify difference between PSS and RSAE.
	// If it is required. Change it later.
	Scheme_RSA_PSS_PSS_SHA256 = register(Algorithm{0x0809, signerRSA_PSS{}, crypto.SHA256})
	Scheme_RSA_PSS_PSS_SHA384 = register(Algorithm{0x080A, signerRSA_PSS{}, crypto.SHA384})
	Scheme_RSA_PSS_PSS_SHA512 = register(Algorithm{0x080B, signerRSA_PSS{}, crypto.SHA512})

	// Legacy algorithms
	Scheme_RSA_PKCS1_SHA1 = register(Algorithm{0x0201, signerRSA_PKCS1v15{}, crypto.SHA1})
	Scheme_ECDSA_SHA1     = register(Algorithm{0x0203, signerECDSA{}, crypto.SHA1})

	// Reserved Code Points
	// 0xFE00 ~ 0xFFFF
	_ Scheme = 0xFE00
	_ Scheme = 0xFFFF
)

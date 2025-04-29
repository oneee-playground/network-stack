package extension

import (
	"testing"
)

func TestSignatureAlgos(t *testing.T) {
	orig := &SignatureAlgos{
		signatureSchemeList: signatureSchemeList{
			SupportedAlogs: []SigScheme{
				SigScheme_RSA_PKCS1_SHA256,
				SigScheme_ECDSA_Secp256r1_SHA256,
			},
		},
	}

	testExtension(t, orig, new(SignatureAlgos), TypeSignatureAlgos)
}

func TestSignatureAlgosCert(t *testing.T) {
	orig := &SignatureAlgosCert{
		signatureSchemeList: signatureSchemeList{
			SupportedAlogs: []SigScheme{
				SigScheme_RSA_PSS_RSAE_SHA256,
				SigScheme_Ed25519,
			},
		},
	}

	testExtension(t, orig, new(SignatureAlgosCert), TypeSignatureAlgosCert)
}

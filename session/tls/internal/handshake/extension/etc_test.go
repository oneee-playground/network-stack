package extension

import (
	"testing"

	"network-stack/session/tls/common"
	"network-stack/session/tls/common/signature"
)

func TestSupportedVersionsCH(t *testing.T) {
	orig := &SupportedVersionsCH{
		Versions: []common.Version{
			common.VersionTLS11, common.VersionTLS12,
		},
	}

	testExtension(t, orig, TypeSupportedVersions)
}

func TestSupportedVersionsSH(t *testing.T) {
	orig := &SupportedVersionsSH{
		SelectedVersion: common.VersionTLS13,
	}

	testExtension(t, orig, TypeSupportedVersions)
}

func TestCookie(t *testing.T) {
	orig := &Cookie{
		Cookie: []byte("sample-cookie"),
	}

	testExtension(t, orig, TypeCookie)
}

func TestPostHandshakeAuth(t *testing.T) {
	orig := &PostHandshakeAuth{}

	testExtension(t, orig, TypePostHandshakeAuth)
}

func TestEarlyDataNST(t *testing.T) {
	orig := &EarlyDataNST{
		MaxEarlyDataSize: 0xDEADBEEF,
	}

	testExtension(t, orig, TypeEarlyData)
}

func TestEarlyDataEmpty(t *testing.T) {
	ch := &EarlyDataCH{}
	ee := &EarlyDataEE{}

	testExtension(t, ch, TypeEarlyData)
	testExtension(t, ee, TypeEarlyData)
}

func TestSignatureAlgos(t *testing.T) {
	orig := &SignatureAlgos{
		SupportedAlgos: []signature.Scheme{
			signature.Scheme_RSA_PKCS1_SHA256,
			signature.Scheme_ECDSA_Secp256r1_SHA256,
		},
	}

	testExtension(t, orig, TypeSignatureAlgos)
}

func TestSignatureAlgosCert(t *testing.T) {
	orig := &SignatureAlgosCert{
		SupportedAlgos: []signature.Scheme{
			signature.Scheme_RSA_PSS_RSAE_SHA256,
			signature.Scheme_Ed25519,
		},
	}

	testExtension(t, orig, TypeSignatureAlgosCert)
}

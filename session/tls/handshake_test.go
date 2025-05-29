package tls

import (
	"network-stack/session/tls/common/signature"
	"network-stack/session/tls/internal/handshake/extension"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetermineSignatureAlgos(t *testing.T) {
	algoExt := &extension.SignatureAlgos{
		SupportedAlgos: []signature.Scheme{signature.Scheme_ECDSA_SHA1},
	}
	algoCertExt := &extension.SignatureAlgosCert{
		SupportedAlgos: []signature.Scheme{signature.Scheme_ECDSA_Secp256r1_SHA256},
	}

	algos, algosCert := determineSignatureAlgos(algoExt, algoCertExt)
	assert.Equal(t, algoExt.SupportedAlgos, algos)
	assert.Equal(t, algoCertExt.SupportedAlgos, algosCert)

	// algoExt replaces algoCertExt.
	algoCertExt = nil
	algos, algosCert = determineSignatureAlgos(algoExt, algoCertExt)
	assert.Equal(t, algoExt.SupportedAlgos, algos)
	assert.Equal(t, algoExt.SupportedAlgos, algosCert)
}

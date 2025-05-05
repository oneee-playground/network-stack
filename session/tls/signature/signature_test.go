package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlgorithm_SignAndVerify(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	data := []byte("test data")

	algo := NewAlgorithm(Scheme_RSA_PKCS1_SHA256, signerRSA_PKCS1v15{}, crypto.SHA256)

	// Test Sign
	signature, err := algo.Sign(data, privKey)
	require.NoError(t, err)

	// Test Verify
	ok, err := algo.Verify(data, signature, &privKey.PublicKey)
	assert.NoError(t, err)
	assert.True(t, ok)
}

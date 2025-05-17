package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignerRSA_PKCS1v15(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	data := []byte("test data")
	hashed := sha256.Sum256(data)

	signer := signerRSA_PKCS1v15{}

	// Test Sign
	signature, err := signer.Sign(rand.Reader, hashed[:], crypto.SHA256, privKey)
	require.NoError(t, err)

	// Test Verify
	err = signer.Verify(hashed[:], signature, crypto.SHA256, &privKey.PublicKey)
	assert.NoError(t, err)

	// Test Verify with invalid signature
	err = signer.Verify(hashed[:], []byte("invalid signature"), crypto.SHA256, &privKey.PublicKey)
	assert.Error(t, err)
}

func TestSignerECDSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	data := []byte("test data")
	hashed := sha256.Sum256(data)

	signer := signerECDSA{curve: elliptic.P256()}

	// Test Sign
	signature, err := signer.Sign(rand.Reader, hashed[:], crypto.SHA256, privKey)
	require.NoError(t, err)

	// Test Verify
	err = signer.Verify(hashed[:], signature, crypto.SHA256, &privKey.PublicKey)
	assert.NoError(t, err)

	// Test Verify with invalid signature
	err = signer.Verify(hashed[:], []byte("invalid signature"), crypto.SHA256, &privKey.PublicKey)
	assert.Error(t, err)
}

func TestSignerRSA_PSS(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	data := []byte("test data")
	hashed := sha256.Sum256(data)

	signer := signerRSA_PSS{}

	// Test Sign
	signature, err := signer.Sign(rand.Reader, hashed[:], crypto.SHA256, privKey)
	require.NoError(t, err)

	// Test Verify
	err = signer.Verify(hashed[:], signature, crypto.SHA256, &privKey.PublicKey)
	assert.NoError(t, err)

	// Test Verify with invalid signature
	err = signer.Verify(hashed[:], []byte("invalid signature"), crypto.SHA256, &privKey.PublicKey)
	assert.Error(t, err)
}

func TestSignerEdDSA(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	data := []byte("test data")

	signer := signerEdDSA{}

	// Test Sign
	signature, err := signer.Sign(rand.Reader, data, crypto.Hash(0), privKey)
	require.NoError(t, err)

	// Test Verify
	err = signer.Verify(data, signature, crypto.Hash(0), pubKey)
	assert.NoError(t, err)

	// Test Verify with invalid signature
	err = signer.Verify(data, []byte("invalid signature"), crypto.Hash(0), pubKey)
	assert.Error(t, err)
}

func TestSignerUnsupportedKey(t *testing.T) {
	signer := signerRSA_PKCS1v15{}

	// Test Sign with unsupported key
	_, err := signer.Sign(rand.Reader, []byte("data"), crypto.SHA256, "unsupported key")
	assert.ErrorIs(t, err, ErrUnsupportedKey)

	// Test Verify with unsupported key
	err = signer.Verify([]byte("data"), []byte("signature"), crypto.SHA256, "unsupported key")
	assert.ErrorIs(t, err, ErrUnsupportedKey)
}

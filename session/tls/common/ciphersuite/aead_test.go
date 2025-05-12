package ciphersuite

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAEAD_AES_128_GCM(t *testing.T) {

	t.Run("Valid 128-bit key", func(t *testing.T) {
		key := make([]byte, 16) // 128-bit key
		aead, err := aeadAES_128_GCM(key)
		require.NoError(t, err)
		assert.NotNil(t, aead)
	})

	t.Run("Invalid key length", func(t *testing.T) {
		key := make([]byte, 15) // Invalid key length
		aead, err := aeadAES_128_GCM(key)
		assert.Error(t, err)
		assert.Nil(t, aead)
	})
}

func TestAEAD_AES_256_GCM(t *testing.T) {
	t.Run("Valid 256-bit key", func(t *testing.T) {
		key := make([]byte, 32) // 256-bit key
		aead, err := aeadAES_256_GCM(key)
		require.NoError(t, err)
		assert.NotNil(t, aead)
	})

	t.Run("Invalid key length", func(t *testing.T) {
		key := make([]byte, 31) // Invalid key length
		aead, err := aeadAES_256_GCM(key)
		assert.Error(t, err)
		assert.Nil(t, aead)
	})
}

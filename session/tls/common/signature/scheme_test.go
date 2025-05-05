package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGet(t *testing.T) {
	algo, ok := Get(Scheme_RSA_PKCS1_SHA256)
	require.True(t, ok)
	assert.Equal(t, Scheme_RSA_PKCS1_SHA256, algo.ID())
}

func TestGetUnregistered(t *testing.T) {
	_, ok := Get(Scheme(0xFFFF)) // Reserved but unregistered
	assert.False(t, ok)
}

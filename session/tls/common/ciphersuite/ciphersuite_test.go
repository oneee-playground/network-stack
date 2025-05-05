package ciphersuite

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGet(t *testing.T) {
	suite, ok := Get(TLS_AES_128_GCM_SHA256)
	require.True(t, ok)
	assert.Equal(t, TLS_AES_128_GCM_SHA256, suite.ID())
}

func TestGetUnregistered(t *testing.T) {
	_, ok := Get(ID([2]uint8{0xFF, 0xFF}))
	assert.False(t, ok)
}

package keyexchange

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGet(t *testing.T) {
	suite, ok := Get(Group_Secp256r1)
	require.True(t, ok)
	assert.Equal(t, Group_Secp256r1, suite.ID())
}

func TestGetUnregistered(t *testing.T) {
	_, ok := Get(GroupID(0xFFFF))
	assert.False(t, ok)
}

package iolib

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWriteFull(t *testing.T) {
	data := []byte("Hello, World!")
	var buf bytes.Buffer

	written, err := WriteFull(&buf, data)
	assert.NoError(t, err)
	assert.Equal(t, uint(len(data)), written)
	assert.Equal(t, data, buf.Bytes())
}

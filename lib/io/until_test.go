package iolib

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadUntil(t *testing.T) {
	sample := []byte("Hello, World!")

	testcases := []struct {
		desc     string
		delim    []byte
		expected []byte
		wantErr  error
	}{
		{
			desc:     "sample",
			delim:    []byte("Wo"),
			expected: []byte("Hello, Wo"),
		},
		{
			desc:     "not found",
			delim:    []byte("Bye!"),
			expected: []byte("Hello, World!"),
			wantErr:  io.EOF,
		},
		{
			desc:     "no delim",
			delim:    []byte(nil),
			expected: nil,
			wantErr:  ErrZeroLenDelim,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			r := NewUntilReader(bytes.NewReader(sample))
			b, err := r.ReadUntil(tc.delim)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.expected, b)
		})
	}
}

func TestReadAfterReadUntil(t *testing.T) {
	sample := []byte("Hello, World!")
	r := NewUntilReader(bytes.NewReader(sample))

	b, err := r.ReadUntil([]byte("el"))
	require.NoError(t, err)
	require.Equal(t, []byte("Hel"), b)

	buf := make([]byte, 10)
	n, err := r.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, len(buf), n)
	assert.Equal(t, []byte("lo, World!"), buf)
}

func TestReadUntilAfterReadUntil(t *testing.T) {
	sample := []byte("Hello, World!")
	r := NewUntilReader(bytes.NewReader(sample))

	b, err := r.ReadUntil([]byte("el"))
	require.NoError(t, err)
	require.Equal(t, []byte("Hel"), b)

	b, err = r.ReadUntil([]byte("Wo"))
	require.NoError(t, err)
	assert.Equal(t, []byte("lo, Wo"), b)
}

func TestReadUntilLimit(t *testing.T) {
	sample := []byte("Hello, World!")
	r := NewUntilReader(bytes.NewReader(sample))

	b, err := r.ReadUntilLimit([]byte("World!"), 3)
	require.ErrorIs(t, err, io.EOF)
	assert.Equal(t, []byte("Hel"), b)

	b, err = r.ReadUntilLimit([]byte("World!"), 10)
	require.NoError(t, err)
	assert.Equal(t, []byte("lo, World!"), b)
}

func TestReadUntilLimitZero(t *testing.T) {
	sample := []byte("Hello, World!")
	r := NewUntilReader(bytes.NewReader(sample))

	b, err := r.ReadUntilLimit([]byte("World!"), 0)
	require.NoError(t, err)
	assert.Equal(t, sample, b)
}

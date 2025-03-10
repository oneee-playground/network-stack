package util

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadUntil(t *testing.T) {
	sample := []byte("Hello, World!")

	testcases := []struct {
		desc     string
		delim    []byte
		expected []byte
		wantErr  bool
	}{
		{
			desc:     "sample",
			delim:    []byte("Wo"),
			expected: []byte("Hello, Wo"),
		},
		{
			desc:    "not found",
			delim:   []byte("Bye!"),
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			r := bufio.NewReader(bytes.NewReader(sample))
			b, err := ReadUntil(r, tc.delim)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.Equal(t, b, tc.expected)
		})
	}
}

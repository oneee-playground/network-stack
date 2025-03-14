package http

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVersion(t *testing.T) {
	testcases := []struct {
		desc     string
		input    []byte
		expected Version
		wantErr  bool
	}{
		{
			desc:     "http 1.1",
			input:    []byte("HTTP/1.1"),
			expected: Version{1, 1},
		},
		{
			desc:    "missing prefix",
			input:   []byte("1.1"),
			wantErr: true,
		},
		{
			desc:    "missing prefix (partial)",
			input:   []byte("HTTP1.1"),
			wantErr: true,
		},
		{
			desc:    "missing prefix (partial)",
			input:   []byte("HTTP1.1"),
			wantErr: true,
		},
		{
			desc:    "missing seperator",
			input:   []byte("HTTP/1"),
			wantErr: true,
		},
		{
			desc:    "two seperators",
			input:   []byte("HTTP/1.1.1"),
			wantErr: true,
		},
		{
			desc:    "version not convertable to int",
			input:   []byte("HTTP/ayo.2"),
			wantErr: true,
		},
		{
			desc:    "negative version",
			input:   []byte("HTTP/1.-1"),
			wantErr: true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			ver, err := ParseVersion(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.Equal(t, tc.expected, ver)
		})
	}
}
func TestVersionToText(t *testing.T) {
	testcases := []struct {
		input    Version
		expected []byte
	}{
		{
			input:    Version{1, 1},
			expected: []byte("HTTP/1.1"),
		},
		{
			input:    Version{1, 0},
			expected: []byte("HTTP/1.0"),
		},
		{
			input:    Version{0, 1},
			expected: []byte("HTTP/0.1"),
		},
		{
			input:    Version{20, 1},
			expected: []byte("HTTP/20.1"),
		},
		{
			input:    Version{100, 100},
			expected: []byte("HTTP/100.100"),
		},
	}
	for _, tc := range testcases {
		t.Run(string(tc.expected), func(t *testing.T) {
			ver := tc.input
			assert.Equal(t, ver.Text(), tc.expected)
		})
	}
}

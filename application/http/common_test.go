package http

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidToken(t *testing.T) {
	testcases := []struct {
		desc     string
		input    string
		expected bool
	}{
		{
			desc:     "valid token with alphabets",
			input:    "Token",
			expected: true,
		},
		{
			desc:     "valid token with digits",
			input:    "Token123",
			expected: true,
		},
		{
			desc:     "valid token with special characters",
			input:    "Token-._~",
			expected: true,
		},
		{
			desc:     "invalid token with space",
			input:    "Token 123",
			expected: false,
		},
		{
			desc:     "invalid token with special characters",
			input:    "Token@123",
			expected: false,
		},
		{
			desc:     "empty token",
			input:    "",
			expected: false,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			result := isValidToken(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

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

func TestNewHeaders(t *testing.T) {
	initial := map[string]string{
		"Hello":     "world!",
		"some-word": "A",
	}

	headers := NewHeaders(initial)

	assert.Empty(t, headers.underlying["some-word"])
	assert.Equal(t, "A", headers.underlying["Some-Word"])

	initial["Hello"] = "there"

	assert.NotEqual(t, initial["Hello"], headers.underlying["Hello"])
}

func TestHeaderFields(t *testing.T) {
	hashmap := map[string]string{
		"A": "a",
		"B": "b",
	}

	h := NewHeaders(hashmap)

	fields := h.Fields()
	assert.Len(t, fields, len(hashmap))
	assert.Contains(t, fields, [2]string{"A", "a"})
	assert.Contains(t, fields, [2]string{"B", "b"})
}

func TestHeadersGetSet(t *testing.T) {
	h := NewHeaders(nil)

	key, value := "content-type", "do you care?"

	a, ok := h.Get(key)
	assert.False(t, ok)
	assert.Empty(t, a)

	h.Set(key, value)

	assert.Empty(t, h.underlying[key])
	assert.Equal(t, value, h.underlying[toCanonicalFieldName(key)])

	a, ok = h.Get(key)
	assert.True(t, ok)
	assert.Equal(t, value, a)
}

func TestToCanonicalFieldName(t *testing.T) {
	testcases := []struct {
		desc     string
		input    string
		expected string
	}{
		{
			desc:     "all lowercase",
			input:    "content-type",
			expected: "Content-Type",
		},
		{
			desc:     "all uppercase",
			input:    "CONTENT-TYPE",
			expected: "Content-Type",
		},
		{
			desc:     "mixed case",
			input:    "cOnTeNt-TyPe",
			expected: "Content-Type",
		},
		{
			desc:     "single word",
			input:    "contenttype",
			expected: "Contenttype",
		},
		{
			desc:     "empty string",
			input:    "",
			expected: "",
		},
		{
			desc:     "already canonical",
			input:    "Content-Type",
			expected: "Content-Type",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			result := toCanonicalFieldName(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

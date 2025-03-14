package semantic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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

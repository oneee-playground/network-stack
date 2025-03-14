package util

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
			result := IsValidToken(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

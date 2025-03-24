package uri

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHex(t *testing.T) {
	assert.Equal(t, [2]byte{'F', 'F'}, hex(0xFF))
	assert.Equal(t, [2]byte{'3', '1'}, hex(0x31))
}

func TestUnhex(t *testing.T) {
	assert.Equal(t, byte(0xFF), unhex([2]byte{'F', 'F'}))
	assert.Equal(t, byte(0xFF), unhex([2]byte{'f', 'f'}))
	assert.Equal(t, byte(0x31), unhex([2]byte{'3', '1'}))
}

func TestShouldEscape(t *testing.T) {
	testcases := []struct {
		input    byte
		mode     encodeMode
		expected bool
	}{
		// unreserved
		{input: '3', expected: false},
		// Every test is now based on reserved char.
		{input: ';', mode: encodeUserInfo, expected: false}, // subdelim
		{input: ':', mode: encodeUserInfo, expected: false},
		{input: '/', mode: encodeUserInfo, expected: true},

		{input: ';', mode: encodeHost, expected: false}, // subdelim
		{input: '[', mode: encodeHost, expected: false},
		{input: ']', mode: encodeHost, expected: false},
		{input: ':', mode: encodeHost, expected: false},
		{input: '/', mode: encodeHost, expected: true},

		{input: ';', mode: encodePath, expected: false}, // subdelim
		{input: ':', mode: encodePath, expected: false},
		{input: '@', mode: encodePath, expected: false},
		{input: '/', mode: encodePath, expected: false},
		{input: '#', mode: encodePath, expected: true},

		{input: ';', mode: encodeQuery, expected: false}, // subdelim
		{input: ':', mode: encodeQuery, expected: false},
		{input: '@', mode: encodeQuery, expected: false},
		{input: '/', mode: encodeQuery, expected: false},
		{input: '?', mode: encodeQuery, expected: false},
		{input: '#', mode: encodeQuery, expected: true},

		{input: ';', mode: encodeFragment, expected: false}, // subdelim
		{input: ':', mode: encodeFragment, expected: false},
		{input: '@', mode: encodeFragment, expected: false},
		{input: '/', mode: encodeFragment, expected: false},
		{input: '?', mode: encodeFragment, expected: false},
		{input: '#', mode: encodeFragment, expected: true},
	}
	for _, tc := range testcases {
		t.Run(fmt.Sprintf("%d %c", tc.mode, tc.input), func(t *testing.T) {
			assert.Equal(t, tc.expected, shouldEscape(tc.input, tc.mode))
		})
	}
}

func TestEscape(t *testing.T) {
	testcases := []struct {
		desc     string
		input    string
		mode     encodeMode
		expected string
	}{
		{
			desc:     "userinfo",
			input:    "foo:password/bar",
			mode:     encodeUserInfo,
			expected: "foo:password%2Fbar",
		},
		{
			desc:     "host",
			input:    "한글.com",
			mode:     encodeHost,
			expected: "%ED%95%9C%EA%B8%80.com",
		},
		{
			desc:     "path",
			input:    "/path/to/#1",
			mode:     encodePath,
			expected: "/path/to/%231",
		},
		{
			desc:     "query",
			input:    "thisis[query]",
			mode:     encodeQuery,
			expected: "thisis%5Bquery%5D",
		},
		{
			desc:     "fragment",
			input:    "thisis[fragment]",
			mode:     encodeFragment,
			expected: "thisis%5Bfragment%5D",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			assert.Equal(t, tc.expected, escape(tc.input, tc.mode))
		})
	}
}

func TestUnescape(t *testing.T) {
	testcases := []struct {
		desc     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			desc:     "normal escaped",
			input:    "hey %5Bthere%5D",
			expected: "hey [there]",
		},
		{
			desc:     "normal escaped (lowercase)",
			input:    "hey %5bthere%5d",
			expected: "hey [there]",
		},
		{
			desc:    "malformed (not enough length)",
			input:   "hey %5bthere%5",
			wantErr: true,
		},
		{
			desc:    "malformed (non-hex)",
			input:   "hey %5bthere%5Z",
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			s, err := unescape(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, s)
		})
	}
}

package ipv6

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAddr(t *testing.T) {
	testcases := []struct {
		desc     string
		input    string
		expected Addr
		wantErr  bool
	}{
		{
			desc:  "example",
			input: "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF",
			expected: Addr{
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
		},
		{
			desc:  "case insensitive",
			input: "ffff:FFFF:ffff:FFFF:ffff:FFFF:ffff:FFFF",
			expected: Addr{
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
		},
		{
			desc:  "leading zeros are omittable",
			input: "FFFF:FFF:FF:F:0:F0:FF0:FFF0",
			expected: Addr{
				0xFF, 0xFF, 0x0F, 0xFF, 0x00, 0xFF, 0x00, 0x0F,
				0x00, 0x00, 0x00, 0xF0, 0x0F, 0xF0, 0xFF, 0xF0,
			},
		},
		{
			desc: "sequence of 0s are omittable with ::",
			// 0000:0000:0000:0000:0000:0000:0000:0000
			input: "::",
			expected: Addr{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			desc: "sequence of 0s are omittable with :: (last exists)",
			// 0000:0000:0000:0000:0000:0000:0000:0001
			input: "::1",
			expected: Addr{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
		},
		{
			desc: "sequence of 0s are omittable with :: (first exists)",
			// 0001:0000:0000:0000:0000:0000:0000:0000
			input: "1::",
			expected: Addr{
				0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			desc: "sequence of 0s are omittable with :: (on the middle)",
			// 0001:0012:0000:0000:0000:FFFF:0000:0013
			input: "1:12::FFFF:0:13",
			expected: Addr{
				0x00, 0x01, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x13,
			},
		},
		{
			desc:  "last element can be an ipv4 address",
			input: "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255",
			expected: Addr{
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
		},
		{
			desc:    "using non-hex value",
			input:   "ZZZZ:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF",
			wantErr: true,
		},
		{
			desc:    "length too long (2 bytes more)",
			input:   "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF",
			wantErr: true,
		},
		{
			desc:    "length too long on omitted",
			input:   "FFFF:FFFF:FFFF:FFFF::FFFF:FFFF:FFFF:FFFF",
			wantErr: true,
		},
		{
			desc:    "bad use of two colons (used more than once)",
			input:   "FFFF::FFFF:FFFF::FFFF:FFFF:FFFF",
			wantErr: true,
		},
		{
			desc:    "bad use of two colons (three colons)",
			input:   "FFFF::FFFF:::FFFF:FFFF:FFFF",
			wantErr: true,
		},
		{
			desc:    "ipv4 address on last, but invalid",
			input:   "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:255.255.foo.255",
			wantErr: true,
		},
		{
			desc:    "ipv4 address on middle",
			input:   "FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255:FFFF:FFFF",
			wantErr: true,
		},
		{
			desc:    "ipv4 address on middle (seperated by two colons)",
			input:   "FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255::",
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			parsed, err := ParseAddr(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Zero(t, parsed)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, parsed)
		})
	}
}

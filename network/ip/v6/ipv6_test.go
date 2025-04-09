package ipv6

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var testpairs = []struct {
	desc string
	repr string
	addr Addr
}{
	{
		desc: "example",
		repr: "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF",
		addr: Addr{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		},
	},
	{
		desc: "leading zeros are omittable",
		repr: "FFFF:FFF:FF:F:0:F0:FF0:FFF0",
		addr: Addr{
			0xFF, 0xFF, 0x0F, 0xFF, 0x00, 0xFF, 0x00, 0x0F,
			0x00, 0x00, 0x00, 0xF0, 0x0F, 0xF0, 0xFF, 0xF0,
		},
	},
	{
		desc: "sequence of 0s are omittable with ::",
		// 0000:0000:0000:0000:0000:0000:0000:0000
		repr: "::",
		addr: Addr{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
	},
	{
		desc: "sequence of 0s are omittable with :: (last exists)",
		// 0000:0000:0000:0000:0000:0000:0000:0001
		repr: "::1",
		addr: Addr{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
	},
	{
		desc: "sequence of 0s are omittable with :: (first exists)",
		// 0001:0000:0000:0000:0000:0000:0000:0000
		repr: "1::",
		addr: Addr{
			0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
	},
	{
		desc: "sequence of 0s are omittable with :: (on the middle)",
		// 0001:0012:0000:0000:0000:FFFF:0000:0013
		repr: "1:12::FFFF:0:13",
		addr: Addr{
			0x00, 0x01, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x13,
		},
	},
}

func TestParseAddr(t *testing.T) {
	testcases := []struct {
		desc     string
		input    string
		expected Addr
		wantErr  bool
	}{
		{
			desc:  "case insensitive",
			input: "ffff:FFFF:ffff:FFFF:ffff:FFFF:ffff:FFFF",
			expected: Addr{
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
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

	for _, pair := range testpairs {
		testcases = append(testcases,
			struct {
				desc     string
				input    string
				expected Addr
				wantErr  bool
			}{
				desc:     pair.desc,
				input:    pair.repr,
				expected: pair.addr,
			})
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

func TestAddrToString(t *testing.T) {
	testcases := []struct {
		desc string
		addr Addr
		repr string
	}{}

	for _, pair := range testpairs {
		testcases = append(testcases,
			struct {
				desc string
				addr Addr
				repr string
			}{
				desc: pair.desc,
				addr: pair.addr,
				repr: pair.repr,
			})
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			assert.Equal(t, tc.repr, tc.addr.String())
		})
	}
}

package ipv4

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
			desc:     "localhost",
			input:    "127.0.0.1",
			expected: Addr{127, 0, 0, 1},
			wantErr:  false,
		},
		{
			desc:    "missing a digit",
			input:   "127.0.0",
			wantErr: true,
		},
		{
			desc:    "non-digit",
			input:   "foo.0.0.1s",
			wantErr: true,
		},
		{
			desc:    "bigger than 255",
			input:   "256.0.0.1",
			wantErr: true,
		},
		{
			desc:    "negative number",
			input:   "127.0.0.-1",
			wantErr: true,
		},
		{
			desc:    "leading 0",
			input:   "127.0.0.01",
			wantErr: true,
		},
		{
			desc:    "unnecessary 0",
			input:   "127.0.00.1",
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

func TestAddrToUint32(t *testing.T) {
	addr := Addr{0xFF, 0xEE, 0x00, 0x22}
	expected := uint32(0xFFEE0022)
	assert.Equal(t, expected, addr.ToUint32())
}

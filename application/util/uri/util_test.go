package uri

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAssertValidScheme(t *testing.T) {
	testcases := []struct {
		desc    string
		input   string
		wantErr bool
	}{
		{
			desc:    "single char (alpha)",
			input:   "A",
			wantErr: false,
		},
		{
			desc:    "example",
			input:   "http",
			wantErr: false,
		},
		{
			desc:    "'+', '-', '.' are allowed",
			input:   "ht+-.tp",
			wantErr: false,
		},
		{
			desc:    "empty",
			input:   "",
			wantErr: true,
		},
		{
			desc:    "first char not alpha",
			input:   "+http",
			wantErr: true,
		},
		{
			desc:    "invalid char",
			input:   "ht=tp",
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			err := assertValidScheme(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestAssertValidHost(t *testing.T) {
	testcases := []struct {
		desc    string
		input   string
		wantErr bool
	}{
		{
			desc:    "example (reg-name)",
			input:   "example.com",
			wantErr: false,
		},
		{
			desc:    "example (ipv4)",
			input:   "127.0.0.1",
			wantErr: false,
		},
		{
			desc:    "example (ip literal, ipv6)",
			input:   "[::]",
			wantErr: false,
		},
		{
			desc:    "example (ip literal, ipvfutre)",
			input:   "[vF.0:1:32342442:1]",
			wantErr: false,
		},
		{
			desc:    "empty (valid)",
			input:   "",
			wantErr: false,
		},
		{
			desc:    "length limit exceeded",
			input:   strings.Repeat("A", 256),
			wantErr: true,
		},
		{
			desc:    "invalid char",
			input:   "example/.com",
			wantErr: true,
		},
		{
			desc:    "malformed ip literal",
			input:   "[hey trust me]",
			wantErr: true,
		},
		{
			desc:    "isn't even ip literal",
			input:   "[example.com",
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			err := assertValidHost(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestIsValidUserInfo(t *testing.T) {
	testcases := []struct {
		desc  string
		input string
		valid bool
	}{
		{
			desc:  "example",
			input: "username:password",
			valid: true,
		},
		{
			desc:  "example (percent-encoded)",
			input: "100%25",
			valid: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			assert.Equal(t, tc.valid, isValidUserInfo(tc.input))
		})
	}
}

func TestIsValidRegName(t *testing.T) {
	testcases := []struct {
		desc  string
		input string
		valid bool
	}{
		{
			desc:  "example",
			input: "example.com",
			valid: true,
		},
		{
			desc:  "example (percent-encoded)",
			input: "100%25",
			valid: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			assert.Equal(t, tc.valid, isValidRegName(tc.input))
		})
	}
}

func TestIsIPvFuture(t *testing.T) {
	testcases := []struct {
		desc  string
		input string
		valid bool
	}{
		{
			desc:  "example",
			input: "v8.123:123:123",
			valid: true,
		},
		{
			desc:  "non-hex",
			input: "vz.53:123",
			valid: false,
		},
		{
			desc:  "no v",
			input: "3.53:123",
			valid: false,
		},
		{
			desc:  "no .",
			input: "v353:123",
			valid: false,
		},
		{
			desc:  "too short",
			input: "v3",
			valid: false,
		},
		{
			desc:  "reserved character",
			input: "v3.123:/123",
			valid: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			assert.Equal(t, tc.valid, isIPvFuture(tc.input))
		})
	}
}

func TestAssertValidPath(t *testing.T) {
	testcases := []struct {
		desc         string
		input        string
		hasAuthority bool
		isRelative   bool
		wantErr      bool
	}{
		{
			desc:         "absoulte path",
			input:        "/path/to/resource",
			hasAuthority: false,
			isRelative:   false,
			wantErr:      false,
		},
		{
			desc:         "non-relative path starts with '//'",
			input:        "//path/to/resource",
			hasAuthority: false,
			isRelative:   false,
			wantErr:      true,
		},
		{
			desc:         "relative path (rootless)",
			input:        "path/to/resource",
			hasAuthority: false,
			isRelative:   true,
			wantErr:      false,
		},
		{
			desc:         "relative path (rootless) 2",
			input:        "../path/to/resource",
			hasAuthority: false,
			isRelative:   true,
			wantErr:      false,
		},

		{
			desc:         "relative reference with absolute path",
			input:        "/hey/there",
			hasAuthority: false,
			isRelative:   true,
			wantErr:      false,
		},
		{
			desc:         "relative path with colon on first segment",
			input:        "oh:/hey/there",
			hasAuthority: false,
			isRelative:   true,
			wantErr:      true,
		},
		{
			desc:         "has authority",
			input:        "/path/to/resource",
			hasAuthority: true,
			isRelative:   false,
			wantErr:      false,
		},
		{
			desc:         "has authority (empty)",
			input:        "",
			hasAuthority: true,
			isRelative:   false,
			wantErr:      false,
		},
		{
			desc:         "has authority (wrong start char)",
			input:        "v/path/to/resource",
			hasAuthority: true,
			isRelative:   true,
			wantErr:      true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			err := assertValidPath(tc.input, tc.hasAuthority, tc.isRelative)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

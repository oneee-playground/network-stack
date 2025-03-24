package uri

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func newp[T any](n T) *T {
	return &n
}

func TestParse(t *testing.T) {
	testcases := []struct {
		desc  string
		input string

		uri     URI
		wantErr bool
	}{
		{
			desc:  "example on RFC (1)",
			input: "ftp://ftp.is.co.za/rfc/rfc1808.txt",
			uri: URI{
				Scheme: "ftp",
				Authority: &Authority{
					Host: "ftp.is.co.za",
				},
				Path: "/rfc/rfc1808.txt",
			},
		},
		{
			desc:  "example on RFC (2)",
			input: "http://www.ietf.org/rfc/rfc2396.txt",
			uri: URI{
				Scheme: "http",
				Authority: &Authority{
					Host: "www.ietf.org",
				},
				Path: "/rfc/rfc2396.txt",
			},
		},
		{
			desc:  "example on RFC (3)",
			input: "ldap://[2001:db8::7]/c=GB?objectClass?one",
			uri: URI{
				Scheme: "ldap",
				Authority: &Authority{
					Host: "[2001:db8::7]",
				},
				Path:  "/c=GB",
				Query: newp("objectClass?one"),
			},
		},
		{
			desc:  "example on RFC (4)",
			input: "mailto:John.Doe@example.com",
			uri: URI{
				Scheme: "mailto",
				Path:   "John.Doe@example.com",
			},
		},
		{
			desc:  "example on RFC (5)",
			input: "news:comp.infosystems.www.servers.unix",
			uri: URI{
				Scheme: "news",
				Path:   "comp.infosystems.www.servers.unix",
			},
		},
		{
			desc:  "example on RFC (6)",
			input: "tel:+1-816-555-1212",
			uri: URI{
				Scheme: "tel",
				Path:   "+1-816-555-1212",
			},
		},
		{
			desc:  "example on RFC (7)",
			input: "telnet://192.0.2.16:80/",
			uri: URI{
				Scheme: "telnet",
				Authority: &Authority{
					Host: "192.0.2.16",
					Port: newp(uint16(80)),
				},
				Path: "/",
			},
		},
		{
			desc:  "example on RFC (8)",
			input: "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
			uri: URI{
				Scheme: "urn",
				Path:   "oasis:names:specification:docbook:dtd:xml:4.1.2",
			},
		},
		{
			desc:  "scheme is lowercased",
			input: "HTTP://localhost",
			uri: URI{
				Scheme: "http",
				Authority: &Authority{
					Host: "localhost",
				},
			},
		},
		{
			desc:  "relative reference (network-path)",
			input: "//localhost/",
			uri: URI{
				Authority: &Authority{
					Host: "localhost",
				},
				Path: "/",
			},
		},
		{
			desc:  "relative reference (absolute)",
			input: "path/relative/ref",
			uri: URI{
				Path: "path/relative/ref",
			},
		},
		{
			desc:  "relative reference (empty)",
			input: "",
			uri:   URI{},
		},
		{
			desc:    "contains CTL (control byte)",
			input:   "\t",
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			uri, err := Parse(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.uri, uri)
		})
	}
}

func TestCutScheme(t *testing.T) {
	testcases := []struct {
		desc  string
		input string

		scheme  string
		rest    string
		wantErr bool
	}{
		{
			desc:   "example",
			input:  "http://example.com",
			scheme: "http",
			rest:   "//example.com",
		},
		{
			desc:   "seperator not found",
			input:  "hahanoseperator",
			scheme: "",
			rest:   "hahanoseperator",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			scheme, rest, err := cutScheme(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.scheme, scheme)
			assert.Equal(t, tc.rest, rest)
		})
	}
}

func TestParseAuthority(t *testing.T) {
	testcases := []struct {
		desc  string
		input string

		authority Authority
		wantErr   bool
	}{
		{
			desc:  "example",
			input: "user:pass@example.com:8080",
			authority: Authority{
				UserInfo: "user:pass",
				Host:     "example.com",
				Port:     newp(uint16(8080)),
			},
		},
		{
			desc:  "no user info",
			input: "example.com:8080",
			authority: Authority{
				UserInfo: "",
				Host:     "example.com",
				Port:     newp(uint16(8080)),
			},
		},
		{
			desc:  "no port too",
			input: "example.com",
			authority: Authority{
				UserInfo: "",
				Host:     "example.com",
				Port:     nil,
			},
		},
		{
			desc:  "no host",
			input: "user:pass@:8080",
			authority: Authority{
				UserInfo: "user:pass",
				Host:     "",
				Port:     newp(uint16(8080)),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			authority, err := parseAuthority(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.authority, authority)
		})
	}
}

func TestGetHostPort(t *testing.T) {
	testcases := []struct {
		desc  string
		input string

		host     string
		portPart string
		wantErr  bool
	}{
		{
			desc:     "reg-name",
			input:    "localhost:8080",
			host:     "localhost",
			portPart: ":8080",
		},
		{
			desc:     "reg-name (no port)",
			input:    "localhost",
			host:     "localhost",
			portPart: "",
		},
		{
			desc:     "ip literal",
			input:    "[::1]:8080",
			host:     "[::1]",
			portPart: ":8080",
		},
		{
			desc:     "ip literal (no port)",
			input:    "[::1]",
			host:     "[::1]",
			portPart: "",
		},
		{
			desc:    "ip literal (malformed)",
			input:   "[::1",
			wantErr: true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			host, portPart, err := getHostPort(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.host, host)
			assert.Equal(t, tc.portPart, portPart)
		})
	}
}

func TestParsePort(t *testing.T) {
	testcases := []struct {
		desc    string
		input   string
		port    uint16
		hasPort bool
		wantErr bool
	}{
		{
			desc:    "empty",
			input:   "",
			port:    0,
			hasPort: false,
		},
		{
			desc:    "port 80",
			input:   ":80",
			port:    80,
			hasPort: true,
		},
		{
			desc:    "no colon delim",
			input:   "45",
			wantErr: true,
		},
		{
			desc:    "no digit after colon",
			input:   ":",
			wantErr: true,
		},
		{
			desc:    "leading zero",
			input:   ":001",
			wantErr: true,
		},
		{
			desc:    "exceeding 16bit",
			input:   ":100000",
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			port, hasPort, err := parsePort(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.hasPort, hasPort)
			assert.Equal(t, tc.port, port)
		})
	}
}

func TestSplitPathQueryFrag(t *testing.T) {
	testcases := []struct {
		desc  string
		input string

		path  string
		query string
		frag  string
	}{
		{
			desc:  "example",
			input: "/path/to/resource?filtered#section",
			path:  "/path/to/resource",
			query: "?filtered",
			frag:  "#section",
		},
		{
			desc:  "no path",
			input: "?filtered#section",
			path:  "",
			query: "?filtered",
			frag:  "#section",
		},
		{
			desc:  "no query",
			input: "/path/to/resource#section",
			path:  "/path/to/resource",
			query: "",
			frag:  "#section",
		},
		{
			desc:  "no frag",
			input: "/path/to/resource?filtered",
			path:  "/path/to/resource",
			query: "?filtered",
			frag:  "",
		},
		{
			desc:  "single query delim",
			input: "?",
			path:  "",
			query: "?",
			frag:  "",
		},
		{
			desc:  "single frag delim",
			input: "#",
			path:  "",
			query: "",
			frag:  "#",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			path, query, frag := splitPathQueryFrag(tc.input)
			assert.Equal(t, tc.path, path)
			assert.Equal(t, tc.query, query)
			assert.Equal(t, tc.frag, frag)
		})
	}
}

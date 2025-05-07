package uri

import (
	"network-stack/lib/types/pointer"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var examplePairs []struct {
	desc string
	raw  string
	uri  URI
} = []struct {
	desc string
	raw  string
	uri  URI
}{
	{
		raw: "ftp://ftp.is.co.za/rfc/rfc1808.txt",
		uri: URI{
			Scheme: "ftp",
			Authority: &Authority{
				Host: "ftp.is.co.za",
			},
			Path: "/rfc/rfc1808.txt",
		},
	},
	{
		raw: "http://www.ietf.org/rfc/rfc2396.txt",
		uri: URI{
			Scheme: "http",
			Authority: &Authority{
				Host: "www.ietf.org",
			},
			Path: "/rfc/rfc2396.txt",
		},
	},
	{
		raw: "ldap://[2001:db8::7]/c=GB?objectClass?one",
		uri: URI{
			Scheme: "ldap",
			Authority: &Authority{
				Host: "[2001:db8::7]",
			},
			Path:  "/c=GB",
			Query: pointer.To("objectClass?one"),
		},
	},
	{
		raw: "mailto:John.Doe@example.com",
		uri: URI{
			Scheme: "mailto",
			Path:   "John.Doe@example.com",
		},
	},
	{
		raw: "news:comp.infosystems.www.servers.unix",
		uri: URI{
			Scheme: "news",
			Path:   "comp.infosystems.www.servers.unix",
		},
	},
	{
		raw: "tel:+1-816-555-1212",
		uri: URI{
			Scheme: "tel",
			Path:   "+1-816-555-1212",
		},
	},
	{
		raw: "telnet://192.0.2.16:80/",
		uri: URI{
			Scheme: "telnet",
			Authority: &Authority{
				Host: "192.0.2.16",
				Port: pointer.To(uint16(80)),
			},
			Path: "/",
		},
	},
	{
		raw: "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
		uri: URI{
			Scheme: "urn",
			Path:   "oasis:names:specification:docbook:dtd:xml:4.1.2",
		},
	},
	{
		desc: "relative reference (network-path)",
		raw:  "//localhost/",
		uri: URI{
			Authority: &Authority{
				Host: "localhost",
			},
			Path: "/",
		},
	},
	{
		desc: "relative reference (absolute)",
		raw:  "path/relative/ref",
		uri: URI{
			Path: "path/relative/ref",
		},
	},
	{
		desc: "relative reference (empty)",
		raw:  "",
		uri:  URI{},
	},
}

func TestIsValid(t *testing.T) {
	testcases := []struct {
		desc    string
		uri     URI
		wantErr bool
	}{
		// Let's test this later if we want,
		// as it consists of tested functions.
		{},
	}
	for _, example := range examplePairs {
		desc := example.desc
		if desc == "" {
			desc = example.raw
		}

		testcases = append(testcases,
			struct {
				desc    string
				uri     URI
				wantErr bool
			}{
				desc:    desc,
				uri:     example.uri,
				wantErr: false,
			})
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			err := tc.uri.IsValid()
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestURIString(t *testing.T) {
	for _, example := range examplePairs {
		desc := example.desc
		if desc == "" {
			desc = example.raw
		}

		t.Run(desc, func(t *testing.T) {
			assert.Equal(t, example.raw, example.uri.String())
		})
	}
}

func TestNormalize(t *testing.T) {
	testcases := []struct {
		desc   string
		input  URI
		output URI
	}{
		{
			desc: "lowercase scheme and host",
			input: URI{
				Scheme: "HTTP",
				Authority: &Authority{
					Host: "www.EXAMPLE.com",
				},
			},
			output: URI{
				Scheme: "http",
				Authority: &Authority{
					Host: "www.example.com",
				},
			},
		},
		{
			desc: "removes percent encoding",
			input: URI{
				Scheme: "example",
				Authority: &Authority{
					Host: "a",
				},
				Path: "/b/c/%7Bfoo%7D",
			},
			output: URI{
				Scheme: "example",
				Authority: &Authority{
					Host: "a",
				},
				Path: "/b/c/{foo}",
			},
		},
		{
			desc: "removes dot segments",
			input: URI{
				Scheme: "example",
				Path:   "/a/b/c/./../../g",
			},
			output: URI{
				Scheme: "example",
				Path:   "/a/g",
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			out, err := Normalize(tc.input)
			require.NoError(t, err)

			assert.Equal(t, tc.output, out)
		})
	}
}

func TestParse(t *testing.T) {
	testcases := []struct {
		desc  string
		input string

		uri     URI
		wantErr bool
	}{
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
			desc:  "host is lowercased",
			input: "http://LOcalHOST",
			uri: URI{
				Scheme: "http",
				Authority: &Authority{
					Host: "localhost",
				},
			},
		},
		{
			desc:    "contains CTL (control byte)",
			input:   "\t",
			wantErr: true,
		},
	}
	for _, example := range examplePairs {
		desc := example.desc
		if desc == "" {
			desc = example.raw
		}

		testcases = append(testcases,
			struct {
				desc    string
				input   string
				uri     URI
				wantErr bool
			}{
				desc:    desc,
				input:   example.raw,
				uri:     example.uri,
				wantErr: false,
			})
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
				Port:     pointer.To(uint16(8080)),
			},
		},
		{
			desc:  "no user info",
			input: "example.com:8080",
			authority: Authority{
				UserInfo: "",
				Host:     "example.com",
				Port:     pointer.To(uint16(8080)),
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
				Port:     pointer.To(uint16(8080)),
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
			desc:    "no digit after colon",
			input:   ":",
			port:    0,
			hasPort: false,
		},
		{
			desc:    "no colon delim",
			input:   "45",
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
			port, hasPort, err := ParsePort(tc.input)
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

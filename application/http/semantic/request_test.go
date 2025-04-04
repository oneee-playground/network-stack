package semantic

import (
	"network-stack/application/http"
	"network-stack/application/util/uri"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestFrom(t *testing.T) {
	nobody := strings.NewReader("")
	// Assume it is valid.
	raw := http.Request{
		RequestLine: http.RequestLine{
			Method:  "GET",
			Target:  "http://localhost/",
			Version: http.Version{1, 1},
		},
		Headers: []http.Field{
			{Name: []byte("Host"), Value: []byte("example.com")},
		},
		Body: nobody,
	}

	// Also test Host header is overwritten by absolute uri.
	expected := &Request{
		Method: MethodGet,
		URI: uri.URI{
			Scheme:    "http",
			Authority: &uri.Authority{Host: "localhost"},
			Path:      "/",
		},
		Host: "localhost",
		Message: Message{
			Version: raw.Version,
			Headers: NewHeaders(map[string][]string{
				"Host": {"localhost"},
			}),
			ContentLength:    nil,
			TransferEncoding: nil,
			Body:             nobody,
			Trailers:         nil,
		},
	}

	request, err := RequestFrom(&raw, ParseRequestOptions{})
	require.NoError(t, err)

	assert.Equal(t, expected, request)

	// Also test RawRequest.
	raw.Headers[0].Value = []byte("localhost") // as this field is overwritten.

	assert.Equal(t, raw, request.RawRequest())
}

func TestParseAndValidateURI(t *testing.T) {
	eighty := uint16(80) // agian..

	testcases := []struct {
		desc  string
		input string
		// options
		method         Method
		isForwardProxy bool
		maxLen         uint

		expected uri.URI
		wantErr  bool
	}{
		// Assume input is valid URI.
		{
			desc:    "too long",
			input:   "http://example.com/",
			maxLen:  5,
			wantErr: true,
		},
		{
			desc:   "connect request",
			input:  "www.example.com:80",
			method: MethodConnect,
			expected: uri.URI{
				Authority: &uri.Authority{
					Host: "www.example.com",
					Port: &eighty,
				},
			},
		},
		{
			desc:     "options request",
			input:    "*",
			method:   MethodOptions,
			expected: uri.URI{Path: "*"},
		},
		{
			desc:    "options request but not asterisk",
			input:   "gotcha",
			method:  MethodOptions,
			wantErr: true,
		},
		{
			desc:  "absolute uri",
			input: "http://localhost/",
			expected: uri.URI{
				Scheme: "http",
				Authority: &uri.Authority{
					Host: "localhost",
				},
				Path: "/",
			},
		},
		{
			desc:    "absolute uri but not http/https",
			input:   "coffee://the.great.pot",
			wantErr: true,
		},
		{
			desc:    "absolute uri but no host",
			input:   "http:/hey",
			wantErr: true,
		},
		{
			desc:     "origin-form",
			input:    "/hey",
			expected: uri.URI{Path: "/hey"},
		},
		{
			desc:           "origin-form but is forward proxy",
			input:          "/hey",
			isForwardProxy: true,
			wantErr:        true,
		},
		{
			desc:    "origin-form but doesn't start with /",
			input:   "hey",
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			uri, err := parseAndValidateURI(tc.input, tc.method, tc.isForwardProxy, tc.maxLen)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, uri)
		})
	}
}

func TestParseAuthorityForm(t *testing.T) {
	eighty := uint16(80) // ok..

	testcase := []struct {
		desc     string
		input    string
		expected uri.URI
		wantErr  bool
	}{
		{
			desc:  "example",
			input: "www.example.com:80",
			expected: uri.URI{
				Authority: &uri.Authority{
					Host: "www.example.com",
					Port: &eighty,
				},
			},
		},
		{
			desc:    "no colon",
			input:   "www.example.com",
			wantErr: true,
		},
		{
			desc:    "no port",
			input:   "www.example.com:",
			wantErr: true,
		},
	}

	for _, tc := range testcase {
		t.Run(tc.desc, func(t *testing.T) {
			uri, err := parseAuthorityForm(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, uri)
		})
	}
}

func TestNormalizeURI(t *testing.T) {
	expected, err := uri.Parse("http://example.com/~smith/home.html")
	require.NoError(t, err)

	testcases := []struct {
		desc  string
		input string
	}{
		{
			desc:  "default port for http is hidden",
			input: "http://example.com:80/~smith/home.html",
		},
		{
			desc:  "lowercasing host & escaped",
			input: "http://EXAMPLE.com/%7Esmith/home.html",
		},
		{
			desc:  "lowercasing host & escaped & no port",
			input: "http://EXAMPLE.com:/%7esmith/home.html",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			parsed, err := uri.Parse(tc.input)
			require.NoError(t, err)
			assert.Equal(t, expected, normalizeURI(parsed))
		})
	}
}

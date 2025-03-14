package http

import (
	"bufio"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type MessageDecoderTestSuite struct {
	suite.Suite
}

func TestMessageDecoderTestSuite(t *testing.T) {
	suite.Run(t, new(MessageDecoderTestSuite))
}

func (s *MessageDecoderTestSuite) TestReadLine() {
	testcases := []struct {
		desc     string
		opts     DecodeOptions
		limit    uint
		input    string
		expected string
		wantErr  bool
	}{
		{
			desc:     "simple line with CRLF",
			input:    "Hello\r\n",
			expected: "Hello",
		},
		{
			desc:    "line exceeding limit",
			input:   "Hey\r\n",
			limit:   1,
			wantErr: true,
		},
		{
			desc:    "Sole LF (fail)",
			input:   "Hello\n",
			wantErr: true,
		},
		{
			desc:     "Sole LF (success)",
			opts:     DecodeOptions{AllowSoleLF: true},
			input:    "Hello\n",
			expected: "Hello",
		},
		{
			desc:     "line without CR before LF",
			input:    "Hello \r World!\r\n",
			expected: "Hello   World!",
		},
		{
			desc:     "line with lenient whitespace",
			opts:     DecodeOptions{LenientWhitespace: true},
			input:    "Hello" + string(whitespaces) + "World!" + "\r\n",
			expected: "Hello" + strings.Repeat(" ", len(whitespaces)) + "World!",
		},
		{
			desc:     "lenient whitespace trimmed",
			opts:     DecodeOptions{LenientWhitespace: true},
			input:    string(whitespaces) + "Hey" + string(whitespaces) + "\r\n",
			expected: "Hey",
		},
	}
	for _, tc := range testcases {
		s.Run(tc.desc, func() {
			d := MessageDecoder{
				br:   bufio.NewReader(strings.NewReader(tc.input)),
				opts: tc.opts,
			}

			b, err := d.readLine(tc.limit)
			if tc.wantErr {
				s.Error(err)
				return
			}

			s.NoError(err)
			s.Equal(tc.expected, string(b))
		})
	}
}

func (s *MessageDecoderTestSuite) TestDecodeHeaders() {
	testcases := []struct {
		desc     string
		opts     DecodeOptions
		input    string
		expected Headers
		wantErr  bool
	}{
		{
			desc: "simple headers",
			input: "" +
				"Content-Type: text/html\r\n" +
				"Content-Length: 123\r\n" +
				"\r\n",
			expected: Headers{
				{"Content-Type", "text/html"},
				{"Content-Length", "123"},
			},
		},
		{
			desc: "headers with leading and trailing whitespace",
			input: "" +
				"Content-Type:   text/html  \r\n" +
				"Content-Length:   123\t\r\n" +
				"\r\n",
			expected: Headers{
				{"Content-Type", "text/html"},
				{"Content-Length", "123"},
			},
		},
		{
			desc: "field name is not a valid token",
			input: "" +
				"content type: text/html\r\n" +
				"Content-Length: 123\r\n" +
				"\r\n",
			expected: Headers{
				{"content type", "text/html"},
				{"Content-Length", "123"},
			},
		},
		{
			desc: "headers exceeding limit",
			opts: DecodeOptions{MaxFieldLineLength: 5},
			input: "" +
				"Content-Type: text/html\r\n" +
				"\r\n",
			wantErr: true,
		},
	}
	for _, tc := range testcases {
		s.Run(tc.desc, func() {
			d := MessageDecoder{
				br:   bufio.NewReader(strings.NewReader(tc.input)),
				opts: tc.opts,
			}

			h := Headers{}
			err := d.decodeHeaders(&h)
			if tc.wantErr {
				s.Error(err)
				return
			}

			s.NoError(err)
			s.Equal(tc.expected, h)
		})
	}
}

type RequestDecoderTestSuite struct {
	suite.Suite
}

func TestRequestDecoderTestSuite(t *testing.T) {
	suite.Run(t, new(RequestDecoderTestSuite))
}

func (s *RequestDecoderTestSuite) TestDecode() {
	body := "field1=value1"

	rawRequest := "" +
		"POST /example HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 13\r\n" +
		"\r\n" +
		body

	expected := Request{
		requestLine: requestLine{
			Method:  "POST",
			Target:  "/example",
			Version: Version{1, 1},
		},
		Headers: Headers{
			{"Host", "example.com"},
			{"Content-Type", "application/x-www-form-urlencoded"},
			{"Content-Length", "13"},
		},
	}

	rd := NewRequestDecoder(strings.NewReader(rawRequest), DefaultDecodeOptions)

	var request Request
	err := rd.Decode(&request)
	s.NoError(err)

	// For assertion.
	bodyReader := request.Body
	request.Body = nil

	s.Equal(expected, request)

	b, err := io.ReadAll(bodyReader)
	s.NoError(err)

	s.Equal(body, string(b))
}

func (s *RequestDecoderTestSuite) TestDecodeRequestLine() {
	rawReqLine := "" +
		"\r\n" + // leading empty lines.
		"\r\n" +
		"GET /abc HTTP/1.1\r\n"

	rd := NewRequestDecoder(strings.NewReader(rawReqLine), DefaultDecodeOptions)

	var reqLine requestLine
	err := rd.decodeRequestLine(&reqLine)

	s.NoError(err)
	s.Equal(requestLine{
		Method:  "GET",
		Target:  "/abc",
		Version: Version{1, 1},
	}, reqLine)
}

func TestParseRequestLine(t *testing.T) {
	testcases := []struct {
		desc     string
		input    []byte
		expected requestLine
		wantErr  bool
	}{
		{
			input: []byte("GET / HTTP/1.0"),
			expected: requestLine{
				Method:  "GET",
				Target:  "/",
				Version: Version{1, 0},
			},
		},
		{
			input: []byte("POST /nested/path HTTP/0.3"),
			expected: requestLine{
				Method:  "POST",
				Target:  "/nested/path",
				Version: Version{0, 3},
			},
		},
		{
			desc:    "invalid request line",
			input:   []byte("INVALID_REQUEST_LINE"),
			wantErr: true,
		},
		{
			desc:    "missing method",
			input:   []byte(" /hey HTTP/1.1"),
			wantErr: true,
		},
		{
			desc:    "missing URI",
			input:   []byte("GET  HTTP/1.1"),
			wantErr: true,
		},
		{
			desc:    "missing version",
			input:   []byte("GET /missing/version"),
			wantErr: true,
		},
		{
			desc:    "invalid HTTP version",
			input:   []byte("GET / HTTP/1.x"),
			wantErr: true,
		},
	}
	for _, tc := range testcases {
		desc := tc.desc
		if desc == "" {
			desc = string(tc.input)
		}

		t.Run(desc, func(t *testing.T) {
			reqLine, err := parseRequestLine(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, reqLine, tc.expected)
		})
	}
}

type ResponseDecoderTestSuite struct {
	suite.Suite
}

func TestResponseDecoderTestSuite(t *testing.T) {
	suite.Run(t, new(ResponseDecoderTestSuite))
}

func (s *ResponseDecoderTestSuite) TestDecode() {
	body := "Hello, world!"

	rawResponse := "" +
		"HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 13\r\n" +
		"\r\n" +
		body

	expected := Response{
		statusLine: statusLine{
			Version:      Version{1, 1},
			StatusCode:   200,
			ReasonPhrase: "OK",
		},
		Headers: Headers{
			{"Content-Type", "text/plain"},
			{"Content-Length", "13"},
		},
	}

	rd := NewResponseDecoder(strings.NewReader(rawResponse), DefaultDecodeOptions)

	var response Response
	err := rd.Decode(&response)
	s.NoError(err)

	// For assertion.
	bodyReader := response.Body
	response.Body = nil

	s.Equal(expected, response)

	b, err := io.ReadAll(bodyReader)
	s.NoError(err)

	s.Equal(body, string(b))
}

func (s *ResponseDecoderTestSuite) TestDecodeStatusLine() {
	rawStatLine := "" +
		"\r\n" + // leading empty lines.
		"\r\n" +
		"HTTP/1.1 200 OK\r\n"

	rd := NewResponseDecoder(strings.NewReader(rawStatLine), DefaultDecodeOptions)

	var statLine statusLine
	err := rd.decodeStatusLine(&statLine)

	s.NoError(err)
	s.Equal(statusLine{
		Version:      Version{1, 1},
		StatusCode:   200,
		ReasonPhrase: "OK",
	}, statLine)
}

func TestParseStatusLine(t *testing.T) {
	testcases := []struct {
		desc     string
		input    []byte
		expected statusLine
		wantErr  bool
	}{
		{
			desc:  "valid status line",
			input: []byte("HTTP/1.1 200 OK"),
			expected: statusLine{
				Version:      Version{1, 1},
				StatusCode:   200,
				ReasonPhrase: "OK",
			},
		},
		{
			desc:  "valid status line with reason phrase",
			input: []byte("HTTP/1.0 404 Not Found"),
			expected: statusLine{
				Version:      Version{1, 0},
				StatusCode:   404,
				ReasonPhrase: "Not Found",
			},
		},
		{
			desc:    "invalid status line",
			input:   []byte("INVALID_STATUS_LINE"),
			wantErr: true,
		},
		{
			desc:    "missing HTTP version",
			input:   []byte(" 200 OK"),
			wantErr: true,
		},
		{
			desc:    "missing status code",
			input:   []byte("HTTP/1.1  OK"),
			wantErr: true,
		},
		{
			desc:    "invalid status code",
			input:   []byte("HTTP/1.1 ABC OK"),
			wantErr: true,
		},
		{
			desc:    "non-3digit status code",
			input:   []byte("HTTP/1.1 1000 OK"),
			wantErr: true,
		},
		{
			desc:    "missing reason phrase",
			input:   []byte("HTTP/1.1 200 "),
			wantErr: false,
			expected: statusLine{
				Version:      Version{1, 1},
				StatusCode:   200,
				ReasonPhrase: "",
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			statLine, err := parseStatusLine(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, statLine)
		})
	}
}

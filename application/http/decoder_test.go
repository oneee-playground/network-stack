package http

import (
	"bufio"
	"bytes"
	"io"
	"network-stack/application/util/rule"
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
		wantErr  error
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
			wantErr: errLineTooLong,
		},
		{
			desc:    "Sole LF (fail)",
			input:   "Hello\n",
			wantErr: ErrMissingCRBeforeLF,
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
			input:    "Hello" + string(rule.Whitespaces) + "World!" + "\r\n",
			expected: "Hello" + strings.Repeat(" ", len(rule.Whitespaces)) + "World!",
		},
		{
			desc:     "lenient whitespace trimmed",
			opts:     DecodeOptions{LenientWhitespace: true},
			input:    string(rule.Whitespaces) + "Hey" + string(rule.Whitespaces) + "\r\n",
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
			if tc.wantErr != nil {
				s.ErrorIs(err, tc.wantErr)
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
		expected []Field
		wantErr  error
	}{
		{
			desc: "simple headers",
			input: "" +
				"Content-Type: text/html\r\n" +
				"Content-Length: 123\r\n" +
				"\r\n",
			expected: []Field{
				{[]byte("Content-Type"), []byte("text/html")},
				{[]byte("Content-Length"), []byte("123")},
			},
		},
		{
			desc: "headers exceeding limit",
			opts: DecodeOptions{MaxFieldLineLength: 5},
			input: "" +
				"Content-Type: text/html\r\n" +
				"\r\n",
			wantErr: ErrFieldLineTooLong,
		},
		{
			desc:    "malformed headers",
			input:   "Content-Type text/html\r\n",
			wantErr: ErrMalformedFieldLine,
		},
	}
	for _, tc := range testcases {
		s.Run(tc.desc, func() {
			d := MessageDecoder{
				br:   bufio.NewReader(strings.NewReader(tc.input)),
				opts: tc.opts,
			}

			h := []Field{}
			err := d.decodeHeaders(&h)
			if tc.wantErr != nil {
				s.ErrorIs(err, tc.wantErr)
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
		Headers: []Field{
			{[]byte("Host"), []byte("example.com")},
			{[]byte("Content-Type"), []byte("application/x-www-form-urlencoded")},
			{[]byte("Content-Length"), []byte("13")},
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
	testcases := []struct {
		desc     string
		input    []byte
		opts     DecodeOptions
		expected requestLine
		wantErr  error
	}{
		{
			desc: "example",
			input: []byte("" +
				"\r\n" + // leading empty lines.
				"\r\n" +
				"GET /abc HTTP/1.1\r\n",
			),
			expected: requestLine{
				Method:  "GET",
				Target:  "/abc",
				Version: Version{1, 1},
			},
		},
		{
			desc: "malformed request line",
			input: []byte("" +
				"GET  /abc HTTP/1.1\r\n",
			),
			wantErr: ErrMalformedRequestLine,
		},
		{
			desc: "length limit exceeded",
			input: []byte("" +
				"GETTTTTTTTTTTTTTTTTTTTTTTTTT /abc HTTP/1.1\r\n",
			),
			opts:    DecodeOptions{MaxRequestLineLength: 20},
			wantErr: ErrRequestLineTooLong,
		},
	}

	for _, tc := range testcases {
		s.Run(tc.desc, func() {
			rd := NewRequestDecoder(bytes.NewReader(tc.input), tc.opts)

			var reqLine requestLine
			err := rd.decodeRequestLine(&reqLine)
			if tc.wantErr != nil {
				s.ErrorIs(err, tc.wantErr)
				return
			}

			s.NoError(err)
			s.Equal(tc.expected, reqLine)
		})
	}

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
		Headers: []Field{
			{[]byte("Content-Type"), []byte("text/plain")},
			{[]byte("Content-Length"), []byte("13")},
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
	testcases := []struct {
		desc     string
		input    []byte
		opts     DecodeOptions
		expected statusLine
		wantErr  error
	}{
		{
			desc: "example",
			input: []byte("" +
				"\r\n" + // leading empty lines.
				"\r\n" +
				"HTTP/1.1 200 OK\r\n"),
			expected: statusLine{
				Version:      Version{1, 1},
				StatusCode:   200,
				ReasonPhrase: "OK",
			},
		},
		{
			desc: "malformed status line",
			input: []byte("" +
				"HTTP/1.1 2000 Not OK\r\n",
			),
			wantErr: ErrMalformedStatusLine,
		},
		{
			desc: "length limit exceeded",
			input: []byte("" +
				"HTTP/1.1 200 Nottttttttttt OK\r\n",
			),
			opts:    DecodeOptions{MaxStatusLineLength: 20},
			wantErr: ErrStatusLineTooLong,
		},
	}

	for _, tc := range testcases {
		s.Run(tc.desc, func() {
			rd := NewResponseDecoder(bytes.NewReader(tc.input), tc.opts)

			var statLine statusLine
			err := rd.decodeStatusLine(&statLine)
			if tc.wantErr != nil {
				s.ErrorIs(err, tc.wantErr)
				return
			}

			s.NoError(err)
			s.Equal(tc.expected, statLine)
		})
	}
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

package http

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

type MessageEncoderTestSuite struct {
	suite.Suite
}

func TestMessageEncoderTestSuite(t *testing.T) {
	suite.Run(t, new(MessageEncoderTestSuite))
}

func (s *MessageEncoderTestSuite) TestWriteLine() {
	testcases := []struct {
		desc     string
		input    []byte
		opts     EncodeOptions
		expected string
		wantErr  bool
	}{
		{
			desc:     "simple line with CRLF",
			input:    []byte("Hello"),
			expected: "Hello\r\n",
		},
		{
			desc:     "simple line with LF",
			input:    []byte("Hello"),
			opts:     EncodeOptions{UseSoleLF: true},
			expected: "Hello\n",
		},
	}

	for _, tc := range testcases {
		s.Run(tc.desc, func() {
			var buf bytes.Buffer
			me := MessageEncoder{
				bw:   bufio.NewWriter(&buf),
				opts: tc.opts,
			}

			err := me.writeLine(tc.input)
			if tc.wantErr {
				s.Error(err)
				return
			}

			s.NoError(err)
			s.NoError(me.bw.Flush())

			s.Equal(tc.expected, buf.String())
		})
	}
}

func (s *MessageEncoderTestSuite) TestEncodeHeaders() {
	testcases := []struct {
		desc     string
		headers  Headers
		opts     EncodeOptions
		expected string
		wantErr  bool
	}{
		{
			desc: "simple headers with CRLF",
			headers: Headers{
				{"Host", "example.com"},
			},
			expected: "" +
				"Host: example.com\r\n" +
				"\r\n",
		},
		{
			desc:     "empty headers",
			headers:  Headers{},
			expected: "\r\n",
		},
	}

	for _, tc := range testcases {
		s.Run(tc.desc, func() {
			var buf bytes.Buffer
			me := MessageEncoder{
				bw:   bufio.NewWriter(&buf),
				opts: tc.opts,
			}

			err := me.encodeHeaders(tc.headers)
			if tc.wantErr {
				s.Error(err)
				return
			}

			s.NoError(err)
			s.NoError(me.bw.Flush())

			s.Equal(tc.expected, buf.String())
		})
	}
}

type RequestEncoderTestSuite struct {
	suite.Suite
}

func TestRequestEncoderTestSuite(t *testing.T) {
	suite.Run(t, new(RequestEncoderTestSuite))
}

func (s *RequestEncoderTestSuite) TestEncode() {
	body := "field1=value1"

	input := Request{
		requestLine: requestLine{
			Method:  "POST",
			Target:  "/example",
			Version: Version{1, 1},
		},
		Headers: Headers{
			{"Host", "example.com"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}

	expected := "" +
		"POST /example HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"\r\n" +
		body

	buf := bytes.NewBuffer(nil)
	re := NewRequestEncoder(buf, DefaultEncodeOptions)

	s.NoError(re.Encode(input))

	s.Equal(expected, buf.String())
}

func (s *RequestEncoderTestSuite) TestEncodeRequestLine() {
	input := requestLine{
		Method:  "GET",
		Target:  "/example",
		Version: Version{1, 1},
	}

	expected := "GET /example HTTP/1.1\r\n"

	buf := bytes.NewBuffer(nil)
	re := NewRequestEncoder(buf, DefaultEncodeOptions)

	s.NoError(re.encodeRequestLine(input))
	s.NoError(re.bw.Flush())

	s.Equal(expected, buf.String())
}

type ResponseEncoderTestSuite struct {
	suite.Suite
}

func TestResponseEncoderTestSuite(t *testing.T) {
	suite.Run(t, new(ResponseEncoderTestSuite))
}

func (s *ResponseEncoderTestSuite) TestEncode() {
	body := "field1=value1"

	input := Response{
		statusLine: statusLine{
			Version:      Version{1, 1},
			StatusCode:   200,
			ReasonPhrase: "OK",
		},
		Headers: Headers{
			{"Host", "example.com"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}

	expected := "" +
		"HTTP/1.1 200 OK\r\n" +
		"Host: example.com\r\n" +
		"\r\n" +
		body

	buf := bytes.NewBuffer(nil)
	re := NewResponseEncoder(buf, DefaultEncodeOptions)

	s.NoError(re.Encode(input))

	s.Equal(expected, buf.String())
}

func (s *ResponseEncoderTestSuite) TestEncodeStatusLine() {
	input := statusLine{
		Version:      Version{1, 1},
		StatusCode:   200,
		ReasonPhrase: "OK",
	}

	expected := "HTTP/1.1 200 OK\r\n"

	buf := bytes.NewBuffer(nil)
	re := NewResponseEncoder(buf, DefaultEncodeOptions)

	s.NoError(re.encodeStatusLine(input))
	s.NoError(re.bw.Flush())

	s.Equal(expected, buf.String())
}

package transfer

import (
	"bytes"
	"io"
	"network-stack/application/http"
	iolib "network-stack/lib/io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type ChunkedReaderTestSuite struct {
	suite.Suite
}

func TestChunkedReaderTestSuite(t *testing.T) {
	suite.Run(t, new(ChunkedReaderTestSuite))
}

func (s *ChunkedReaderTestSuite) TestRead() {
	input := []byte("" +
		"5;ext=foo\r\n" +
		"ABCDE\r\n" +
		"a\r\n" +
		"FGHIJKLNMO\r\n" +
		"0\r\n" + // last chunk
		"Hello: World\r\n" + // trailer
		"\r\n", // empty trailer (last trailer)
	)

	trailers := make([]http.Field, 0)
	cr := NewChunkedCoder().NewReader(bytes.NewReader(input)).(*ChunkedReader)
	cr.SetOnTrailerReceived(func(f []http.Field) { trailers = f })

	buf := make([]byte, 2)
	// First read reads only AB
	n, err := cr.Read(buf)
	s.Require().NoError(err)
	s.Equal(len(buf), n)
	s.Equal([]byte("AB"), buf)

	buf = make([]byte, 10)
	// Second read reads all the data in first chunk.
	n, err = cr.Read(buf)
	s.Require().NoError(err)
	s.Equal(3, n)
	s.Equal([]byte("CDE"), buf[:n])

	// Third read reads all the data in second chunk.
	n, err = cr.Read(buf)
	s.Require().NoError(err)
	s.Equal(len(buf), n)
	s.Equal([]byte("FGHIJKLNMO"), buf)

	// Fourth read reads last chunk.
	n, err = cr.Read(buf)
	s.Require().ErrorIs(err, io.EOF)
	s.Equal(0, n)

	s.Len(trailers, 1)
	expected := http.Field{Name: []byte("Hello"), Value: []byte("World")}
	s.Equal(expected, trailers[0])
}

func (s *ChunkedReaderTestSuite) TestDecodeChunk() {
	testcases := []struct {
		desc     string
		input    []byte
		expected Chunk
		wantErr  bool
	}{
		{
			desc: "example chunk",
			input: []byte(
				"5;ext=foo\r\n" +
					"ABCDE\r\n",
			),
			expected: Chunk{
				Size: 5,
				Extensions: [][2]string{
					{"ext", "foo"},
				},
			},
		},
		{
			desc: "BWS inside chunk",
			input: []byte(
				"5 ; ext = foo\r\n" +
					"ABCDE\r\n",
			),
			expected: Chunk{
				Size: 5,
				Extensions: [][2]string{
					{"ext", "foo"},
				},
			},
		},
		{
			desc:    "malformed chunk (empty)",
			input:   []byte("\r\n"),
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		s.Run(tc.desc, func() {
			cr := NewChunkedCoder().NewReader(bytes.NewReader(tc.input)).(*ChunkedReader)

			err := cr.decodeChunk()
			if tc.wantErr {
				s.Error(err)
				return
			}

			s.NoError(err)

			data, err := io.ReadAll(cr.chunk.data)
			s.NoError(err)

			cr.chunk.data = nil

			s.Equal(tc.expected, *cr.chunk)
			s.Len(data, int(cr.chunk.Size)+2) // ignore crlf
		})
	}
}

func TestDecodeChunkSize(t *testing.T) {
	testcases := []struct {
		desc     string
		input    []byte
		expected uint
		wantErr  bool
	}{
		{
			desc:     "normal hex",
			input:    []byte("FF"),
			expected: 0xFF,
		},
		{
			desc:    "invalid hex",
			input:   []byte("haha this aint hex"),
			wantErr: true,
		},
		{
			desc:    "hex too long",
			input:   []byte("FFFFFFFFFFFFFFFFFF"), // 9 bytes
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			size, err := decodeChunkSize(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, size)
		})
	}
}

func (s *ChunkedReaderTestSuite) TestDecodeTrailers() {
	r := strings.NewReader(
		"" +
			"Hello: World\r\n" +
			"Foo: Bar\r\n" +
			"\r\n",
	)
	expected := []http.Field{
		{Name: []byte("Hello"), Value: []byte("World")},
		{Name: []byte("Foo"), Value: []byte("Bar")},
	}

	store := make([]http.Field, 0)
	cr := NewChunkedCoder().NewReader(r).(*ChunkedReader)
	cr.SetOnTrailerReceived(func(f []http.Field) { store = f })

	s.NoError(cr.decodeTrailers())
	s.Equal(expected, store)
}

type ChunkedWriterTestSuite struct {
	suite.Suite
}

func TestChunkedWriterTestSuite(t *testing.T) {
	suite.Run(t, new(ChunkedWriterTestSuite))
}

func (s *ChunkedWriterTestSuite) TestWrite() {
	buf := bytes.NewBuffer(nil)

	cw := NewChunkedCoder().NewWriter(&stubWriteCloser{buf: buf}).(*ChunkedWriter)

	// Empty write is ignored
	n, err := cw.Write(nil)
	s.Require().NoError(err)
	s.Require().Zero(n)
	s.Require().Empty(buf.Bytes())

	cw.SetExtensions([][2]string{{"foo", "bar"}})
	p := []byte("ABC")

	expected := []byte("" +
		"3;foo=bar\r\n" +
		"ABC\r\n",
	)

	n, err = cw.Write(p)
	s.Require().NoError(err)
	s.Equal(len(p), n)
	s.Equal(expected, buf.Bytes())
}

func (s *ChunkedWriterTestSuite) TestClose() {
	trailers := []http.Field{{Name: []byte("foo"), Value: []byte("bar")}}
	buf := bytes.NewBuffer(nil)

	cw := NewChunkedCoder().NewWriter(&stubWriteCloser{buf: buf}).(*ChunkedWriter)
	cw.SetSendTrailers(func() []http.Field { return trailers })

	cw.SetExtensions([][2]string{{"foo", "bar"}})
	expected := []byte("" +
		"0;foo=bar\r\n" +
		"foo: bar\r\n" +
		"\r\n",
	)

	err := cw.Close()
	s.Require().NoError(err)
	s.Equal(expected, buf.Bytes())
}

func (s *ChunkedWriterTestSuite) TestEncodeChunk() {
	chunk := Chunk{
		Size: 0xF,
		Extensions: [][2]string{
			{"foo", "bar"},
		},
		data: bytes.NewBuffer([]byte("123456789ABCDEF")),
	}

	expected := []byte("" +
		"f;foo=bar\r\n" +
		"123456789ABCDEF\r\n",
	)

	buf := bytes.NewBuffer(nil)

	cw := NewChunkedCoder().NewWriter(&stubWriteCloser{buf: buf}).(*ChunkedWriter)

	_, err := cw.encodeChunk(chunk)
	s.Require().NoError(err)

	s.Equal(expected, buf.Bytes())
}

func (s *ChunkedWriterTestSuite) TestEncodeChunkLast() {
	chunk := Chunk{
		Size: 0,
		Extensions: [][2]string{
			{"foo", "bar"},
		},
	}

	expected := []byte("0;foo=bar\r\n")

	buf := bytes.NewBuffer(nil)

	cw := NewChunkedCoder().NewWriter(&stubWriteCloser{buf: buf}).(*ChunkedWriter)

	_, err := cw.encodeChunk(chunk)
	s.Require().NoError(err)

	s.Equal(expected, buf.Bytes())
}

func (s *ChunkedWriterTestSuite) TestEncodeTrailers() {
	trailers := []http.Field{
		{Name: []byte("Foo"), Value: []byte("Bar")},
	}

	expected := []byte("" +
		"Foo: Bar\r\n" +
		"\r\n",
	)

	buf := bytes.NewBuffer(nil)

	cw := NewChunkedCoder().NewWriter(&stubWriteCloser{buf: buf}).(*ChunkedWriter)
	cw.SetSendTrailers(func() []http.Field { return trailers })

	s.Require().NoError(cw.encodeTrailers())
	s.Equal(expected, buf.Bytes())
}

func (s *ChunkedWriterTestSuite) TestEncodeTrailersNil() {
	expected := []byte("\r\n")

	buf := bytes.NewBuffer(nil)

	cw := NewChunkedCoder().NewWriter(&stubWriteCloser{buf: buf}).(*ChunkedWriter)

	s.Require().NoError(cw.encodeTrailers())
	s.Equal(expected, buf.Bytes())
}

func TestReadLine(t *testing.T) {
	line := []byte("hello\r\n")
	result, err := readLine(iolib.NewUntilReader(bytes.NewReader(line)))
	assert.NoError(t, err)
	assert.Equal(t, []byte("hello"), result)
}

func TestWriteLine(t *testing.T) {
	line := []byte("hello")

	buf := bytes.NewBuffer(nil)
	err := writeLine(buf, line)
	assert.NoError(t, err)

	assert.Equal(t, []byte("hello\r\n"), buf.Bytes())
}

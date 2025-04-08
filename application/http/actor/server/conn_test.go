package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"network-stack/application/http"
	"network-stack/application/http/semantic"
	"network-stack/application/http/semantic/status"
	"network-stack/application/http/transfer"
	"network-stack/application/util/uri"
	iolib "network-stack/lib/io"
	"network-stack/transport"
	"network-stack/transport/pipe"
	"sync"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ServeTestSuite struct {
	suite.Suite

	ctx              context.Context
	tConn, otherConn transport.Conn
	version          http.Version

	conn *conn

	clock *clock.Mock

	defaultRequest  semantic.Request
	defaultResponse semantic.Response
	defaultHandle   HandleFunc
}

func TestServeTestSuite(t *testing.T) {
	suite.Run(t, new(ServeTestSuite))
}

func (s *ServeTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.clock = clock.NewMock()

	s.tConn, s.otherConn = pipe.NewPair("a", "b", s.clock)

	s.version = http.Version{1, 1}
	s.defaultRequest = semantic.Request{
		Method: semantic.MethodGet,
		URI:    uri.URI{Path: "/"},
		Message: semantic.Message{
			Version: s.version,
			Body:    bytes.NewReader(nil),
		},
	}
	s.defaultResponse = semantic.Response{
		Message: semantic.Message{Version: s.version},
		Status:  status.OK,
		Date:    s.clock.Now(),
	}
	s.defaultHandle = func(c *HandleContext, request *semantic.Request) *semantic.Response {
		copy := s.defaultResponse
		return &copy
	}

	s.conn = &conn{
		con:      s.tConn,
		r:        iolib.NewUntilReader(s.tConn),
		w:        s.tConn,
		version:  s.version,
		clock:    s.clock,
		handle:   s.defaultHandle,
		transfer: transfer.NewCodingApplier(nil),
	}

}

func (s *ServeTestSuite) TestServeOnce() {
	timeout := 10 * time.Millisecond

	go func() {
		defer s.clock.Add(timeout)
		res, err := sendRequest(s.otherConn, s.defaultRequest.RawRequest())
		s.Require().NoError(err)

		expected := s.defaultResponse
		expected.EnsureHeadersSet()

		res.Body, expected.Body = nil, nil
		s.Require().Equal(res, expected.RawResponse())

	}()

	s.conn.opts.Serve.Timeout.IdleTimeout = timeout

	alt, err := s.conn.serve(s.ctx)
	s.ErrorIs(err, ErrIdleTimeoutExceeded)
	s.Nil(alt)
}

func (s *ServeTestSuite) TestServeConsecutive() {
	timeout := 10 * time.Millisecond

	go func() {
		defer s.clock.Add(timeout)
		for range 3 {
			res, err := sendRequest(s.otherConn, s.defaultRequest.RawRequest())
			s.Require().NoError(err)

			expected := s.defaultResponse
			expected.EnsureHeadersSet()

			res.Body, expected.Body = nil, nil
			s.Require().Equal(res, expected.RawResponse())
		}
	}()

	s.conn.opts.Serve.Timeout.IdleTimeout = timeout

	alt, err := s.conn.serve(s.ctx)
	s.ErrorIs(err, ErrIdleTimeoutExceeded)
	s.Nil(alt)
}

func (s *ServeTestSuite) TestServeGracefulClose() {
	s.conn.handle = func(c *HandleContext, request *semantic.Request) *semantic.Response {
		res := s.defaultHandle(c, request)

		// This cannot be done outside of this package.
		c.closeConn = true

		return res
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		res, err := sendRequest(s.otherConn, s.defaultRequest.RawRequest())
		s.Require().NoError(err)

		expected := s.defaultResponse
		expected.EnsureHeadersSet()
		expected.Headers.Set("Connection", "close")

		res.Body, expected.Body = nil, nil

		got, err := semantic.ResponseFrom(res, semantic.ParseResponseOptions{})
		s.Require().NoError(err)

		s.Require().Equal(expected, got)
	}()

	alt, err := s.conn.serve(s.ctx)
	s.NoError(err)
	s.Nil(alt)
	wg.Wait()
}

func (s *ServeTestSuite) TestServeForceClose() {
	s.conn.handle = func(c *HandleContext, request *semantic.Request) *semantic.Response {
		// This cannot be done outside of this package.
		c.closeConn = true
		return nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		res, err := sendRequest(s.otherConn, s.defaultRequest.RawRequest())
		s.Require().ErrorIs(err, transport.ErrConnClosed)
		s.Zero(res)
	}()

	alt, err := s.conn.serve(s.ctx)
	s.NoError(err)
	s.Nil(alt)

	s.conn.con.Close()
	wg.Wait()
}

func (s *ServeTestSuite) TestInvalidRequest() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Write invalid request.
		_, err := s.otherConn.Write([]byte("GET / HTTP/1.X\r\n"))
		s.Require().NoError(err)

		// Read response.
		var rawRes http.Response
		dec := http.NewResponseDecoder(iolib.NewUntilReader(s.otherConn), http.DecodeOptions{})
		s.Require().NoError(dec.Decode(&rawRes))

		response, err := semantic.ResponseFrom(rawRes, semantic.ParseResponseOptions{})
		s.Require().NoError(err)

		expected := semantic.Response{
			Status: status.BadRequest,
			Date:   s.clock.Now(),
			Message: semantic.Message{
				Version: s.version,
			},
		}
		expected.EnsureHeadersSet()

		// cannot compare those
		expected.Body = nil
		response.Body = nil

		s.Equal(expected, response)
	}()

	alt, err := s.conn.serve(s.ctx)
	s.NoError(err)
	s.Nil(alt)

	wg.Wait()
}

func (s *ServeTestSuite) TestConnClosedOnReading() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Write invalid request.
		_, err := s.otherConn.Write([]byte("GET"))
		s.Require().NoError(err)

		s.Require().NoError(s.otherConn.Close())
	}()

	alt, err := s.conn.serve(s.ctx)
	s.ErrorIs(err, transport.ErrConnClosed)
	s.Nil(alt)

	wg.Wait()
}

func (s *ServeTestSuite) TestConnClosedOnWriting() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		enc := http.NewRequestEncoder(s.otherConn, http.EncodeOptions{})
		s.Require().NoError(enc.Encode(s.defaultRequest.RawRequest()))

		s.Require().NoError(s.otherConn.Close())
	}()

	alt, err := s.conn.serve(s.ctx)
	s.ErrorIs(err, transport.ErrConnClosed)
	s.Nil(alt)

	wg.Wait()
}

func sendRequest(conn transport.Conn, request http.Request) (res http.Response, err error) {
	enc := http.NewRequestEncoder(conn, http.EncodeOptions{})
	dec := http.NewResponseDecoder(iolib.NewUntilReader(conn), http.DecodeOptions{})

	if err := enc.Encode(request); err != nil {
		return http.Response{}, err
	}

	if err := dec.Decode(&res); err != nil {
		return http.Response{}, err
	}
	return res, nil
}

type WaitForRequestTestSuite struct {
	suite.Suite

	clock *clock.Mock

	ctx      context.Context
	dst, src transport.Conn

	conn *conn
}

func TestWaitForRequestTestSuite(t *testing.T) {
	suite.Run(t, new(WaitForRequestTestSuite))
}

func (s *WaitForRequestTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.clock = clock.NewMock()
	s.dst, s.src = pipe.NewPair("a", "b", s.clock)

	s.conn = &conn{con: s.dst, clock: s.clock}
}

func (s *WaitForRequestTestSuite) TearDownTest() {
	s.Require().NoError(s.dst.Close())
}

func (s *WaitForRequestTestSuite) TestRead() {
	content := []byte("hey")
	go func() {
		_, err := s.src.Write(content)
		s.Require().NoError(err)
		s.Require().NoError(s.src.Close())
	}()

	s.NoError(s.conn.waitForRequest(s.ctx))

	b, err := io.ReadAll(s.dst)
	s.ErrorIs(err, transport.ErrConnClosed) // As other connection will close immidiately.

	// Check if no bytes are missing.
	s.Equal(content, b)
}

func (s *WaitForRequestTestSuite) TestContextCancel() {
	ctx, cancel := context.WithCancel(s.ctx)
	cancel()

	err := s.conn.waitForRequest(ctx)
	s.ErrorIs(err, context.Canceled)
}

func (s *WaitForRequestTestSuite) TestTimeout() {
	s.conn.opts.Serve.Timeout.IdleTimeout = time.Millisecond
	go func() {
		// Wait for code execution halting.
		time.Sleep(10 * time.Millisecond)

		s.clock.Add(time.Hour)
	}()

	err := s.conn.waitForRequest(s.ctx)
	s.ErrorIs(err, ErrIdleTimeoutExceeded)
}

type ReadRequestTestSuite struct {
	suite.Suite

	defaultRequest semantic.Request
	dst, src       transport.Conn

	conn *conn

	dec *http.RequestDecoder

	clock *clock.Mock
}

func TestReadRequestTestSuite(t *testing.T) {
	suite.Run(t, new(ReadRequestTestSuite))
}

func (s *ReadRequestTestSuite) SetupTest() {
	s.clock = clock.NewMock()

	s.dst, s.src = pipe.NewPair("a", "b", s.clock)

	s.conn = &conn{
		con:      s.dst,
		r:        iolib.NewUntilReader(s.dst),
		transfer: transfer.NewCodingApplier(nil),
		clock:    s.clock,
		// below are not used.
		version: http.Version{},
		w:       nil,
		handle:  nil,
		logger:  nil,
	}
	s.dec = http.NewRequestDecoder(s.conn.r, http.DecodeOptions{})

	s.defaultRequest = semantic.Request{
		Method: semantic.MethodGet,
		URI:    uri.URI{Path: "/"},
		Host:   "example.com",
		Message: semantic.Message{
			Version: http.Version{1, 1},
			Headers: semantic.NewHeaders(nil),
			Body:    bytes.NewReader(nil),
		},
	}

}

func (s *ReadRequestTestSuite) TestReadRequest() {
	done := s.startWritingRequest(s.defaultRequest)

	request, err := s.conn.readRequest(s.dec)
	s.Require().NoError(err)
	s.Require().NoError(s.dst.Close())
	<-done

	expected := s.defaultRequest.RawRequest()
	got := request.RawRequest()

	// Cannot compare these
	expected.Body = nil
	got.Body = nil

	s.Equal(expected, got)
}

func (s *ReadRequestTestSuite) TestReadRequestContentLength() {
	l := uint(5)

	expected := s.defaultRequest
	expected.ContentLength = &l

	done := s.startWritingRequest(expected)

	request, err := s.conn.readRequest(s.dec)
	s.Require().NoError(err)
	s.Require().NoError(s.dst.Close())
	<-done

	expected.EnsureHeadersSet()

	// Cannot compare these
	s.IsType(&iolib.LimitedReader{}, request.Body)
	expected.Body = nil
	request.Body = nil

	s.Equal(&expected, request)
}

func (s *ReadRequestTestSuite) TestReadTimeout() {
	s.conn.opts.Serve.Timeout.ReadTimeout = time.Millisecond
	go func() {
		_, err := s.src.Write([]byte("HTTP"))
		s.Require().NoError(err)
		// Add after writing is started
		s.clock.Add(time.Hour)
	}()

	_, err := s.conn.readRequest(s.dec)
	s.ErrorIs(err, transport.ErrDeadLineExceeded)
}

func (s *ReadRequestTestSuite) startWritingRequest(request semantic.Request) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		request.EnsureHeadersSet()

		raw := request.RawRequest()
		e := http.NewRequestEncoder(s.src, http.EncodeOptions{})
		s.Require().NoError(e.Encode(raw))
		close(done)
	}()
	return done
}

type WriteResponseTestSuite struct {
	suite.Suite

	response  *semantic.Response
	outputBuf *bytes.Buffer
	src, dst  transport.Conn

	conn *conn

	enc *http.ResponseEncoder

	clock *clock.Mock
}

func TestWriteResponseTestSuite(t *testing.T) {
	suite.Run(t, new(WriteResponseTestSuite))
}

func (s *WriteResponseTestSuite) SetupTest() {
	s.clock = clock.NewMock()

	s.outputBuf = bytes.NewBuffer(nil)
	s.src, s.dst = pipe.NewPair("a", "b", s.clock)

	s.conn = &conn{
		con:      s.src,
		w:        s.src,
		transfer: transfer.NewCodingApplier(nil),
		clock:    s.clock,
		// below are not used.
		r:       nil,
		version: http.Version{},
		handle:  nil,
		logger:  nil,
		opts:    Options{},
	}
	s.enc = http.NewResponseEncoder(s.conn.w, http.EncodeOptions{})

	s.response = &semantic.Response{
		Status: status.OK,
		Message: semantic.Message{
			Version: http.Version{1, 1},
			Body:    bytes.NewReader(nil),
			Headers: semantic.NewHeaders(nil),
		},
	}

}

func (s *WriteResponseTestSuite) TestWriteResponse() {
	done := s.startReadingResponse()

	d := http.NewResponseDecoder(iolib.NewUntilReader(s.outputBuf), http.DecodeOptions{})

	err := s.conn.writeResponse(s.response, s.enc)
	s.Require().NoError(err)
	s.Require().NoError(s.src.Close())
	<-done

	expected := s.response.RawResponse()
	var got http.Response
	s.Require().NoError(d.Decode(&got))

	// Cannot compare these.
	expected.Body = nil
	got.Body = nil

	s.Equal(expected, got)
}

func (s *WriteResponseTestSuite) TestWriteTimeout() {
	s.conn.opts.Serve.Timeout.WriteTimeout = time.Millisecond
	go func() {
		_, err := s.dst.Read(nil)
		s.Require().NoError(err)
		// Add after writing is started
		s.clock.Add(time.Hour)
	}()
	err := s.conn.writeResponse(s.response, s.enc)
	s.ErrorIs(err, transport.ErrDeadLineExceeded)
}

func (s *WriteResponseTestSuite) startReadingResponse() <-chan struct{} {
	done := make(chan struct{})
	go func() {
		_, err := s.outputBuf.ReadFrom(s.dst)
		if err != nil && err != transport.ErrConnClosed {
			s.FailNow("unexpected error", err)
		}
		close(done)
	}()
	return done
}

func TestToStatusError(t *testing.T) {
	testcases := []struct {
		input     error
		expected  status.Status
		wantCause bool
	}{
		{
			input:     errors.New("some decoding error"),
			expected:  status.BadRequest,
			wantCause: true,
		},
		{
			input:     transport.ErrDeadLineExceeded,
			expected:  status.RequestTimeout,
			wantCause: false,
		},
		{
			input:     semantic.ErrURITooLong,
			expected:  status.RequestURITooLong,
			wantCause: true,
		},
		{
			input:     semantic.ErrContentTooBig,
			expected:  status.ContentTooLarge,
			wantCause: true,
		},
		{
			input:     transfer.ErrUnsupportedCoding,
			expected:  status.NotImplemented,
			wantCause: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.input.Error(), func(t *testing.T) {
			serr := toStatusError(tc.input)
			assert.Equal(t, tc.expected, serr.Status)
			if tc.wantCause {
				assert.Equal(t, tc.input, serr.Cause())
			}
		})
	}
}

func TestStatusErrToResponse(t *testing.T) {
	cause := errors.New("this is cause")

	testcases := []struct {
		desc     string
		input    status.Error
		wantBody bool
	}{
		{
			desc:     "example",
			input:    status.NewError(cause, status.BadRequest),
			wantBody: true,
		},
		{
			desc:     "want body but no cause",
			input:    status.NewError(nil, status.BadRequest),
			wantBody: true,
		},
		{
			desc:     "want no body",
			input:    status.NewError(cause, status.BadRequest),
			wantBody: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			response := statusErrToResponse(tc.input, !tc.wantBody)
			assert.Equal(t, tc.input.Status, response.Status)
			if tc.wantBody {
				if tc.input.Cause() != nil {
					b, err := io.ReadAll(response.Body)
					require.NoError(t, err)
					assert.Equal(t, tc.input.Cause().Error(), string(b))
				} else {
					assert.Nil(t, response.Body)
				}
			}
		})
	}
}

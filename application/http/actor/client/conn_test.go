package client

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
	"network-stack/lib/ds/queue"
	iolib "network-stack/lib/io"
	"network-stack/lib/types/pointer"
	"network-stack/transport"
	"network-stack/transport/pipe"
	"sync"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/suite"
)

type ConnTestSuite struct {
	suite.Suite

	ctx              context.Context
	tConn, otherConn transport.Conn

	version  http.Version
	maxSeats uint

	conn     *conn
	writeBuf *bytes.Buffer

	clock *clock.Mock

	defaultRequest  semantic.Request
	defaultResponse semantic.Response
}

func TestConnTestSuite(t *testing.T) {
	suite.Run(t, new(ConnTestSuite))
}

func (s *ConnTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.clock = clock.NewMock()
	s.tConn, s.otherConn = pipe.NewPair("a", "b", s.clock)

	s.version = http.Version{1, 1}
	s.maxSeats = 2

	s.defaultRequest = semantic.Request{
		Method: semantic.MethodGet,
		URI:    uri.URI{Path: "/"},
		Message: semantic.Message{
			Version: s.version,
			Body:    bytes.NewReader(nil),
		},
	}
	s.defaultResponse = semantic.Response{
		Message: semantic.Message{
			Version:       s.version,
			Body:          bytes.NewReader(nil),
			ContentLength: pointer.To(uint(0)),
		},
		Status: status.OK,
		Date:   s.clock.Now(),
	}
	s.defaultResponse.EnsureHeadersSet()

	s.writeBuf = bytes.NewBuffer(nil)
	s.conn = &conn{
		con:       s.tConn,
		r:         iolib.NewUntilReader(s.tConn),
		w:         s.tConn,
		clock:     s.clock,
		transfer:  transfer.NewCodingApplier(nil),
		ongoings:  queue.NewCircular[*roundtripSession](s.maxSeats),
		writePipe: make(chan *roundtripSession),
		mu:        sync.Mutex{},
		opts:      Options{},

		maxSeats: s.maxSeats,
		seats:    0,
		closing:  false,
		idleAt:   time.Time{},

		// Below are metadata that we don't need in these tests.
		version:  s.version,
		addr:     nil,
		pipeline: false,
		logger:   nil,
		isAlt:    false,
	}
}

func (s *ConnTestSuite) TestIdleTimeoutExceeded() {
	s.False(s.conn.idleTimeoutExceeded(0)) // it is not idle.

	s.conn.idleAt = s.clock.Now()
	timeout := 3 * time.Second
	s.clock.Add(timeout) // advance timer.

	s.True(s.conn.idleTimeoutExceeded(timeout))
}

func (s *ConnTestSuite) TestWriteRequest() {
	done := s.startReadingRequest()

	d := http.NewRequestDecoder(iolib.NewUntilReader(s.writeBuf), http.DecodeOptions{})
	e := http.NewRequestEncoder(s.conn.w, http.EncodeOptions{})

	err := s.conn.writeRequest(&s.defaultRequest, e)
	s.Require().NoError(err)
	s.Require().NoError(s.tConn.Close())
	<-done

	expected := s.defaultRequest.RawRequest()
	var got http.Request
	s.Require().NoError(d.Decode(&got))

	// Cannot compare these.
	expected.Body = nil
	got.Body = nil

	s.Equal(expected, got)
}

func (s *ConnTestSuite) startReadingRequest() <-chan struct{} {
	done := make(chan struct{})
	go func() {
		_, err := s.writeBuf.ReadFrom(s.otherConn)
		if err != nil && err != transport.ErrConnClosed {
			s.FailNow("unexpected error", err)
		}
		close(done)
	}()
	return done
}

func (s *ConnTestSuite) TestReadResponse() {
	done := s.startWritingResponse(s.defaultResponse, 1)

	d := http.NewResponseDecoder(iolib.NewUntilReader(s.conn.con), http.DecodeOptions{})

	response, err := s.conn.readResponse(d)
	s.Require().NoError(err)
	s.Require().NoError(s.tConn.Close())
	<-done

	expected, got := s.defaultResponse, response

	// Cannot compare these
	expected.Body = nil
	got.Body = nil

	s.Equal(&expected, got)
}

func (s *ConnTestSuite) startWritingResponse(response semantic.Response, n uint) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		response.EnsureHeadersSet()
		e := http.NewResponseEncoder(s.otherConn, http.EncodeOptions{})
		raw := response.RawResponse()

		for range n {
			s.Require().NoError(e.Encode(raw))
		}

		close(done)
	}()
	return done
}

func (s *ConnTestSuite) TestReadLoop() {
	s.conn.seats = s.maxSeats

	done := s.startWritingResponse(s.defaultResponse, s.conn.seats)
	var wg sync.WaitGroup
	defer wg.Wait()

	session := &roundtripSession{
		req:        &semantic.Request{},
		responseTo: make(chan *semantic.Response),
		errTo:      make(chan error),
		callerQuit: make(chan struct{}),
	}

	for range s.conn.seats {
		s.conn.ongoings.Enqueue(session)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.conn.readLoop()
	}()

	for range s.conn.seats {
		select {
		case response := <-session.responseTo:
			body := response.Body
			response.Body, s.defaultResponse.Body = nil, nil

			s.Equal(&s.defaultResponse, response)

			_, err := io.ReadAll(body)
			s.NoError(err)

		case err := <-session.errTo:
			s.FailNow("unexpected error", err)
		}
	}
	<-done
	s.Require().NoError(s.conn.con.Close())
}

func (s *ConnTestSuite) TestWriteLoop() {
	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.conn.writeLoop()
	}()

	n := 3

	readingDone := make(chan struct{})
	go func() {
		var got http.Request
		d := http.NewRequestDecoder(iolib.NewUntilReader(s.otherConn), http.DecodeOptions{})

		expected := s.defaultRequest.Clone().RawRequest()

		for range n {
			s.Require().NoError(d.Decode(&got))

			expected.Body = nil
			got.Body = nil

			s.Equal(expected, got)
		}
		close(readingDone)
	}()

	errTo := make(chan error)
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case err := <-errTo:
			s.FailNow("unexpected error", err)
		case <-readingDone:
		}
	}()

	for range n {
		s.conn.writePipe <- &roundtripSession{
			req:   pointer.To(s.defaultRequest.Clone()),
			errTo: errTo,
		}
	}

	<-readingDone
	close(s.conn.writePipe)
}

func (s *ConnTestSuite) TestClose() {
	session := &roundtripSession{
		req:        &semantic.Request{},
		responseTo: make(chan *semantic.Response),
		errTo:      make(chan error),
		callerQuit: make(chan struct{}),
	}

	s.conn.ongoings.Enqueue(session)

	closeErr := errors.New("hey this is close error")

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case err := <-session.errTo:
			s.ErrorIs(err, closeErr)
		case <-session.responseTo:
			s.FailNow("how?")
		}
	}()

	s.conn.close(closeErr)

	s.True(s.conn.closing)
}

func (s *ConnTestSuite) TestCloseRace() {
	var wg sync.WaitGroup

	wg.Add(2)
	doClose := func() {
		defer wg.Done()
		s.conn.close(nil)
	}

	go doClose()
	go doClose()

	wg.Wait()

	s.True(s.conn.closing)
}

func (s *ConnTestSuite) TestRoundtrip() {
	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		dec := http.NewRequestDecoder(iolib.NewUntilReader(s.otherConn), http.DecodeOptions{})
		enc := http.NewResponseEncoder(s.otherConn, http.EncodeOptions{})

		var request http.Request
		s.Require().NoError(dec.Decode(&request))
		request.Body, s.defaultRequest.Body = nil, nil
		s.Require().Equal(s.defaultRequest.RawRequest(), request)

		s.NoError(enc.Encode(s.defaultResponse.RawResponse()))
	}()

	go s.conn.readLoop()
	go s.conn.writeLoop()

	response, err := s.conn.roundtrip(s.ctx, &s.defaultRequest)
	s.Require().NoError(err)
	body := response.Body
	response.Body, s.defaultResponse.Body = nil, nil
	s.Equal(&s.defaultResponse, response)

	_, err = io.ReadAll(body)
	s.Require().NoError(err)

	s.conn.close(nil)
	s.conn.actuallyClose()
}

func (s *ConnTestSuite) TestRoundtripContextCancel() {
	ctx, cancel := context.WithCancel(s.ctx)
	cancel()

	s.conn.writePipe = make(chan *roundtripSession, 1) // temp. so the procedure can move on.

	response, err := s.conn.roundtrip(ctx, &s.defaultRequest)
	s.Require().ErrorIs(err, context.Canceled)
	s.Nil(response)
}

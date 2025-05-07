package server

import (
	"bytes"
	"context"
	"math/rand"
	"network-stack/application/http"
	"network-stack/application/http/semantic"
	"network-stack/application/http/semantic/status"
	"network-stack/application/http/transfer"
	"network-stack/application/util/uri"
	iolib "network-stack/lib/io"
	"network-stack/lib/types/pointer"
	"network-stack/transport"
	"network-stack/transport/pipe"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/suite"
)

type ServePipelineTestSuite struct {
	suite.Suite

	pipeLen uint // 1 + bufLen

	ctx              context.Context
	tConn, otherConn transport.Conn
	version          http.Version

	conn *conn

	clock *clock.Mock

	defaultRequest  semantic.Request
	defaultResponse semantic.Response
	defaultHandle   HandleFunc
}

func TestServePipelineTestSuite(t *testing.T) {
	suite.Run(t, new(ServePipelineTestSuite))
}

func (s *ServePipelineTestSuite) SetupTest() {
	s.pipeLen = 3

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
		opts: Options{
			Serve: ServeOptions{
				SafeMethods: []semantic.Method{semantic.MethodGet},
			},
			Pipeline: PipelineOptions{
				BufferLength:  s.pipeLen - 1,
				ServeParallel: true,
			},
		},
	}
}

func (s *ServePipelineTestSuite) TestServePipelined() {
	timeout := 10 * time.Millisecond

	closed := make(chan struct{})
	go func() {
		defer func() {
			for {
				select {
				case <-closed:
					return
				default:
					s.clock.Add(timeout)
				}
			}
		}()
		enc := http.NewRequestEncoder(s.otherConn, http.EncodeOptions{})
		dec := http.NewResponseDecoder(iolib.NewUntilReader(s.otherConn), http.DecodeOptions{})

		for range s.pipeLen {
			s.Require().NoError(enc.Encode(s.defaultRequest.RawRequest()))
		}
		for range s.pipeLen {
			var raw http.Response
			s.Require().NoError(dec.Decode(&raw))

			expected := s.defaultResponse
			expected.EnsureHeadersSet()

			raw.Body, expected.Body = nil, nil
			s.Require().Equal(raw, expected.RawResponse())
		}
	}()

	s.conn.opts.Serve.Timeout.IdleTimeout = timeout

	alt, err := s.conn.servePipeine(s.ctx)
	s.ErrorIs(err, ErrIdleTimeoutExceeded)
	s.Nil(alt)
	close(closed)
}

func (s *ServePipelineTestSuite) TestInvalidRequestAfterValid() {
	// TODO: Flaky. should change the logic to properly use mutext on worker.
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()

		// Write valid request.
		enc := http.NewRequestEncoder(s.otherConn, http.EncodeOptions{})
		s.Require().NoError(enc.Encode(s.defaultRequest.RawRequest()))

		// Write invalid request.
		_, err := s.otherConn.Write([]byte("GET / HTTP/1.X\r\n"))
		s.Require().NoError(err)

		expected := []semantic.Response{
			s.defaultResponse,
			{
				Status: status.BadRequest,
				Date:   s.clock.Now(),
				Message: semantic.Message{
					Version: s.version,
				},
			},
		}
		// Read response.
		var rawRes http.Response
		dec := http.NewResponseDecoder(iolib.NewUntilReader(s.otherConn), http.DecodeOptions{})

		for _, expect := range expected {
			s.Require().NoError(dec.Decode(&rawRes))

			s.Require().NoError(err)

			expect.EnsureHeadersSet()
			rawRes.Body = nil

			s.Equal(expect.RawResponse(), rawRes)
		}

		// Check if the connection is closed.
		_, err = s.otherConn.Read(nil)
		s.ErrorIs(err, transport.ErrConnClosed)
	}()

	alt, err := s.conn.servePipeine(s.ctx)
	s.NoError(err)
	s.Nil(alt)
	s.NoError(s.tConn.Close())

	wg.Wait()
}

func (s *ServePipelineTestSuite) TestUnsafeMethod() {
	timeout := time.Millisecond

	s.conn.handle = func(c *HandleContext, request *semantic.Request) *semantic.Response {
		time.Sleep(50 * time.Millisecond)
		return s.defaultHandle(c, request)
	}

	closed := make(chan struct{})
	go func() {
		defer func() {
			for {
				select {
				case <-closed:
					return
				default:
					s.clock.Add(timeout)
				}
			}
		}()

		enc := http.NewRequestEncoder(s.otherConn, http.EncodeOptions{})
		dec := http.NewResponseDecoder(iolib.NewUntilReader(s.otherConn), http.DecodeOptions{})

		// Write safe request.
		s.Require().NoError(enc.Encode(s.defaultRequest.RawRequest()))

		// Write unsafe request.
		unsafe := s.defaultRequest
		unsafe.Method = semantic.MethodPost
		s.Require().NoError(enc.Encode(unsafe.RawRequest()))

		for range 2 {
			var raw http.Response
			s.Require().NoError(dec.Decode(&raw))

			expected := s.defaultResponse
			expected.EnsureHeadersSet()

			raw.Body, expected.Body = nil, nil
			s.Require().Equal(raw, expected.RawResponse())
		}
	}()

	s.conn.opts.Serve.Timeout.IdleTimeout = timeout

	alt, err := s.conn.servePipeine(s.ctx)
	s.ErrorIs(err, ErrIdleTimeoutExceeded)
	s.Nil(alt)
	close(closed)
}

type PipelineReceiverTestSuite struct {
	suite.Suite

	bufLen uint

	ctx      context.Context
	clock    *clock.Mock
	dst, src transport.Conn

	conn *conn

	defaultRequest semantic.Request

	receiver *pipelineReceiver
}

func TestPipelineReceiverTestSuite(t *testing.T) {
	suite.Run(t, new(PipelineReceiverTestSuite))
}

func (s *PipelineReceiverTestSuite) SetupTest() {
	s.bufLen = 1
	s.ctx = context.Background()
	s.clock = clock.NewMock()

	s.dst, s.src = pipe.NewPair("a", "b", s.clock)

	s.conn = &conn{
		con:      s.dst,
		r:        iolib.NewUntilReader(s.dst),
		clock:    s.clock,
		transfer: transfer.NewCodingApplier(nil),
	}

	s.defaultRequest = semantic.Request{
		Method: semantic.MethodGet,
		URI:    uri.URI{Path: "/"},
		Host:   "example.com",
		Message: semantic.Message{
			Version: http.Version{1, 1},
			Body:    bytes.NewReader(nil),
		},
	}
	s.defaultRequest.EnsureHeadersSet()

	s.receiver = newPipelineReceiver(s.conn, 1)
}

func (s *PipelineReceiverTestSuite) TestContextCancel() {
	ctx, cancel := context.WithCancel(s.ctx)

	var wg sync.WaitGroup
	defer wg.Wait()

	s.receiver.start(ctx, &wg)
	s.receiver.signal <- struct{}{}

	cancel()
	s.ErrorIs(<-s.receiver.errchan, context.Canceled)
}

func (s *PipelineReceiverTestSuite) TestReadContinuous() {
	var wg sync.WaitGroup
	defer wg.Wait()

	s.receiver.start(s.ctx, &wg)

	N := 3

	go func() {
		enc := http.NewRequestEncoder(s.src, http.EncodeOptions{})
		for range N {
			s.receiver.signal <- struct{}{}
			s.Require().NoError(enc.Encode(s.defaultRequest.RawRequest()))
		}
		close(s.receiver.signal)
	}()

	expected := s.defaultRequest
	expected.Body = nil

	for range N {
		request := <-s.receiver.stream

		// Is it buffered?
		s.IsType(&bytes.Buffer{}, request.Body)

		request.Body = nil

		s.Equal(&expected, request)
	}
}

func (s *PipelineReceiverTestSuite) TestReadChunked() {
	var wg sync.WaitGroup
	defer wg.Wait()

	s.receiver.start(s.ctx, &wg)

	go func() {
		enc := http.NewRequestEncoder(s.src, http.EncodeOptions{})
		s.receiver.signal <- struct{}{}

		s.defaultRequest.TransferEncoding = []transfer.Coding{transfer.CodingChunked}
		s.defaultRequest.EnsureHeadersSet()

		s.Require().NoError(enc.Encode(s.defaultRequest.RawRequest()))

		close(s.receiver.signal)
	}()

	request := <-s.receiver.stream

	// It shouldn't be buffered
	s.NotEqual(reflect.TypeOf(&bytes.Buffer{}), reflect.TypeOf(request.Body))

	s.defaultRequest.Body = nil
	request.Body = nil

	s.Equal(&s.defaultRequest, request)
}

func (s *PipelineReceiverTestSuite) TestReadError() {
	var wg sync.WaitGroup
	defer wg.Wait()

	s.receiver.start(s.ctx, &wg)

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.receiver.signal <- struct{}{}

		_, err := s.src.Write([]byte("AYO THIS IS HTTP\r\n"))
		s.NoError(err)

		close(s.receiver.signal)
	}()

	s.Error(<-s.receiver.errchan)
}

type PipelineSenderTestSuite struct {
	suite.Suite

	ctx      context.Context
	clock    *clock.Mock
	src, dst transport.Conn

	conn *conn

	defaultResponse semantic.Response

	sender *pipelineSender
}

func TestPipelineSenderTestSuite(t *testing.T) {
	suite.Run(t, new(PipelineSenderTestSuite))
}

func (s *PipelineSenderTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.clock = clock.NewMock()

	s.src, s.dst = pipe.NewPair("a", "b", s.clock)

	s.conn = &conn{
		con:      s.src,
		w:        s.src,
		clock:    s.clock,
		version:  http.Version{1, 1},
		transfer: transfer.NewCodingApplier(nil),
	}

	s.defaultResponse = semantic.Response{
		Message: semantic.Message{Version: s.conn.version},
		Status:  status.OK,
		Date:    s.clock.Now(),
	}
	s.defaultResponse.EnsureHeadersSet()

	s.sender = newPipelineSender(s.conn)
}

func (s *PipelineSenderTestSuite) TestSend() {
	var wg sync.WaitGroup
	defer wg.Wait()

	s.sender.start(&wg)

	N := 3

	wg.Add(1)
	go func() {
		defer wg.Done()
		dec := http.NewResponseDecoder(iolib.NewUntilReader(s.dst), http.DecodeOptions{})

		for range N {
			var raw http.Response
			s.Require().NoError(dec.Decode(&raw))

			response, err := semantic.ResponseFrom(raw, semantic.ParseResponseOptions{})
			s.Require().NoError(err)

			response.Body = nil

			s.Equal(s.defaultResponse, response)
		}
	}()

	for range N {
		s.sender.stream <- pointer.To(s.defaultResponse.Clone())
	}
	close(s.sender.stream)
}

func (s *PipelineSenderTestSuite) TestSendError() {
	var wg sync.WaitGroup
	defer wg.Wait()

	s.conn.opts.Serve.Timeout.WriteTimeout = time.Millisecond

	s.sender.start(&wg)

	s.sender.stream <- &s.defaultResponse

	time.Sleep(50 * time.Millisecond)
	s.clock.Add(time.Millisecond) // Timeout.

	s.ErrorIs(<-s.sender.errchan, transport.ErrDeadLineExceeded)

	for range 3 {
		// responses after error are drained.
		s.sender.stream <- &s.defaultResponse
	}

	close(s.sender.stream)
}

type PipelineWorkerTestSuite struct {
	suite.Suite

	ctx context.Context

	extraWorkers uint

	tConn transport.Conn

	conn   *conn
	worker *pipelineWorker
}

func TestPipelineWorkerTestSuite(t *testing.T) {
	suite.Run(t, new(PipelineWorkerTestSuite))
}

func (s *PipelineWorkerTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.extraWorkers = 1

	s.tConn, _ = pipe.NewPair("a", "b", clock.NewMock())

	s.conn = &conn{
		con: s.tConn,
		handle: func(c *HandleContext, request *semantic.Request) *semantic.Response {
			return &semantic.Response{}
		},
	}

	s.worker = newPipelineWorker(s.conn, s.extraWorkers)
}

func (s *PipelineWorkerTestSuite) TestOrdered() {
	var wg sync.WaitGroup
	defer wg.Wait()

	s.worker.handle = func(c *HandleContext, request *semantic.Request) *semantic.Response {
		time.Sleep(time.Duration(rand.Intn(10)) * time.Millisecond)

		order, _ := request.Headers.Get("Order")
		i, _ := strconv.Atoi(order)

		return &semantic.Response{Message: makeOrderMessage(i)}
	}

	s.worker.start(s.ctx, &wg)

	// To test its capability of handling flooding inputs,
	// set N as its concurrency limit + 2
	N := int((1 + s.extraWorkers) + 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range N {
			expected := &semantic.Response{Message: makeOrderMessage(i)}

			output := <-s.worker.outputs
			response := output.response
			response.Body = nil
			expected.Body = nil

			s.Equal(expected, response)
		}
	}()

	for i := range N {
		s.worker.inputs <- pipelineInput{
			request: &semantic.Request{Message: makeOrderMessage(i)},
			block:   false,
		}
		<-s.worker.moreSignal
	}
	close(s.worker.inputs)
}

func makeOrderMessage(order int) semantic.Message {
	return semantic.Message{
		Headers: semantic.NewHeaders(map[string][]string{
			"Order": {strconv.Itoa(int(order))},
		}),
		Body: bytes.NewReader(nil),
	}
}

func (s *PipelineWorkerTestSuite) TestBlocking() {
	var wg sync.WaitGroup
	defer wg.Wait()

	processingDone := make(chan struct{})
	s.worker.handle = func(c *HandleContext, request *semantic.Request) *semantic.Response {
		processingDone <- struct{}{}
		return &semantic.Response{}
	}

	s.worker.start(s.ctx, &wg)

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-s.worker.outputs
		<-s.worker.outputs
	}()

	s.worker.inputs <- pipelineInput{
		request: &semantic.Request{Message: semantic.Message{Body: bytes.NewReader(nil)}},
		block:   true,
	}

	nextInput := pipelineInput{
		request: &semantic.Request{Message: semantic.Message{Body: bytes.NewReader(nil)}},
		block:   false,
	}
	select {
	case <-s.worker.moreSignal:
		// This shouldn't happen.
		s.FailNow("input received before blocked processing done")
	case <-processingDone:
	}
	<-s.worker.moreSignal

	s.worker.inputs <- nextInput
	<-s.worker.moreSignal
	<-processingDone

	close(s.worker.inputs)
}

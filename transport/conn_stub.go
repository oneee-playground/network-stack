package transport

import (
	"bytes"
	"context"
	"sync"
)

type stubConn struct {
	stream       chan []byte
	closed       chan struct{}
	signalClosed func()

	buf *bytes.Buffer

	counterpart *stubConn
}

var _ Conn = (*stubConn)(nil)

func (s *stubConn) Close() error {
	// Assume closing closed connection will panic?
	close(s.closed)
	close(s.counterpart.stream)
	s.signalClosed()
	return nil
}

func (s *stubConn) Read(p []byte) (n int, err error) {
	if s.buf.Len() > 0 {
		// if buf is not empty, read from it.
		return s.buf.Read(p)
	}

	select {
	case <-s.closed:
		return 0, ErrConnClosed
	case b, ok := <-s.stream:
		if !ok {
			// counterpart is closed.
			return 0, ErrConnClosed
		}
		n := copy(p, b)
		if remain := len(b) - n; remain > 0 {
			// copy didn't get all the bytes from counterpart.
			// store it for later.
			s.buf.Write(b[n:])
		}
		return n, nil
	}
}

func (s *stubConn) Write(p []byte) (n int, err error) {
	c := make([]byte, len(p))
	copy(c, p)

	select {
	case <-s.closed:
		return 0, ErrConnClosed
	case <-s.counterpart.closed:
		// counterpart is closed. return an error.
		return 0, ErrConnClosed
	case s.counterpart.stream <- c:
		return len(c), nil
	}
}

type stubConnListener struct {
	connChan chan *stubConn

	m      sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

func NewStubConnListener() *stubConnListener {
	return &stubConnListener{
		connChan: make(chan *stubConn),
	}
}

var _ ConnListener = (*stubConnListener)(nil)

func (s *stubConnListener) Accept(ctx context.Context) (Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case conn, ok := <-s.connChan:
		if !ok {
			return nil, ErrConnListnerClosed
		}
		return conn, nil
	}
}

func (s *stubConnListener) MakeConn() (*stubConn, error) {
	s.m.Lock()
	defer s.m.Unlock()
	if s.closed {
		return nil, ErrConnListnerClosed
	}

	s.wg.Add(2)

	toFeed := &stubConn{
		signalClosed: s.wg.Done,
		closed:       make(chan struct{}),
		buf:          bytes.NewBuffer(nil),
		stream:       make(chan []byte),
	}
	toReturn := &stubConn{
		signalClosed: s.wg.Done,
		closed:       make(chan struct{}),
		buf:          bytes.NewBuffer(nil),
		stream:       make(chan []byte),
	}

	toFeed.counterpart, toReturn.counterpart = toReturn, toFeed

	s.connChan <- toFeed

	return toReturn, nil
}

func (s *stubConnListener) Close() error {
	s.m.Lock()
	close(s.connChan)
	s.closed = true
	s.m.Unlock()

	s.wg.Wait()
	return nil
}

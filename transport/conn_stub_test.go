package transport

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type StubConnTestSuite struct {
	suite.Suite

	listenConn, dialConn *stubConn
}

func (s *StubConnTestSuite) SetupTest() {
	s.listenConn = &stubConn{
		signalClosed: func() {},
		closed:       make(chan struct{}),
		buf:          bytes.NewBuffer(nil),
		stream:       make(chan []byte),
	}
	s.dialConn = &stubConn{
		signalClosed: func() {},
		closed:       make(chan struct{}),
		buf:          bytes.NewBuffer(nil),
		stream:       make(chan []byte),
	}

	s.listenConn.counterpart, s.dialConn.counterpart = s.dialConn, s.listenConn
}

func (s *StubConnTestSuite) TestReadWrite() {
	data := []byte("Hello, World!")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		n, err := s.listenConn.Write(data)
		s.Require().NoError(err)
		s.Equal(len(data), n)
	}()
	go func() {
		buf := make([]byte, 10)

		n, err := s.dialConn.Read(buf)
		s.Require().NoError(err)
		s.Equal(len(buf), n)
		s.Equal(data[:n], buf)

		n, err = s.dialConn.Read(buf)
		s.Require().NoError(err)
		s.Equal(len(data)-len(buf), n)
		s.Equal(data[len(buf):], buf)
	}()

	wg.Wait()
}

func (s *StubConnTestSuite) TestClose() {
	tryReadWrite := func(conn *stubConn) {
		buf := make([]byte, 10)

		n, err := conn.Read(buf)
		s.Require().ErrorIs(err, ErrConnClosed)
		s.Zero(n)
		s.Empty(buf)

		n, err = conn.Write(buf)
		s.Require().ErrorIs(err, ErrConnClosed)
		s.Zero(n)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	done := make(chan struct{})
	go func() {
		s.Require().NoError(s.listenConn.Close())
		close(done)

		tryReadWrite(s.listenConn)
	}()
	go func() {
		select {
		case <-time.After(time.Second):
			s.FailNow("timeout exceeded")
		case <-done:
		}

		tryReadWrite(s.dialConn)
	}()

	wg.Wait()
}

type StubConnListenerTestSuite struct {
	suite.Suite

	listener *stubConnListener
}

func TestStubConnListenerTestSuite(t *testing.T) {
	suite.Run(t, new(StubConnListenerTestSuite))
}

func (s *StubConnListenerTestSuite) SetupTest() {
	s.listener = NewStubConnListener()
}

func (s *StubConnListenerTestSuite) TestAccept() {
	go func() {
		ctx, close := context.WithTimeout(context.Background(), time.Second)
		defer close()

		conn, err := s.listener.Accept(ctx)
		s.Require().NoError(err)
		s.NotNil(conn)

		defer conn.Close()
	}()

	conn, err := s.listener.MakeConn()
	s.Require().NoError(err)
	s.NotNil(conn)

	conn.Close()
}

func (s *StubConnListenerTestSuite) TestClose() {
	s.Require().NoError(s.listener.Close())

	conn, err := s.listener.Accept(context.Background())
	s.ErrorIs(err, ErrConnListnerClosed)
	s.Nil(conn)

	conn, err = s.listener.MakeConn()
	s.ErrorIs(err, ErrConnListnerClosed)
	s.Nil(conn)
}

func (s *StubConnListenerTestSuite) TestCloseGraceful() {
	go func() {
		ctx, close := context.WithTimeout(context.Background(), time.Second)
		defer close()

		conn, err := s.listener.Accept(ctx)
		s.Require().NoError(err)
		s.NotNil(conn)

		defer conn.Close()
	}()

	conn, err := s.listener.MakeConn()
	s.Require().NoError(err)
	s.NotNil(conn)

	// Above is same as TestAccept.

	done := make(chan struct{})
	go func() {
		s.NoError(s.listener.Close())
		close(done)
	}()

	c := time.After(time.Millisecond * 100)
	select {
	case <-c:
		s.Require().NoError(conn.Close())
	case <-done:
		s.FailNow("conn listener didn't wait for connections")
	}

	s.Eventually(func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond*10)
}

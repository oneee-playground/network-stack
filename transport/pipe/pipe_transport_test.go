package pipe

import (
	"context"
	"network-stack/transport"
	"sync"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/suite"
)

type PipeTransportTestSuite struct {
	suite.Suite

	transport *PipeTransport
}

func TestPipeTransportTestSuite(t *testing.T) {
	suite.Run(t, new(PipeTransportTestSuite))
}

func (s *PipeTransportTestSuite) SetupTest() {
	s.transport = NewPipeTransport(clock.New())
}

func (s *PipeTransportTestSuite) TestListen() {
	addr := Addr{Name: "hey"}

	lis, err := s.transport.Listen(addr)
	s.Require().NoError(err)
	s.Require().NotNil(lis)

	got, ok := s.transport.listeners[addr]
	s.True(ok)
	s.Equal(lis, got)

	lis, err = s.transport.Listen(addr)
	s.ErrorIs(err, transport.ErrAddrAlreadyInUse)
	s.Nil(lis)
}

func (s *PipeTransportTestSuite) TestDial() {
	addr := Addr{Name: "hey"}

	lis, err := s.transport.Listen(addr)
	s.Require().NoError(err)
	s.Require().NotNil(lis)
	go func() {
		_, err := lis.Accept(context.Background())
		s.Require().NoError(err)
	}()

	conn, err := s.transport.Dial(context.Background(), addr)
	s.Require().NoError(err)
	s.Require().NotNil(conn)

	s.Equal(conn.RemoteAddr(), transport.Addr(addr))
}

type PipeListenerTestSuite struct {
	suite.Suite

	transport *PipeTransport
	pl        *pipeListener
}

func TestPipeListenerTestSuite(t *testing.T) {
	suite.Run(t, new(PipeListenerTestSuite))
}

func (s *PipeListenerTestSuite) SetupTest() {
	s.transport = NewPipeTransport(clock.New())

	s.pl = &pipeListener{
		addr:      Addr{Name: "hey"},
		transport: s.transport,
		requests:  make(chan pipeRequest),
		closed:    make(chan struct{}),
	}

	s.transport.listeners[s.pl.addr] = s.pl
}

func (s *PipeListenerTestSuite) TestAccept() {
	_, p2 := NewPair("dialer", s.pl.addr.(Addr).Name, s.transport.clock)

	done := make(chan struct{})
	go func() {
		defer close(done)

		req := pipeRequest{conn: p2, accepted: make(chan struct{})}

		s.pl.requests <- req

		_, ok := <-req.accepted
		s.True(ok)
	}()

	conn, err := s.pl.Accept(context.Background())
	s.Equal(p2, conn)
	s.NoError(err)
	<-done
}

func (s *PipeListenerTestSuite) TestAcceptCancels() {
	_, p2 := NewPair("dialer", s.pl.addr.(Addr).Name, s.transport.clock)

	done := make(chan struct{})
	go func() {
		defer close(done)

		req := pipeRequest{conn: p2, accepted: make(chan struct{})}

		s.pl.requests <- req

		// Doesn't receive from accepted
	}()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	conn, err := s.pl.Accept(ctx)
	s.Nil(conn)
	s.ErrorIs(err, context.Canceled)
}

func (s *PipeListenerTestSuite) TestClose() {
	s.Require().NoError(s.pl.Close())

	<-s.pl.closed

	s.ErrorIs(s.pl.Close(), transport.ErrConnListenerClosed)

	listener, ok := s.transport.listeners[s.pl.addr]
	s.False(ok)
	s.Nil(listener)
}

func (s *PipeListenerTestSuite) TestCloseAwaitingConns() {
	var wg sync.WaitGroup
	defer wg.Wait()

	s.pl.requests = make(chan pipeRequest, 1)

	wg.Add(1)
	done := make(chan struct{})
	go func() {
		defer wg.Done()
		req := pipeRequest{
			conn:     nil,
			accepted: make(chan struct{}),
		}
		s.pl.requests <- req

		done <- struct{}{}

		_, ok := <-req.accepted
		s.False(ok)
	}()
	<-done

	s.Require().NoError(s.pl.Close())
}

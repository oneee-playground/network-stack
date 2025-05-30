package test

import (
	"bytes"
	"network-stack/transport"
	"sync"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/suite"
	"go.uber.org/goleak"
)

type ConnTestSuite struct {
	suite.Suite
	C1, C2 transport.Conn
	Clock  clock.Clock

	done  chan struct{}
	timer *time.Timer
}

func (s *ConnTestSuite) SetupTest() {
	s.done = make(chan struct{})
	s.Clock = clock.New() // Use real-time timer for now.

	s.timer = time.AfterFunc(time.Second, func() {
		select {
		case <-s.done:
		default:
			s.FailNow("timeout exceeded")
		}
	})
}

func (s *ConnTestSuite) TearDownTest() {
	defer goleak.VerifyNone(s.T())
	close(s.done)
	s.timer.Stop()
}

func (s *ConnTestSuite) TestReadWrite() {
	data := []byte("Hello, World!")

	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, err := s.C1.Write(data)
		s.Require().NoError(err)
		s.Equal(len(data), n)
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 10)

		n, err := s.C2.Read(buf)
		s.Require().NoError(err)
		s.Equal(len(buf), n)
		s.Equal(data[:n], buf)

		n, err = s.C2.Read(buf)
		s.Require().NoError(err)
		s.Equal(len(data)-len(buf), n)
		s.Equal(data[len(buf):], buf[:n])
	}()
}

func (s *ConnTestSuite) TestWriteRace() {
	data := []byte("ABCD")
	N := 10

	var wg sync.WaitGroup
	defer wg.Wait()

	result := make([]byte, 0)

	wg.Add(1)
	go func() {
		defer wg.Done()

		b := make([]byte, len(data))
		for range N {
			n, err := s.C2.Read(b)
			s.Require().NoError(err)
			result = append(result, b[:n]...)
		}

		s.Equal(bytes.Repeat(data, N), result)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		var wwg sync.WaitGroup
		for range N {
			wwg.Add(1)
			go func() {
				defer wwg.Done()
				n, err := s.C1.Write(data)
				s.Require().NoError(err)
				s.Equal(len(data), n)
			}()
		}
		wwg.Wait()
	}()
}

func (s *ConnTestSuite) TestReadRace() {
	data := []byte("ABCD")
	N := 10

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()

		for range N {
			n, err := s.C2.Write(data)
			s.Require().Equal(len(data), n)
			s.Require().NoError(err)
		}
	}()

	result := make([]byte, 0)
	var l sync.Mutex

	wg.Add(1)
	go func() {
		defer wg.Done()
		var wwg sync.WaitGroup
		for range N {
			wwg.Add(1)
			go func() {
				defer wwg.Done()
				b := make([]byte, len(data))

				n, err := s.C1.Read(b)
				s.Require().NoError(err)
				s.Equal(len(data), n)

				l.Lock()
				result = append(result, b[:n]...)
				l.Unlock()
			}()
		}
		wwg.Wait()

		s.Equal(bytes.Repeat(data, N), result)
	}()
}

func (s *ConnTestSuite) TestClose() {
	tryReadWrite := func(conn transport.Conn) {
		buf := make([]byte, 10)

		n, err := conn.Read(buf)
		s.Require().ErrorIs(err, transport.ErrConnClosed)
		s.Zero(n)

		n, err = conn.Write(buf)
		s.Require().ErrorIs(err, transport.ErrConnClosed)
		s.Zero(n)
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(2)

	done := make(chan struct{})
	go func() {
		defer wg.Done()
		s.Require().NoError(s.C1.Close())
		close(done)

		tryReadWrite(s.C1)
	}()
	go func() {
		defer wg.Done()
		select {
		case <-s.Clock.After(time.Second):
			s.FailNow("timeout exceeded")
		case <-done:
		}

		tryReadWrite(s.C2)
	}()
}

func (s *ConnTestSuite) TestReadBeforeClose() {
	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := s.C1.Read(nil)
		s.ErrorIs(err, transport.ErrConnClosed)
	}()

	time.Sleep(50 * time.Millisecond)
	s.Require().NoError(s.C1.Close())
}

func (s *ConnTestSuite) TestWriteBeforeClose() {
	if _, ok := s.C1.(transport.BufferedConn); ok {
		s.T().Skip("transport.BufferedConn might fail the test due to its buffer.")
	}

	input := []byte("hey")
	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := s.C1.Write(input)
		s.ErrorIs(err, transport.ErrConnClosed)
	}()

	time.Sleep(50 * time.Millisecond)
	s.Require().NoError(s.C1.Close())
}

func (s *ConnTestSuite) TestReadDeadLine() {
	s.C1.SetReadDeadLine(s.Clock.Now().Add(-time.Second))

	b := make([]byte, 1)
	n, err := s.C1.Read(b)
	s.ErrorIs(err, transport.ErrDeadLineExceeded)
	s.Zero(n)

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := s.C2.Write([]byte{'a'})
		s.NoError(err)
	}()

	s.C1.SetReadDeadLine(time.Time{})

	n, err = s.C1.Read(b)
	s.NoError(err)
	s.Equal(1, n)
}

func (s *ConnTestSuite) TestWriteDeadLine() {
	s.C1.SetWriteDeadLine(s.Clock.Now().Add(-time.Second))

	n, err := s.C1.Write([]byte{'a'})
	s.ErrorIs(err, transport.ErrDeadLineExceeded)
	s.Zero(n)

	// Some implementations might not be able to write after the deadline.

	// var wg sync.WaitGroup
	// defer wg.Wait()

	// wg.Add(1)
	// go func() {
	// 	defer wg.Done()
	// 	_, err := s.C2.Read(make([]byte, 1))
	// 	s.NoError(err)
	// }()

	// s.C1.SetWriteDeadLine(time.Time{})

	// n, err = s.C1.Write([]byte{'a'})
	// s.NoError(err)
	// s.Equal(1, n)
}

func (s *ConnTestSuite) TestAddr() {
	local1, remote1 := s.C1.LocalAddr(), s.C1.RemoteAddr()
	local2, remote2 := s.C2.LocalAddr(), s.C2.RemoteAddr()

	s.Equal(local1, remote2)
	s.Equal(local2, remote1)
}

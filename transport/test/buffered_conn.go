package test

import (
	"network-stack/transport"
	"sync"
	"testing"

	"github.com/stretchr/testify/suite"
)

type BufferedConnTestSuite struct {
	ConnTestSuite
}

func TestBufferedConnTestSuite(t *testing.T) {
	suite.Run(t, new(BufferedConnTestSuite))
}

func (s *BufferedConnTestSuite) SetupTest() {
	s.ConnTestSuite.SetupTest()
}

func (s *BufferedConnTestSuite) TestBothWrite() {
	c1 := s.C1.(transport.BufferedConn)
	c2 := s.C2.(transport.BufferedConn)
	size1, size2 := int(c1.ReadBufSize()), int(c2.ReadBufSize())

	var wg sync.WaitGroup
	wg.Add(2)
	defer wg.Wait()

	go func() {
		defer wg.Done()
		b := make([]byte, size2)

		// Write as much as c2 can handle.
		n, err := s.C1.Write(b)
		s.Require().NoError(err)
		s.Equal(size2, n)

		n, err = s.C2.Read(b)
		s.Require().NoError(err)
		s.Equal(size2, n)
	}()

	go func() {
		defer wg.Done()
		b := make([]byte, size1)

		// Write as much as c1 can handle.
		n, err := s.C2.Write(b)
		s.Require().NoError(err)
		s.Equal(size1, n)

		n, err = s.C1.Read(b)
		s.Require().NoError(err)
		s.Equal(size1, n)
	}()
}

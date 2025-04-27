package conn

import (
	"network-stack/transport/pipe"
	"network-stack/transport/test"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ConnTestSuite struct {
	test.ConnTestSuite
}

func TestConnTestSuite(t *testing.T) {
	suite.Run(t, new(ConnTestSuite))
}

func (s *ConnTestSuite) SetupTest() {
	s.ConnTestSuite.SetupTest()

	c1, c2 := pipe.NewPair("a", "b", s.Clock)

	s.C1 = &Conn{underlying: c1}
	s.C2 = &Conn{underlying: c2}
}

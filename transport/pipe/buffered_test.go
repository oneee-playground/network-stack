package pipe

import (
	"network-stack/transport/test"
	"testing"

	"github.com/stretchr/testify/suite"
)

type BufferedPipeTestSuite struct {
	test.BufferedConnTestSuite
}

func TestBufferedPipeTestSuite(t *testing.T) {
	suite.Run(t, new(BufferedPipeTestSuite))
}

func (s *BufferedPipeTestSuite) SetupTest() {
	s.BufferedConnTestSuite.SetupTest()
	s.C1, s.C2 = BufferedPipe("A", "B", s.Clock, 20)
}

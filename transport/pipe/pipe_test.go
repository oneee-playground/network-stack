package pipe

import (
	"network-stack/transport/test"
	"testing"

	"github.com/stretchr/testify/suite"
)

type PipeTestSuite struct {
	test.ConnTestSuite
}

func TestPipeTestSuite(t *testing.T) {
	suite.Run(t, new(PipeTestSuite))
}

func (s *PipeTestSuite) SetupTest() {
	s.ConnTestSuite.SetupTest()
	s.C1, s.C2 = Pipe("A", "B", s.Clock)
}

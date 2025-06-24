package transport

import (
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/suite"
)

type PortTableTestSuite struct {
	suite.Suite

	table *PortTable
}

func TestPortTableTestSuite(t *testing.T) {
	suite.Run(t, new(PortTableTestSuite))
}

func (s *PortTableTestSuite) SetupTest() {
	s.table = NewPortTable(EphemeralPortOptions{
		Range: [2]uint16{},
		Rand:  func() uint16 { return 0 },
	})
}
func (s *PortTableTestSuite) TestOccupy() {
	port := uint16(100)

	ok, result, release := s.table.Occupy(port)
	s.Require().True(ok)
	s.Require().Equal(port, result)
	s.Require().NotNil(release)

	ok, _, _release := s.table.Occupy(port)
	s.Require().False(ok)
	s.Require().Nil(_release)

	release()

	ok, result, release = s.table.Occupy(port)
	s.Require().True(ok)
	s.Require().Equal(port, result)
	s.Require().NotNil(release)
}

func (s *PortTableTestSuite) TestOccupyEphemeral() {
	s.table = NewPortTable(EphemeralPortOptions{
		Range:  [2]uint16{1, 2}, // only result in 1
		Rand:   func() uint16 { return uint16(rand.Uint()) },
		MaxTry: 1,
	})

	ok, result, release := s.table.Occupy(0)
	s.Require().True(ok)
	s.Require().Equal(uint16(1), result)
	s.Require().NotNil(release)

	ok, _, _release := s.table.Occupy(0)
	s.Require().False(ok)
	s.Require().Nil(_release)

	release()

	ok, result, release = s.table.Occupy(0)
	s.Require().True(ok)
	s.Require().Equal(uint16(1), result)
	s.Require().NotNil(release)
}

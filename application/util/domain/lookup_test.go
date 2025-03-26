package domain

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type LookuperTestSuite struct {
	suite.Suite

	initial  map[string]string
	lookuper Lookuper
}

func (s *LookuperTestSuite) SetupTest() {
	s.initial = map[string]string{
		"localhost":   "127.0.0.1",
		"example.com": "1.1.1.1", // It's actually cloudflare. But who cares?
	}
}

func (s *LookuperTestSuite) TestLookup() {
	addr, err := s.lookuper.Lookup("localhost")
	s.NoError(err)
	s.Equal("127.0.0.1", addr)

	addr, err = s.lookuper.Lookup("example.com")
	s.NoError(err)
	s.Equal("1.1.1.1", addr)

	// Non-existent.
	addr, err = s.lookuper.Lookup("non-existent.com")
	s.ErrorIs(err, ErrDomainNotFound)
	s.Zero(addr)
}

func (s *LookuperTestSuite) TestLookupInitCopied() {
	s.initial["localhost"] = "haha modified"

	addr, err := s.lookuper.Lookup("localhost")
	s.NoError(err)
	s.Equal("127.0.0.1", addr)
}

type mapLookuperTestSuite struct{ LookuperTestSuite }

func TestMapLookuperTestSuite(t *testing.T) {
	suite.Run(t, new(mapLookuperTestSuite))
}

func (s *mapLookuperTestSuite) SetupTest() {
	s.LookuperTestSuite.SetupTest()
	s.lookuper = NewMapLookuper(s.initial)
}

package domain

import (
	"context"
	"network-stack/network"
	ipv4 "network-stack/network/ip/v4"
	"testing"

	"github.com/stretchr/testify/suite"
)

type LookuperTestSuite struct {
	suite.Suite

	initial  map[string][]network.Addr
	lookuper Lookuper
}

func (s *LookuperTestSuite) SetupTest() {
	s.initial = map[string][]network.Addr{
		"localhost":   {ipv4.Addr{127, 0, 0, 1}},
		"example.com": {ipv4.Addr{1, 1, 1, 1}}, // It's actually cloudflare. But who cares?
	}
}

func (s *LookuperTestSuite) TestLookup() {
	ctx := context.Background()

	addrs, err := s.lookuper.Lookup(ctx, "localhost")
	s.NoError(err)
	s.Len(addrs, 1)
	s.Equal(ipv4.Addr{127, 0, 0, 1}, addrs[0])

	addrs, err = s.lookuper.Lookup(ctx, "example.com")
	s.NoError(err)
	s.Len(addrs, 1)
	s.Equal(ipv4.Addr{1, 1, 1, 1}, addrs[0])

	// Non-existent.
	addrs, err = s.lookuper.Lookup(ctx, "non-existent.com")
	s.ErrorIs(err, ErrDomainNotFound)
	s.Empty(addrs)
}

func (s *LookuperTestSuite) TestLookupInitCopied() {
	ctx := context.Background()
	s.initial["localhost"] = []network.Addr{ipv4.Addr{123, 123, 123, 123}}

	addrs, err := s.lookuper.Lookup(ctx, "localhost")
	s.NoError(err)
	s.Len(addrs, 1)
	s.Equal(ipv4.Addr{127, 0, 0, 1}, addrs[0])
}

type mapLookuperTestSuite struct{ LookuperTestSuite }

func TestMapLookuperTestSuite(t *testing.T) {
	suite.Run(t, new(mapLookuperTestSuite))
}

func (s *mapLookuperTestSuite) SetupTest() {
	s.LookuperTestSuite.SetupTest()
	s.lookuper = NewMapLookuper(s.initial)
}

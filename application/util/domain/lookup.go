package domain

import (
	"context"
	"maps"
	"network-stack/network/ip"

	"github.com/pkg/errors"
)

var ErrDomainNotFound = errors.New("domain not found")

type Lookuper interface {
	LookupIP(ctx context.Context, domain string) (addrs []ip.Addr, err error)
}

type mapLookuper struct {
	set map[string][]ip.Addr
}

var _ Lookuper = (*mapLookuper)(nil)

func NewMapLookuper(set map[string][]ip.Addr) *mapLookuper {
	if set == nil {
		set = make(map[string][]ip.Addr)
	}
	return &mapLookuper{set: maps.Clone(set)}
}

func (m *mapLookuper) LookupIP(ctx context.Context, domain string) (addrs []ip.Addr, err error) {
	addrs, ok := m.set[domain]
	if !ok {
		return nil, ErrDomainNotFound
	}
	return addrs, nil
}

func (m *mapLookuper) Set(domain string, addrs []ip.Addr) {
	if len(addrs) == 0 {
		return
	}
	m.set[domain] = addrs
}

func (m *mapLookuper) Del(domain string) { delete(m.set, domain) }

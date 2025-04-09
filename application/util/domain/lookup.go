package domain

import (
	"context"
	"maps"
	"network-stack/network"

	"github.com/pkg/errors"
)

var ErrDomainNotFound = errors.New("domain not found")

type Lookuper interface {
	Lookup(ctx context.Context, domain string) (addrs []network.Addr, err error)
}

type mapLookuper struct {
	set map[string][]network.Addr
}

var _ Lookuper = (*mapLookuper)(nil)

func NewMapLookuper(set map[string][]network.Addr) *mapLookuper {
	if set == nil {
		set = make(map[string][]network.Addr)
	}
	return &mapLookuper{set: maps.Clone(set)}
}

func (m *mapLookuper) Lookup(ctx context.Context, domain string) (addrs []network.Addr, err error) {
	addrs, ok := m.set[domain]
	if !ok {
		return nil, ErrDomainNotFound
	}
	return addrs, nil
}

func (m *mapLookuper) Set(domain string, addrs []network.Addr) {
	if len(addrs) == 0 {
		return
	}
	m.set[domain] = addrs
}

func (m *mapLookuper) Del(domain string) { delete(m.set, domain) }

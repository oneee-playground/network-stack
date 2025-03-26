package domain

import (
	"maps"

	"github.com/pkg/errors"
)

var ErrDomainNotFound = errors.New("domain not found")

type Lookuper interface {
	Lookup(domain string) (addr string, err error)
}

type mapLookuper struct {
	set map[string]string
}

var _ Lookuper = (*mapLookuper)(nil)

func NewMapLookuper(set map[string]string) *mapLookuper {
	if set == nil {
		set = make(map[string]string)
	}
	return &mapLookuper{set: maps.Clone(set)}
}

func (m *mapLookuper) Lookup(domain string) (addr string, err error) {
	addr, ok := m.set[domain]
	if !ok {
		return "", ErrDomainNotFound
	}
	return addr, nil
}

func (m *mapLookuper) Set(domain, addr string) { m.set[domain] = addr }

func (m *mapLookuper) Del(domain string) { delete(m.set, domain) }

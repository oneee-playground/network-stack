package transport

import (
	"sync"

	"github.com/pkg/errors"
)

type PortTable struct {
	table map[uint16]struct{}
	mu    sync.Mutex

	ephemeral    [2]uint16 // start, end
	rand         func() uint16
	maxRandTry uint
}

type EphemeralPortOptions struct {
	Range  [2]uint16 // [start, end)
	Rand   func() uint16
	MaxTry uint
}

func (o EphemeralPortOptions) validate() error {
	if o.Range[0] > o.Range[1] {
		return errors.Errorf("end(%d) must be greater or equal than start(%d)", o.Range[1], o.Range[0])
	}
	if o.Rand == nil {
		return errors.New("rand function must be provided")
	}
	return nil
}

func NewPortTable(opts EphemeralPortOptions) *PortTable {
	if err := opts.validate(); err != nil {
		panic(err)
	}

	return &PortTable{
		table:        make(map[uint16]struct{}),
		ephemeral:    opts.Range,
		rand:         opts.Rand,
		maxRandTry: opts.MaxTry,
	}
}

func (p *PortTable) Occupy(port uint16) (ok bool, result uint16, release func()) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if port == 0 {
		return p.occupyEphemeralLocked()
	}

	if ok, release := p.occupyLocked(port); ok {
		return true, port, release
	}

	return false, 0, nil
}

func (p *PortTable) occupyEphemeralLocked() (ok bool, port uint16, release func()) {
	for try := uint(0); try < p.maxRandTry; try++ {
		port := p.selectEphemeral()

		if port == 0 {
			continue
		}

		if ok, release := p.occupyLocked(port); ok {
			return true, port, release
		}
	}

	return false, 0, nil
}

func (p *PortTable) occupyLocked(port uint16) (ok bool, release func()) {
	if _, found := p.table[port]; found {
		return false, nil
	}

	p.table[port] = struct{}{}

	release = func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		delete(p.table, port)
	}

	return true, release
}

func (p *PortTable) selectEphemeral() uint16 {
	gap := p.ephemeral[1] - p.ephemeral[0]
	selected := p.ephemeral[0] + (p.rand() % gap)
	return selected
}

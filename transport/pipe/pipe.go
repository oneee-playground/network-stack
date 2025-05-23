// Wow this so much looks like the one in stdlib!
// Because I borrowed the idea from there..
package pipe

import (
	"network-stack/network"
	"network-stack/transport"
	"sync"
	"time"

	"github.com/benbjohnson/clock"
)

type pipe struct {
	stream chan []byte // stream that this pipe reads from.
	nc     chan int    // counterpart's respond will be sent here.

	writeMu sync.Mutex

	closed chan struct{}
	once   sync.Once // making sure not to close closed channel.

	rdeadLine *chanDeadLine
	wdeadLine *chanDeadLine

	// the opposite pipe.
	counterpart *pipe

	addr Addr
}

type Addr struct {
	Name string
}

func (p Addr) NetworkAddr() network.Addr { return nil }
func (p Addr) Identifier() any           { return p.Name }
func (p Addr) String() string            { return p.Name }

var _ transport.Addr = Addr{}
var _ transport.Conn = (*pipe)(nil)

// Pipe creates a pair of pipes. each of pipes will be synchronouse, unbuffered.
func Pipe(name1, name2 string, clock clock.Clock) (c1, c2 *pipe) {
	c1 = &pipe{
		stream:    make(chan []byte),
		nc:        make(chan int),
		closed:    make(chan struct{}),
		rdeadLine: newChanDeadLine(clock),
		wdeadLine: newChanDeadLine(clock),
		addr:      Addr{Name: name1},
	}
	c2 = &pipe{
		stream:    make(chan []byte),
		nc:        make(chan int),
		closed:    make(chan struct{}),
		rdeadLine: newChanDeadLine(clock),
		wdeadLine: newChanDeadLine(clock),
		addr:      Addr{Name: name2},
	}
	c1.counterpart, c2.counterpart = c2, c1
	return
}

func (p *pipe) LocalAddr() transport.Addr  { return p.addr }
func (p *pipe) RemoteAddr() transport.Addr { return p.counterpart.addr }

func (p *pipe) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func (p *pipe) Read(b []byte) (n int, err error) {
	if err := p.checkReadOK(); err != nil {
		return 0, err
	}

	select {
	case received := <-p.stream:
		n := copy(b, received)
		p.counterpart.nc <- n
		return n, nil
	case <-p.closed:
		return 0, transport.ErrConnClosed
	case <-p.counterpart.closed:
		return 0, transport.ErrConnClosed
	case <-p.rdeadLine.wait():
		return 0, transport.ErrDeadLineExceeded
	}
}

func (p *pipe) Write(b []byte) (n int, err error) {
	if err := p.checkWriteOK(); err != nil {
		return 0, err
	}

	if len(b) == 0 {
		return 0, nil
	}

	// Serialize write operations to prevent interleaving write.
	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	// Ensure all the bytes are sent.
	// Wow this actually is a do-while loop.
	nn := 0
	for once := true; once || len(b) > 0; once = false {
		select {
		case p.counterpart.stream <- b:
			n := <-p.nc
			b = b[n:]
			nn += n
		case <-p.closed:
			return nn, transport.ErrConnClosed
		case <-p.counterpart.closed:
			return nn, transport.ErrConnClosed
		case <-p.wdeadLine.wait():
			return nn, transport.ErrDeadLineExceeded
		}
	}

	return nn, nil
}

func (p *pipe) checkReadOK() error  { return p._checkOK(p.rdeadLine) }
func (p *pipe) checkWriteOK() error { return p._checkOK(p.wdeadLine) }

func (p *pipe) _checkOK(d *chanDeadLine) error {
	switch {
	case isClosed(p.closed):
		return transport.ErrConnClosed
	case isClosed(p.counterpart.closed):
		return transport.ErrConnClosed
	case isClosed(d.wait()):
		return transport.ErrDeadLineExceeded
	}
	return nil

}

func (p *pipe) SetReadDeadLine(t time.Time)  { p.rdeadLine.set(t) }
func (p *pipe) SetWriteDeadLine(t time.Time) { p.wdeadLine.set(t) }

type chanDeadLine struct {
	clock clock.Clock

	t *clock.Timer
	m sync.Mutex

	closed chan struct{}
}

func newChanDeadLine(clock clock.Clock) *chanDeadLine {
	return &chanDeadLine{
		clock:  clock,
		closed: make(chan struct{}),
	}
}

func (d *chanDeadLine) set(t time.Time) {
	d.m.Lock()
	defer d.m.Unlock()

	if d.t != nil {
		// Stop existing timer.
		d.t.Stop()
	}
	d.t = nil

	if isClosed(d.closed) {
		d.closed = make(chan struct{})
	}

	if t.IsZero() {
		// zero value means no limit.
		return
	}

	d.t = d.clock.AfterFunc(d.clock.Until(t), func() {
		close(d.closed)
	})
}

func (d *chanDeadLine) wait() <-chan struct{} {
	d.m.Lock()
	defer d.m.Unlock()
	return d.closed
}

func isClosed(c <-chan struct{}) bool {
	select {
	case <-c: // c will only fire at closed state.
		return true
	default:
		return false
	}
}

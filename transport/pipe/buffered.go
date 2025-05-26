package pipe

import (
	"bytes"
	"network-stack/transport"
	"sync"
	"time"

	"github.com/benbjohnson/clock"
)

// See:
// - https://github.com/golang/go/issues/24205
// - https://github.com/golang/go/issues/34502
type bufferedPipe struct {
	addr Addr

	buf *bytes.Buffer // protected by in.

	in, out  sync.Cond
	serialMu sync.Mutex // For serialized write operations.

	_closed  bool
	closedMu sync.Mutex

	rdeadLine, wdeadLine *deadline

	// the opposite pipe.
	counterpart *bufferedPipe
}

var _ transport.Conn = (*bufferedPipe)(nil)
var _ transport.BufferedConn = (*bufferedPipe)(nil)

// BufferedPipe creates a pair of pipes. each of pipes will be asynchronouse, buffered.
// Because BufferedPipe only writes/reads data through the buffer, bufSize MUST be more than 0.
func BufferedPipe(name1, name2 string, clock clock.Clock, bufSize uint) (c1, c2 *bufferedPipe) {
	if bufSize == 0 {
		panic("buffer size cannot be 0")
	}

	c1 = &bufferedPipe{
		buf:       bytes.NewBuffer(make([]byte, 0, bufSize)),
		rdeadLine: newDeadLine(clock),
		wdeadLine: newDeadLine(clock),
		addr:      Addr{Name: name1},
	}
	c1.in.L, c1.out.L = &sync.Mutex{}, &sync.Mutex{}

	c2 = &bufferedPipe{
		buf:       bytes.NewBuffer(make([]byte, 0, bufSize)),
		rdeadLine: newDeadLine(clock),
		wdeadLine: newDeadLine(clock),
		addr:      Addr{Name: name2},
	}
	c2.in.L, c2.out.L = &sync.Mutex{}, &sync.Mutex{}

	c1.counterpart, c2.counterpart = c2, c1
	return
}

func (p *bufferedPipe) ReadBufSize() uint          { return uint(p.buf.Cap()) }
func (p *bufferedPipe) WriteBufSize() uint         { return uint(p.counterpart.buf.Cap()) }
func (p *bufferedPipe) LocalAddr() transport.Addr  { return p.addr }
func (p *bufferedPipe) RemoteAddr() transport.Addr { return p.counterpart.addr }

func (p *bufferedPipe) Close() error {
	p.closedMu.Lock()
	p._closed = true
	p.closedMu.Unlock()

	p.notifyRead()
	p.notifyWrite()
	p.counterpart.notifyRead()
	p.counterpart.notifyWrite()
	return nil
}

func (p *bufferedPipe) Read(b []byte) (n int, err error) {
	defer func() {
		if err != nil {
			return
		}
		// If buffer was full and counterpart was waiting,
		// we must notify them that it is now available to write.
		p.counterpart.out.L.Lock()
		p.counterpart.notifyWrite()
		p.counterpart.out.L.Unlock()
	}()

	p.in.L.Lock()
	defer p.in.L.Unlock()

	for {
		// We must check for deadline first.
		if p.rdeadLine.exceeded() {
			return 0, transport.ErrDeadLineExceeded
		}

		// Even if connection is closed, we must be able to read from buffer.
		if p.buf.Len() > 0 {
			return p.buf.Read(b)
		}

		if p.closed() || p.counterpart.closed() {
			return 0, transport.ErrConnClosed
		}

		// Wait until one of conditions is satisfied.
		p.in.Wait()
	}
}

func (p *bufferedPipe) Write(b []byte) (n int, err error) {
	// Serialize write operations to prevent interleaving write.
	p.serialMu.Lock()
	defer p.serialMu.Unlock()

	p.out.L.Lock()
	defer p.out.L.Unlock()

	// Ensure all the bytes are sent.
	nn := 0
	for once := true; once || len(b) > 0; once = false {
		if p.wdeadLine.exceeded() {
			return nn, transport.ErrDeadLineExceeded
		}

		if p.closed() || p.counterpart.closed() {
			return nn, transport.ErrConnClosed
		}

		// It might race with counterpart's read. So acquire lock.
		p.counterpart.in.L.Lock()

		// We don't want counterpart's buffer to grow.
		remain := p.counterpart.buf.Cap() - p.counterpart.buf.Len()

		if canWrite := min(len(b), remain); canWrite > 0 {
			// If counterpart's buffer was empty, and its read was waiting,
			// We signal them to start reading. Since we hold its read lock, read will start after write.
			p.counterpart.notifyRead()

			p.counterpart.buf.Write(b[:canWrite])
			b = b[canWrite:]
			nn += canWrite

			p.counterpart.in.L.Unlock()
			continue
		}

		p.counterpart.in.L.Unlock()
		p.out.Wait()
	}

	return nn, nil
}

func (p *bufferedPipe) closed() bool {
	p.closedMu.Lock()
	defer p.closedMu.Unlock()

	return p._closed
}

// notifyRead's caller already holds lock. So no need to hold it in here.
func (p *bufferedPipe) notifyRead()  { p.in.Signal() }
func (p *bufferedPipe) notifyWrite() { p.out.Signal() }

func (p *bufferedPipe) SetReadDeadLine(t time.Time)  { p.rdeadLine.set(t, func() { p.in.Signal() }) }
func (p *bufferedPipe) SetWriteDeadLine(t time.Time) { p.wdeadLine.set(t, func() { p.out.Signal() }) }

func newDeadLine(clock clock.Clock) *deadline { return &deadline{clock: clock} }

type deadline struct {
	clock clock.Clock
	m     sync.Mutex

	timer *clock.Timer
	t     time.Time
}

func (d *deadline) set(t time.Time, onExceed func()) {
	d.m.Lock()
	defer d.m.Unlock()

	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}

	d.t = t

	if !t.IsZero() {
		d.timer = d.clock.AfterFunc(d.clock.Until(t), func() {
			d.m.Lock()
			defer d.m.Unlock()
			onExceed()
		})
	}
}

func (d *deadline) exceeded() bool {
	d.m.Lock()
	defer d.m.Unlock()

	if d.t.IsZero() {
		return false
	}

	return d.clock.Until(d.t) <= 0
}

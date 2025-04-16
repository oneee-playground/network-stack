package pipe

import (
	"context"
	"network-stack/transport"
	"sync"

	"github.com/benbjohnson/clock"
)

type pipeRequest struct {
	conn     *pipe
	accepted chan struct{}
}

type PipeTransport struct {
	listeners map[transport.Addr]*pipeListener
	clock     clock.Clock

	mu sync.Mutex
}

func NewPipeTransport(clock clock.Clock) *PipeTransport {
	return &PipeTransport{
		listeners: make(map[transport.Addr]*pipeListener),
		clock:     clock,
	}
}

var _ transport.ConnDialer = (*PipeTransport)(nil)

func (pt *PipeTransport) Dial(ctx context.Context, addr transport.Addr) (transport.Conn, error) {
	pt.mu.Lock()
	listener, ok := pt.listeners[addr]
	pt.mu.Unlock()

	if !ok {
		return nil, transport.ErrNetUnreachable
	}

	p1, p2 := NewPair("dialer", addr.(Addr).Name, pt.clock)

	req := pipeRequest{
		conn:     p2,
		accepted: make(chan struct{}, 1),
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-listener.closed:
		return nil, transport.ErrConnRefused
	case listener.requests <- req:
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case _, accepted := <-req.accepted:
		if !accepted {
			return nil, transport.ErrConnRefused
		}
	}

	return p1, nil
}

func (pt *PipeTransport) Listen(addr Addr) (*pipeListener, error) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if _, ok := pt.listeners[addr]; ok {
		return nil, transport.ErrAddrAlreadyInUse
	}

	pl := &pipeListener{
		addr:     addr,
		requests: make(chan pipeRequest),
	}
	pt.listeners[addr] = pl

	return pl, nil
}

type pipeListener struct {
	addr transport.Addr

	transport *PipeTransport

	requests chan pipeRequest
	closed   chan struct{}

	mu sync.Mutex
}

var _ transport.ConnListener = (*pipeListener)(nil)

func (pl *pipeListener) Accept(ctx context.Context) (transport.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case request, ok := <-pl.requests:
		if !ok {
			return nil, transport.ErrConnListenerClosed
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case request.accepted <- struct{}{}:
		}

		return request.conn, nil
	}
}

func (pl *pipeListener) Close() error {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	select {
	case <-pl.closed:
		return transport.ErrConnListenerClosed
	default:
	}

	close(pl.closed)

	for range len(pl.requests) {
		req := <-pl.requests
		close(req.accepted)
	}
	close(pl.requests)

	pl.transport.mu.Lock()
	delete(pl.transport.listeners, pl.addr)
	pl.transport.mu.Unlock()

	return nil
}

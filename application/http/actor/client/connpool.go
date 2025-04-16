package client

import (
	"context"
	"network-stack/application/http"
	"network-stack/lib/ds/queue"
	"network-stack/transport"
	"sync"
	"time"

	"github.com/benbjohnson/clock"
)

type connPool struct {
	connsPerAddr map[transport.Addr]*connBlock
	connsMu      sync.Mutex

	idleWaiters map[transport.Addr]queue.Queue[*connRequest]
	idleWaitMu  sync.Mutex

	dialWaiters map[transport.Addr]queue.Queue[*connRequest]
	dialWaitMu  sync.Mutex

	dialFunc func(ctx context.Context, block *connBlock, req *connRequest)

	idleTimeout time.Duration
	clock       clock.Clock
}

type connBlock struct {
	mu    sync.Mutex
	conns []*conn
}

func (block *connBlock) len() uint { return uint(len(block.conns)) }

type connCriteria struct {
	addr transport.Addr

	pipeline bool
	ver      http.Version
}

type connRequest struct {
	ctx context.Context

	criteria connCriteria

	mu        sync.Mutex
	satisfied bool
	result    chan connResult
}

func (r *connRequest) provide(conn *conn, err error) (success bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.satisfied {
		return false
	}

	r.result <- connResult{conn: conn, err: err}
	r.satisfied = true

	return true
}

func (r *connRequest) shouldSkip() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-r.ctx.Done():
		return true
	default:
	}

	return r.satisfied
}

type connResult struct {
	conn *conn
	err  error
}

func (c *connCriteria) matches(conn *conn) bool {
	if conn.closing || conn.seats == 0 || conn.isAlt {
		return false
	}

	if c.addr != conn.addr {
		return false
	}

	if c.ver != conn.version || c.pipeline != conn.pipeline {
		return false
	}

	return true
}

func (pool *connPool) getBlock(addr transport.Addr) (block *connBlock, release func()) {
	pool.connsMu.Lock()
	defer pool.connsMu.Unlock()

	block, ok := pool.connsPerAddr[addr]
	if !ok {
		block = &connBlock{conns: make([]*conn, 0)}
		pool.connsPerAddr[addr] = block
	}

	// clean closed conns

	block.mu.Lock()
	return block, func() { block.mu.Unlock() }
}

func (pool *connPool) request(r *connRequest) (found bool) {
	block, release := pool.getBlock(r.criteria.addr)
	defer release()

	for idx := int(block.len()) - 1; idx >= 0; idx-- {
		conn := block.conns[idx]
		conn.mu.Lock()

		if conn.idleTimeoutExceeded(pool.idleTimeout) {
			conn.closeLocked(nil)
		}

		if conn.closing {
			// Remove idle conneection.
			conn.actuallyClose()

			block.conns = append(block.conns[:idx], block.conns[idx+1:]...)

			pool.dialWaitMu.Lock()
			if waiters, ok := pool.dialWaiters[conn.addr]; ok {
				// If there are requests waiting for dial, do dial.
				for waiters.Len() > 0 {
					req, _ := waiters.Dequeue()

					if !req.shouldSkip() {
						pool.dialFunc(r.ctx, block, req)
						break
					}
				}
			}
			pool.dialWaitMu.Unlock()

			conn.mu.Unlock()
			continue
		}

		// If matching conn exists, use it immediately.
		if r.criteria.matches(conn) {
			conn.occupyLocked()
			// Don't need to check if it suceeded.
			r.provide(conn, nil)
			return true
		}

		conn.mu.Unlock()
	}

	if block.len() == 0 {
		return false
	}

	pool.idleWaitMu.Lock()
	defer pool.idleWaitMu.Unlock()

	waiters, ok := pool.idleWaiters[r.criteria.addr]
	if !ok {
		// Create a new queue if not exists.
		waiters = queue.NewNaive[*connRequest](0)
		pool.idleWaiters[r.criteria.addr] = waiters
	}

	waiters.Enqueue(r)

	return false
}

func (pool *connPool) enqueueDial(req *connRequest) {
	pool.dialWaitMu.Lock()
	defer pool.dialWaitMu.Unlock()

	waiters, ok := pool.dialWaiters[req.criteria.addr]
	if !ok {
		waiters = queue.NewNaive[*connRequest](0)
		pool.dialWaiters[req.criteria.addr] = waiters
	}

	waiters.Enqueue(req)
}

func (pool *connPool) put(conn *conn) {
	conn.mu.Lock()
	conn.unoccupyLocked()

	requestFound := false

	pool.idleWaitMu.Lock()
	if waiters, ok := pool.idleWaiters[conn.addr]; ok {
		var enqueLater []*connRequest

		for waiters.Len() > 0 {
			req, _ := waiters.Dequeue()
			if req.shouldSkip() {
				continue
			}

			if req.criteria.matches(conn) {
				conn.occupyLocked()

				if success := req.provide(conn, nil); success {
					requestFound = true
					break
				}

				conn.unoccupyLocked()
			}

			enqueLater = append(enqueLater, req)
		}

		// Restore requests. Yeah this looks inefficient.
		for _, req := range enqueLater {
			waiters.Enqueue(req)
		}

		if waiters.Len() == 0 {
			delete(pool.idleWaiters, conn.addr)
		}
	}
	pool.idleWaitMu.Unlock()

	if !requestFound {
		conn.mu.Unlock()
	}
}

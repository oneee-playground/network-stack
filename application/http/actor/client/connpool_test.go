package client

import (
	"context"
	"errors"
	"network-stack/application/http"
	"network-stack/lib/ds/queue"
	"network-stack/transport"
	"network-stack/transport/pipe"
	"sync"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestConnCriteria(t *testing.T) {
	criteria := connCriteria{
		addr:     newTransportAddr(),
		pipeline: false,
		ver:      http.Version{1, 1},
	}

	testcases := []struct {
		desc    string
		conn    *conn
		matches bool
	}{
		{
			desc: "matches",
			conn: &conn{
				seats:    1,
				addr:     criteria.addr,
				version:  criteria.ver,
				pipeline: criteria.pipeline,
			},
			matches: true,
		},
		{
			desc:    "closing conn",
			conn:    &conn{closing: true},
			matches: false,
		},
		{
			desc:    "no seats",
			conn:    &conn{seats: 0},
			matches: false,
		},
		{
			desc:    "controlled by alt handler",
			conn:    &conn{isAlt: true},
			matches: false,
		},
		{
			desc:    "wrong addr",
			conn:    &conn{addr: nil},
			matches: false,
		},
		{
			desc:    "wrong version",
			conn:    &conn{version: http.Version{0, 0}},
			matches: false,
		},
		{
			desc:    "wrong pipeline",
			conn:    &conn{pipeline: !criteria.pipeline},
			matches: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			assert.Equal(t, tc.matches, criteria.matches(tc.conn))
		})
	}
}

type ConnRequestTestSuite struct {
	suite.Suite

	req      *connRequest
	criteria connCriteria
}

func TestConnRequestTestSuite(t *testing.T) {
	suite.Run(t, new(ConnRequestTestSuite))
}

func (s *ConnRequestTestSuite) SetupTest() {
	s.criteria = connCriteria{
		addr:     newTransportAddr(),
		pipeline: false,
		ver:      http.Version{1, 1},
	}
	s.req = &connRequest{
		ctx:      context.Background(),
		criteria: s.criteria,
		result:   make(chan connResult, 1),
	}
}

func (s *ConnRequestTestSuite) TestShouldSkip() {
	s.False(s.req.shouldSkip())

	s.req.satisfied = true
	s.True(s.req.shouldSkip())
	s.req.satisfied = false

	ctx, cancel := context.WithCancel(context.Background())
	s.req.ctx = ctx
	cancel()
	s.True(s.req.shouldSkip())
}

func (s *ConnRequestTestSuite) TestProvide() {
	conn := &conn{}
	s.True(s.req.provide(conn, nil))
	s.Equal(conn, (<-s.req.result).conn)
	s.True(s.req.satisfied)

	s.req.satisfied = false
	err := errors.New("hehe err")
	s.True(s.req.provide(nil, err))
	s.Equal(err, (<-s.req.result).err)
	s.True(s.req.satisfied)

	s.False(s.req.provide(nil, nil))
}

type ConnPoolTestSuite struct {
	suite.Suite

	pool  *connPool
	clock *clock.Mock

	req      *connRequest
	criteria connCriteria
}

func TestConnPoolTestSuite(t *testing.T) {
	suite.Run(t, new(ConnPoolTestSuite))
}

func (s *ConnPoolTestSuite) SetupTest() {
	s.clock = clock.NewMock()
	s.pool = &connPool{
		connsPerAddr: make(map[transport.Addr]*connBlock),
		idleWaiters:  make(map[transport.Addr]queue.Queue[*connRequest]),
		dialWaiters:  make(map[transport.Addr]queue.Queue[*connRequest]),
		clock:        s.clock,
		dialFunc:     func(ctx context.Context, block *connBlock, req *connRequest) {},
	}
	s.criteria = connCriteria{
		addr:     newTransportAddr(),
		pipeline: false,
		ver:      http.Version{1, 1},
	}
	s.req = &connRequest{
		ctx:      context.Background(),
		criteria: s.criteria,
		result:   make(chan connResult, 1),
	}
}

func (s *ConnPoolTestSuite) TestGetBlock() {
	addr := newTransportAddr()

	// Race
	var block1, block2 *connBlock
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		block, release := s.pool.getBlock(addr)
		block1 = block
		release()
	}()
	go func() {
		defer wg.Done()
		block, release := s.pool.getBlock(addr)
		block2 = block
		release()
	}()
	wg.Wait()
	s.Equal(block1, block2)
	s.Equal(block1, s.pool.connsPerAddr[addr])
}

func (s *ConnPoolTestSuite) TestRequest() {
	c := &conn{
		seats:    1,
		addr:     s.criteria.addr,
		version:  s.criteria.ver,
		pipeline: s.criteria.pipeline,
	}

	block := &connBlock{conns: []*conn{c}}

	s.pool.connsPerAddr = map[transport.Addr]*connBlock{s.criteria.addr: block}

	go func() {
		s.True(s.pool.request(s.req))
	}()

	conn := (<-s.req.result).conn
	s.Equal(c, conn)
	s.Zero(c.seats)
	conn.mu.Unlock()
}

func (s *ConnPoolTestSuite) TestRequestBlockEmpty() {
	s.False(s.pool.request(s.req))

	waiters, ok := s.pool.idleWaiters[s.criteria.addr]
	s.Require().False(ok)
	s.Require().Nil(waiters)
}

func (s *ConnPoolTestSuite) TestRequestBlockNotEmpty() {
	block := &connBlock{conns: []*conn{{seats: 0}}}

	s.pool.connsPerAddr = map[transport.Addr]*connBlock{s.criteria.addr: block}

	s.False(s.pool.request(s.req))

	waiters, ok := s.pool.idleWaiters[s.criteria.addr]
	s.Require().True(ok)
	s.Require().NotNil(waiters)

	s.Require().Equal(uint(1), waiters.Len())
	got, err := waiters.Dequeue()
	s.NoError(err)
	s.Equal(s.req, got)
}

func (s *ConnPoolTestSuite) TestRequestRemoveClosedConns() {
	timeout := 10 * time.Millisecond

	c1, _ := pipe.Pipe("", "", nil)
	c2, _ := pipe.Pipe("", "", nil)

	idleConn := &conn{
		con:       c1,
		idleAt:    s.clock.Now().Add(-timeout),
		clock:     s.clock,
		ongoings:  queue.NewCircular[*roundtripSession](0),
		writePipe: make(chan *roundtripSession),
	}
	closedConn := &conn{
		con:       c2,
		closing:   true,
		clock:     s.clock,
		ongoings:  queue.NewCircular[*roundtripSession](0),
		writePipe: make(chan *roundtripSession),
	}

	block := &connBlock{conns: []*conn{idleConn, closedConn}}

	s.pool.connsPerAddr = map[transport.Addr]*connBlock{s.criteria.addr: block}

	s.False(s.pool.request(s.req))

	s.Zero(block.len())
	s.True(idleConn.closing)
	s.True(closedConn.closing)

	_, err := c1.Read(nil)
	s.ErrorIs(err, transport.ErrConnClosed)
	_, err = c2.Read(nil)
	s.ErrorIs(err, transport.ErrConnClosed)
}

func (s *ConnPoolTestSuite) TestRequestRemoveClosedConnsNewDial() {
	c1, _ := pipe.Pipe("", "", nil)

	closedConn := &conn{
		con:       c1,
		closing:   true,
		clock:     s.clock,
		ongoings:  queue.NewCircular[*roundtripSession](0),
		writePipe: make(chan *roundtripSession),
	}

	block := &connBlock{conns: []*conn{closedConn}}

	s.pool.connsPerAddr = map[transport.Addr]*connBlock{s.criteria.addr: block}

	s.pool.dialFunc = func(ctx context.Context, gotBlock *connBlock, req *connRequest) {
		s.Equal(block, gotBlock)
		s.Equal(s.req, req)
	}

	waiters := queue.NewNaive[*connRequest](1)
	waiters.Enqueue(s.req)
	s.pool.dialWaiters[s.criteria.addr] = waiters

	s.False(s.pool.request(s.req))

	s.Zero(block.len())

	_, err := c1.Read(nil)
	s.ErrorIs(err, transport.ErrConnClosed)
}

func (s *ConnPoolTestSuite) TestEnqueueDial() {
	req := &connRequest{criteria: connCriteria{addr: nil}}
	s.pool.enqueueDial(req)

	waiters, ok := s.pool.dialWaiters[nil]
	s.Require().True(ok)
	s.Require().NotNil(waiters)

	s.Require().Equal(uint(1), waiters.Len())
	got, err := waiters.Dequeue()
	s.NoError(err)
	s.Equal(req, got)
}

func (s *ConnPoolTestSuite) TestPut() {
	conn := &conn{seats: 0, maxSeats: 1, clock: s.clock}

	s.pool.put(conn)

	s.Equal(uint(1), conn.seats)
	s.Equal(s.clock.Now(), conn.idleAt)
}

func (s *ConnPoolTestSuite) TestPutIdleWaiters() {
	c := &conn{
		seats:    0,
		maxSeats: 1,
		addr:     s.criteria.addr,
		version:  s.criteria.ver,
		pipeline: s.criteria.pipeline,
		clock:    s.clock,
	}

	waiters := queue.NewNaive[*connRequest](1)
	waiters.Enqueue(s.req)
	s.pool.idleWaiters[s.criteria.addr] = waiters

	go func() {
		s.pool.put(c)
	}()
	conn := (<-s.req.result).conn
	s.Equal(c, conn)
	s.Zero(c.seats)
	conn.mu.Unlock()
}

func newTransportAddr() transport.Addr {
	p1, _ := pipe.Pipe("a", "b", nil) // just to use addr.
	return p1.LocalAddr()
}

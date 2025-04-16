package client

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"network-stack/application/http"
	"network-stack/application/http/actor/common"
	"network-stack/application/http/semantic"
	"network-stack/application/http/semantic/status"
	"network-stack/application/util/domain"
	"network-stack/application/util/uri"
	iolib "network-stack/lib/io"
	"network-stack/lib/pointer"
	"network-stack/network/ip"
	ipv4 "network-stack/network/ip/v4"
	"network-stack/transport"
	"network-stack/transport/pipe"
	"sync"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/suite"
)

type stubIP struct {
	raw []byte
	str string
	ver uint
}

func (s stubIP) Raw() []byte    { return bytes.Clone(s.raw) }
func (s stubIP) String() string { return s.str }
func (s stubIP) Version() uint  { return s.ver }

type ClientTestSuite struct {
	suite.Suite

	transport *pipe.PipeTransport
	lookuper  domain.Lookuper
	logger    *slog.Logger

	stubIP      stubIP
	combineAddr pipe.Addr

	client *Client

	clock *clock.Mock
}

func TestClientTestSuite(t *testing.T) {
	suite.Run(t, new(ClientTestSuite))
}

func (s *ClientTestSuite) SetupTest() {
	s.clock = clock.NewMock()
	s.stubIP = stubIP{str: "this is actually stub"}
	s.combineAddr = pipe.Addr{Name: "hello"}

	s.transport = pipe.NewPipeTransport(s.clock)
	s.lookuper = domain.NewMapLookuper(map[string][]ip.Addr{"localhost": {s.stubIP}})
	s.logger = slog.New(slog.DiscardHandler)

	s.client = New(s.transport, s.lookuper, s.logger, s.clock, Options{})
	s.client.combineAddr = func(net ip.Addr, port uint16) transport.Addr {
		return s.combineAddr
	}
}

func (s *ClientTestSuite) TestSend() {
	var wg sync.WaitGroup
	n := uint(5)

	request := semantic.Request{
		Method: semantic.MethodGet,
		URI: uri.URI{
			Scheme:    "http",
			Authority: &uri.Authority{Host: "localhost"},
			Path:      "/",
		},
		Message: semantic.Message{
			Version: http.Version{1, 1},
		},
	}

	response := semantic.Response{
		Status: status.OK,
		Message: semantic.Message{
			Version:       request.Version,
			Body:          bytes.NewBuffer(nil),
			ContentLength: pointer.To(uint(0)),
		},
	}
	response.EnsureHeadersSet()

	wg.Add(int(n))
	<-s.doListen(n, func(conn transport.Conn) {
		dec := http.NewRequestDecoder(iolib.NewUntilReader(conn), http.DecodeOptions{})
		enc := http.NewResponseEncoder(conn, http.EncodeOptions{})

		response := response.Clone()
		response.Body = bytes.NewBuffer(nil)

		go func() {
			defer wg.Done()
			var req http.Request
			s.Require().NoError(dec.Decode(&req))

			raw := request.RawRequest()
			raw.Body = nil
			req.Body = nil

			s.Require().Equal(raw, req)

			s.Require().NoError(enc.Encode(response.RawResponse()))
		}()
	})

	var m sync.Mutex
	releases := []func() error{}

	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, release, err := s.client.Send(context.Background(), pointer.To(request.Clone()))
			s.Require().NoError(err)

			expected := response.Clone()
			expected.Body = nil
			body := got.Body
			got.Body = nil

			s.Equal(&expected, got)

			got.Body = body

			_, err = io.ReadAll(got.Body)
			s.Require().NoError(err)

			m.Lock()
			releases = append(releases, release)
			m.Unlock()
		}()
	}
	wg.Wait()

	for _, release := range releases {
		s.NoError(release())
	}
}

func (s *ClientTestSuite) TestUpgrade() {
	var wg sync.WaitGroup
	defer wg.Wait()

	request := semantic.Request{ // It actually has to be upgrade requeest. its TODO: I guess.
		Method: semantic.MethodGet,
		URI: uri.URI{
			Scheme:    "http",
			Authority: &uri.Authority{Host: "localhost"},
			Path:      "/",
		},
		Message: semantic.Message{
			Version: http.Version{1, 1},
		},
	}

	response := semantic.Response{ // This too have to be 101 switching protocol. later.
		Status: status.OK,
		Message: semantic.Message{
			Version:       request.Version,
			Body:          bytes.NewBuffer(nil),
			ContentLength: pointer.To(uint(0)),
		},
	}
	response.EnsureHeadersSet()

	helloWorld := "Hello World!"

	wg.Add(1)
	<-s.doListen(1, func(conn transport.Conn) {
		defer wg.Done()
		r, w := iolib.NewUntilReader(conn), conn
		dec := http.NewRequestDecoder(r, http.DecodeOptions{})
		enc := http.NewResponseEncoder(w, http.EncodeOptions{})

		response := response.Clone()
		response.Body = bytes.NewBuffer(nil)

		var req http.Request
		s.Require().NoError(dec.Decode(&req))

		raw := request.RawRequest()
		raw.Body = nil
		req.Body = nil

		s.Equal(raw, req)

		s.NoError(enc.Encode(response.RawResponse()))

		buf := make([]byte, len(helloWorld))
		_, err := r.Read(buf)
		s.NoError(err)
		s.Equal(helloWorld, string(buf))
	})

	s.Require().NoError(s.client.Upgrade(
		context.Background(),
		pointer.To(request.Clone()),
		func(res *semantic.Response) (common.AltHandler, error) {
			expected := response.Clone()
			expected.Body = nil
			body := res.Body
			res.Body = nil

			s.Equal(&expected, res)

			res.Body = body

			return func(ctx context.Context, conn transport.Conn) error {
				_, err := conn.Write([]byte(helloWorld))
				s.NoError(err)
				return nil
			}, nil
		},
	))

}

func (s *ClientTestSuite) TestConvertToAddr() {
	authority := uri.Authority{
		Host: ipv4.Addr{1, 1, 1, 1}.String(),
		Port: pointer.To(uint16(10)),
	}

	s.client.combineAddr = func(net ip.Addr, port uint16) transport.Addr {
		s.Equal(net, ipv4.Addr{1, 1, 1, 1})
		s.Equal(port, uint16(10))
		return s.combineAddr
	}

	addr, err := s.client.convertToAddr(context.Background(), "http", authority)
	s.Require().NoError(err)
	s.Equal(s.combineAddr, addr)
}

func (s *ClientTestSuite) TestConvertToAddrDefaultPort() {
	authority := uri.Authority{
		Host: ipv4.Addr{1, 1, 1, 1}.String(),
	}

	s.client.combineAddr = func(net ip.Addr, port uint16) transport.Addr {
		s.Equal(net, ipv4.Addr{1, 1, 1, 1})
		s.Equal(port, uint16(80))
		return s.combineAddr
	}

	addr, err := s.client.convertToAddr(context.Background(), "http", authority)
	s.Require().NoError(err)
	s.Equal(s.combineAddr, addr)
}

func (s *ClientTestSuite) TestConvertToAddrHostLookup() {
	authority := uri.Authority{
		Host: "localhost",
		Port: pointer.To(uint16(10)),
	}

	s.client.combineAddr = func(net ip.Addr, port uint16) transport.Addr {
		s.Equal(net, s.stubIP)
		s.Equal(port, uint16(10))
		return s.combineAddr
	}

	addr, err := s.client.convertToAddr(context.Background(), "http", authority)
	s.Require().NoError(err)
	s.Equal(s.combineAddr, addr)
}

func (s *ClientTestSuite) TestGetConn() {
	s.client.connPool.idleTimeout = time.Second

	<-s.doListen(3, func(conn transport.Conn) {
		s.Equal(pipe.Addr{Name: "dialer"}, conn.RemoteAddr())
	})

	ver := http.Version{1, 1}
	conn1, release, err := s.client.getConn(context.Background(), ver, s.combineAddr)
	s.Require().NoError(err)
	release()

	s.client.connPool.put(conn1)

	conn2, release, err := s.client.getConn(context.Background(), ver, s.combineAddr)
	s.Require().NoError(err)
	release()

	conn3, release, err := s.client.getConn(context.Background(), ver, s.combineAddr)
	s.Require().NoError(err)
	release()

	conn2.mu.Lock()
	conn3.mu.Lock()
	defer conn2.mu.Unlock()
	defer conn3.mu.Unlock()
	s.Equal(conn1, conn2)
	s.NotEqual(conn2, conn3)
}

func (s *ClientTestSuite) TestDialNewConnMaxConns() {
	// Only test edge case since normal case test would be same as startDialForBlock().
	s.client.opts.Conn.MaxOpenConnsPerHost = 1

	ctx := context.Background()
	block, release := s.client.connPool.getBlock(s.combineAddr)
	block.conns = make([]*conn, 1) // length 1
	release()

	req := &connRequest{
		ctx: ctx,
		criteria: connCriteria{
			addr: s.combineAddr,
			ver:  http.Version{1, 1},
		},
		result: make(chan connResult),
	}

	s.client.dialNewConn(ctx, req)

	s.Require().Len(block.conns, 1)

	waiters, ok := s.client.connPool.dialWaiters[s.combineAddr]
	s.Require().True(ok)
	s.Require().NotNil(waiters)

	s.Require().Equal(uint(1), waiters.Len())
	got, _ := waiters.Dequeue()
	s.Equal(req, got)
}

func (s *ClientTestSuite) TestStartDialForBlockError() {
	ctx := context.Background()
	block := &connBlock{conns: make([]*conn, 0)}

	req := &connRequest{
		ctx: ctx,
		criteria: connCriteria{
			addr: s.combineAddr,
			ver:  http.Version{1, 1},
		},
		result: make(chan connResult),
	}

	s.client.startDialForBlock(ctx, block, req)

	s.Require().Len(block.conns, 1)

	result := <-req.result
	s.Require().ErrorIs(result.err, transport.ErrNetUnreachable)
	s.Require().True(block.conns[0].closing)
}

func (s *ClientTestSuite) TestStartDialForBlock() {
	<-s.doListen(1, func(conn transport.Conn) {
		s.Equal(pipe.Addr{Name: "dialer"}, conn.RemoteAddr())
	})

	ctx := context.Background()
	block := &connBlock{conns: make([]*conn, 0)}

	req := &connRequest{
		ctx: ctx,
		criteria: connCriteria{
			addr: s.combineAddr,
			ver:  http.Version{1, 1},
		},
		result: make(chan connResult),
	}

	s.client.startDialForBlock(ctx, block, req)

	s.Require().Len(block.conns, 1)

	result := <-req.result
	s.Require().NoError(result.err)

	s.Equal(uint(0), result.conn.seats)
	s.Equal(s.combineAddr, result.conn.addr)
	result.conn.mu.Unlock()

	s.Eventually(
		func() bool {
			result.conn.mu.Lock()
			defer result.conn.mu.Unlock()
			return result.conn.seats == 0
		},
		time.Second, 10*time.Millisecond,
	)
}

func (s *ClientTestSuite) TestDial() {
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(1)
	<-s.doListen(1, func(conn transport.Conn) {
		defer wg.Done()
		s.Equal(pipe.Addr{Name: "dialer"}, conn.RemoteAddr())
	})

	ctx := context.Background()
	criteria := connCriteria{addr: s.combineAddr}
	dst := &conn{}

	s.Require().NoError(s.client.dial(ctx, criteria, dst))
	s.Equal(s.combineAddr, dst.con.RemoteAddr())
}

func (s *ClientTestSuite) doListen(
	acceptN uint,
	afterConn func(conn transport.Conn),
) chan struct{} {
	done := make(chan struct{})
	go func() {
		lis, err := s.transport.Listen(s.combineAddr)
		s.Require().NoError(err)

		done <- struct{}{}
		for range acceptN {
			conn, err := lis.Accept(context.Background())
			s.Require().NoError(err)
			afterConn(conn)
		}
	}()
	return done
}

package client

import (
	"context"
	"io"
	"log/slog"
	"network-stack/application/http"
	"network-stack/application/http/actor/common"
	"network-stack/application/http/semantic"
	"network-stack/application/http/transfer"
	"network-stack/application/util/domain"
	"network-stack/application/util/uri"
	"network-stack/lib/ds/queue"
	iolib "network-stack/lib/io"
	"network-stack/lib/types/pointer"
	"network-stack/network/ip"
	ipv4 "network-stack/network/ip/v4"
	ipv6 "network-stack/network/ip/v6"
	"network-stack/transport"
	"network-stack/transport/tcp"

	"github.com/benbjohnson/clock"
	"github.com/pkg/errors"
)

type Client struct {
	connPool *connPool

	opts Options

	logger *slog.Logger
	clock  clock.Clock

	transfer   *transfer.CodingApplier
	lookuper   domain.Lookuper
	connDialer transport.ConnDialer

	combineAddr CombineAddrFunc
}

type CombineAddrFunc func(net ip.Addr, port uint16) transport.Addr

func New(
	d transport.ConnDialer,
	lookuper domain.Lookuper,
	logger *slog.Logger,
	clock clock.Clock,
	opts Options,
) *Client {
	client := &Client{
		connDialer: d,
		lookuper:   lookuper,
		logger:     logger,
		opts:       opts,
		clock:      clock,
	}

	client.connPool = &connPool{
		connsPerAddr: make(map[transport.Addr]*connBlock),
		idleWaiters:  make(map[transport.Addr]queue.Queue[*connRequest]),
		dialWaiters:  make(map[transport.Addr]queue.Queue[*connRequest]),
		idleTimeout:  client.opts.Timeout.IdleTimeout,
		clock:        client.clock,
		dialFunc:     client.startDialForBlock,
	}

	client.combineAddr = func(net ip.Addr, port uint16) transport.Addr {
		return tcp.NewAddr(net, port)
	}

	client.transfer = transfer.NewCodingApplier(opts.ExtraTransferCoders)

	return client
}

func (c *Client) Send(ctx context.Context, request *semantic.Request) (_ *semantic.Response, release func() error, _ error) {
	if err := c.validateRequest(request); err != nil {
		return nil, nil, errors.Wrap(err, "canonizing request")
	}

	addr, err := c.convertToAddr(ctx, request.URI.Scheme, *request.URI.Authority)
	if err != nil {
		return nil, nil, errors.Wrap(err, "converting authority to addr")
	}

	conn, unlockConn, err := c.getConn(ctx, request.Version, addr)
	if err != nil {
		return nil, nil, errors.Wrap(err, "getting connection")
	}
	unlockConn()

	res, err := conn.roundtrip(ctx, request)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error while request-response roundtrip")
	}

	release = func() error {
		_, err := io.Copy(io.Discard, res.Body)
		if err != nil {
			err = errors.Wrap(err, "reading body to discard all")
			conn.close(err)
			return err
		}

		c.connPool.put(conn)
		return nil
	}

	return res, release, nil
}

func (c *Client) Upgrade(
	ctx context.Context, request *semantic.Request,
	newHandle func(res *semantic.Response) (common.AltHandler, error),
) error {
	if err := c.validateRequest(request); err != nil {
		return errors.Wrap(err, "canonizing request")
	}

	addr, err := c.convertToAddr(ctx, request.URI.Scheme, *request.URI.Authority)
	if err != nil {
		return errors.Wrap(err, "converting authority to addr")
	}

	conn, unlockConn, err := c.getConn(ctx, request.Version, addr)
	if err != nil {
		return errors.Wrap(err, "getting connection")
	}
	// Block further requests on this connection.
	conn.isAlt = true
	unlockConn()

	res, err := conn.roundtrip(ctx, request)
	if err != nil {
		return errors.Wrap(err, "error while request-response roundtrip")
	}

	handle, err := newHandle(res)
	if err != nil {
		return errors.Wrap(err, "error while making new handle for response")
	}

	if _, err := io.Copy(io.Discard, res.Body); err != nil {
		// Probably there won't be no body in this response.
		return errors.Wrap(err, "reading body to discard all")
	}

	wrapped := common.NewHTTPWrappedConn(conn.con, conn.r, conn.w)

	err = common.HandleAlt(ctx, wrapped, handle)
	conn.close(err)

	return err
}

func (c *Client) validateRequest(request *semantic.Request) error {
	// TODO: need to fill this func up.
	_ = request
	return nil
}

func (c *Client) convertToAddr(ctx context.Context, scheme string, authority uri.Authority) (transport.Addr, error) {
	if authority.Port == nil {
		authority.Port = pointer.To(semantic.DefaultPort(scheme))
	}

	var ipAddrs []ip.Addr
	if addr, ok := parseIPAddr(authority.Host); ok {
		ipAddrs = []ip.Addr{addr}
	} else {
		// Host is a domain name. Resolve it to the ip address.
		result, err := c.lookuper.LookupIP(ctx, authority.Host)
		if err != nil {
			return nil, errors.Wrapf(err, "lookup for host(%s) failed", authority.Host)
		}

		ipAddrs = result
	}

	// Lets simply use the first address.
	// We might need to use func passed by caller.
	ipAddr := ipAddrs[0]

	return c.combineAddr(ipAddr, *authority.Port), nil
}

// Yeah this looks so similar to net/http/transport.go
func (c *Client) getConn(ctx context.Context, version http.Version, addr transport.Addr) (_ *conn, release func(), _ error) {
	req := &connRequest{
		ctx: ctx,
		criteria: connCriteria{
			addr:     addr,
			ver:      version,
			pipeline: c.opts.Pipeline.UsePipelining,
		},
		result: make(chan connResult, 1),
	}

	if found := c.connPool.request(req); !found {
		c.dialNewConn(ctx, req)
	}

	select {
	case result := <-req.result:
		if result.err != nil {
			return nil, nil, result.err
		}
		return result.conn, func() { result.conn.mu.Unlock() }, nil
	case <-ctx.Done():
		select {
		// This could happen if result is already provided.
		case result := <-req.result:
			if result.err != nil {
				return nil, nil, result.err
			}

			// put conn into pool.
			c.connPool.put(result.conn)
		default:
		}

		return nil, nil, ctx.Err()
	}
}

func (c *Client) dialNewConn(ctx context.Context, req *connRequest) {
	block, release := c.connPool.getBlock(req.criteria.addr)
	defer release()

	maxConnsPerHost := c.opts.Conn.MaxOpenConnsPerHost

	if maxConnsPerHost == 0 || block.len() < maxConnsPerHost {
		// We can dial immediately.
		c.startDialForBlock(ctx, block, req)
		return
	}

	// We even have to wait for dial.
	c.connPool.enqueueDial(req)
}

// startDialForBlock assumes block is locked.
func (c *Client) startDialForBlock(
	ctx context.Context, block *connBlock, req *connRequest,
) {
	// Create an empty conn struct for placeholder.
	conn := &conn{
		addr:     req.criteria.addr,
		version:  req.criteria.ver,
		pipeline: req.criteria.pipeline,
		con:      nil, // will be filled after actual dial.
		seats:    0,
		transfer: c.transfer,
		// TODO:
		logger: c.logger,
		clock:  c.clock,
	}

	block.conns = append(block.conns, conn)

	go func() {
		err := c.dial(ctx, req.criteria, conn)

		block.mu.Lock()
		defer block.mu.Unlock()

		if err != nil {
			// remove the conn from block.
			conn.closing = true

			req.provide(nil, err) // we don't care if it succeeds.
			return
		}

		// set seats.
		switch {
		case false:
			// Support v2.
		case req.criteria.pipeline:
			// Assume zero doesn't get provided.
			conn.seats = c.opts.Pipeline.MaxConcurrentRequest
		default:
			conn.seats = 1
		}

		// set essential fields.
		conn.ongoings = queue.NewCircular[*roundtripSession](conn.seats)
		conn.writePipe = make(chan *roundtripSession)
		conn.maxSeats = conn.seats
		conn.w = conn.con
		conn.r = iolib.NewUntilReader(conn.con)

		go conn.readLoop()
		go conn.writeLoop()

		conn.mu.Lock()
		conn.occupyLocked()

		if success := req.provide(conn, nil); !success {
			conn.unoccupyLocked()
			conn.mu.Unlock()
		}
	}()
}

func (c *Client) dial(ctx context.Context, criteria connCriteria, dstConn *conn) error {
	tConn, err := c.connDialer.Dial(ctx, criteria.addr)
	if err != nil {
		return err
	}

	dstConn.con = tConn

	return nil
}

func parseIPAddr(host string) (ip.Addr, bool) {
	if addr, err := ipv4.ParseAddr(host); err == nil {
		return addr, true
	}
	if addr, err := ipv6.ParseAddr(host); err == nil {
		return addr, true
	}
	return nil, false
}

package server

import (
	"context"
	"log/slog"
	"sync"

	"network-stack/application/http"
	"network-stack/application/http/transfer"
	iolib "network-stack/lib/io"
	"network-stack/transport"

	"github.com/benbjohnson/clock"
	"github.com/pkg/errors"
)

type Server struct {
	l transport.ConnListener

	closeListener func()
	wg            sync.WaitGroup

	logger *slog.Logger
	opts   Options

	handle  HandleFunc
	trasfer *transfer.CodingApplier
	clock   clock.Clock
}

func New(
	l transport.ConnListener,
	logger *slog.Logger,
	clock clock.Clock,
	handle HandleFunc,
	opts Options,
) *Server {
	s := &Server{
		l:       l,
		logger:  logger,
		opts:    opts,
		handle:  handle,
		clock:   clock,
		trasfer: transfer.NewCodingApplier(opts.ExtraTransferCoders),
	}

	return s
}

func (s *Server) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.closeListener = cancel
	go func() {
		connCtx, connCancel := context.WithCancel(context.Background())
		for {
			conn, err := s.acceptConn(ctx)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					s.logger.Error(
						"unexpected error when accepting connection",
						"error", err.Error(),
					)
				}
				connCancel()
				return
			}

			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				conn.start(connCtx)
			}()
		}
	}()
}

func (s *Server) acceptConn(ctx context.Context) (*conn, error) {
	con, err := s.l.Accept(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "listening for connection")
	}

	conn := &conn{
		con:      con,
		r:        iolib.NewUntilReader(con),
		w:        con,
		handle:   s.handle,
		opts:     s.opts,
		version:  http.Version{1, 1}, // temp.
		logger:   s.logger.With("conn", con.RemoteAddr()),
		transfer: s.trasfer,
		clock:    s.clock,
	}

	return conn, nil
}

func (s *Server) Close() error {
	s.closeListener()
	s.wg.Wait()
	return nil
}

package server

import (
	"context"
	"io"
	"network-stack/transport"
	"time"

	"github.com/pkg/errors"
)

type AltHandler func(ctx context.Context, conn transport.Conn) error

type httpWrappedConn struct {
	conn transport.Conn
	r    io.Reader
	w    io.Writer
}

var _ transport.Conn = (*httpWrappedConn)(nil)

func (h *httpWrappedConn) Close() error { return h.conn.Close() }

func (h *httpWrappedConn) LocalAddr() transport.Addr  { return h.conn.LocalAddr() }
func (h *httpWrappedConn) RemoteAddr() transport.Addr { return h.conn.RemoteAddr() }

func (h *httpWrappedConn) Read(p []byte) (n int, err error)  { return h.r.Read(p) }
func (h *httpWrappedConn) Write(p []byte) (n int, err error) { return h.w.Write(p) }

func (h *httpWrappedConn) SetReadDeadLine(t time.Time)  { h.conn.SetReadDeadLine(t) }
func (h *httpWrappedConn) SetWriteDeadLine(t time.Time) { h.conn.SetWriteDeadLine(t) }

func serveAltHandler(ctx context.Context, conn *httpWrappedConn, h AltHandler) (err error) {
	conn.SetReadDeadLine(time.Time{})
	conn.SetWriteDeadLine(time.Time{})

	defer func() {
		if e := recover(); e != nil {
			err = errors.Errorf("altHandler panicked: %s", e)
		}
	}()

	return h(ctx, conn)
}

package common

import (
	"context"
	"io"
	"network-stack/transport"
	"time"

	"github.com/pkg/errors"
)

type AltHandler func(ctx context.Context, conn transport.Conn) error

type HTTPWrappedConn struct {
	conn transport.Conn
	r    io.Reader
	w    io.Writer
}

func NewHTTPWrappedConn(conn transport.Conn, r io.Reader, w io.Writer) *HTTPWrappedConn {
	return &HTTPWrappedConn{
		conn: conn,
		r:    r,
		w:    w,
	}
}

var _ transport.Conn = (*HTTPWrappedConn)(nil)

func (h *HTTPWrappedConn) Close() error { return h.conn.Close() }

func (h *HTTPWrappedConn) LocalAddr() transport.Addr  { return h.conn.LocalAddr() }
func (h *HTTPWrappedConn) RemoteAddr() transport.Addr { return h.conn.RemoteAddr() }

func (h *HTTPWrappedConn) Read(p []byte) (n int, err error)  { return h.r.Read(p) }
func (h *HTTPWrappedConn) Write(p []byte) (n int, err error) { return h.w.Write(p) }

func (h *HTTPWrappedConn) SetReadDeadLine(t time.Time)  { h.conn.SetReadDeadLine(t) }
func (h *HTTPWrappedConn) SetWriteDeadLine(t time.Time) { h.conn.SetWriteDeadLine(t) }

func HandleAlt(ctx context.Context, conn *HTTPWrappedConn, h AltHandler) (err error) {
	conn.SetReadDeadLine(time.Time{})
	conn.SetWriteDeadLine(time.Time{})

	defer func() {
		if e := recover(); e != nil {
			err = errors.Errorf("altHandler panicked: %s", e)
		}
	}()

	return h(ctx, conn)
}

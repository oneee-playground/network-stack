package transport

import (
	"context"
	"errors"
	"time"
)

var (
	ErrConnClosed       = errors.New("connection is closed")
	ErrDeadLineExceeded = errors.New("deadline exceeded")
)

type Conn interface {
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error

	LocalAddr() Addr
	RemoteAddr() Addr

	SetReadDeadLine(t time.Time)
	SetWriteDeadLine(t time.Time)
}

// BufferedConn guarentees read/writes are internally buffered.
// Size of 0 implies that it doesn't know its internal buffer size.
type BufferedConn interface {
	Conn
	ReadBufSize() uint
	WriteBufSize() uint
}

var (
	ErrAddrAlreadyInUse   = errors.New("address already in use")
	ErrConnListenerClosed = errors.New("conn listener is closed")
)

type ConnListener interface {
	Accept(ctx context.Context) (Conn, error)
	Close() error
}

var (
	ErrConnRefused    = errors.New("connection refused")
	ErrNetUnreachable = errors.New("network is unreachable")
)

type ConnDialer interface {
	Dial(ctx context.Context, addr Addr) (Conn, error)
}

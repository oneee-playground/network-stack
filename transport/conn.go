package transport

import (
	"context"
	"errors"
	"time"
)

var (
	ErrConnClosed        = errors.New("connection is closed")
	ErrConnListnerClosed = errors.New("conn listener is closed")
	ErrDeadLineExceeded  = errors.New("deadline exceeded")
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

type ConnListener interface {
	Accept(ctx context.Context) (Conn, error)
	Close() error
}

type ConnDialer interface {
	Dial(ctx context.Context, addr Addr) (Conn, error)
}

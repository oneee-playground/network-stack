package transport

import (
	"context"
	"errors"
)

var (
	ErrConnClosed        = errors.New("connection is closed")
	ErrConnListnerClosed = errors.New("conn listener is closed")
)

type Conn interface {
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error
}

type ConnListener interface {
	Accept(ctx context.Context) (Conn, error)
	Close() error
}

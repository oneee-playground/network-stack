package conn

import (
	"network-stack/transport"
	"time"
)

type Conn struct {
	underlying transport.Conn
}

var _ transport.Conn = (*Conn)(nil)

func (conn *Conn) LocalAddr() transport.Addr {
	return conn.underlying.LocalAddr()
}

func (conn *Conn) RemoteAddr() transport.Addr {
	return conn.underlying.RemoteAddr()
}

func (conn *Conn) Close() error {
	return conn.underlying.Close()
}

func (conn *Conn) Read(p []byte) (n int, err error) {
	return conn.underlying.Read(p)
}

func (conn *Conn) Write(p []byte) (n int, err error) {
	return conn.underlying.Write(p)
}

func (conn *Conn) SetReadDeadLine(t time.Time) {
	conn.underlying.SetReadDeadLine(t)
}

func (conn *Conn) SetWriteDeadLine(t time.Time) {
	conn.underlying.SetWriteDeadLine(t)
}

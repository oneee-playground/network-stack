// Package tls imlements Transport Layer Security (TLS)
//
// NOTE: It only supports TLS 1.3
//
// Reference:
// - https://datatracker.ietf.org/doc/html/rfc8446
// - https://datatracker.ietf.org/doc/html/rfc6066
package tls

import (
	"network-stack/transport"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/pkg/errors"
)

// Unimplemented:
// - TLS 1.2 Compatibility.
// -  https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2.1
// - Post Handshake Auth
// - Extensions: OID filters.
// - 0-RTT.
// - Handshake Timeout

type RecordOptions struct {
	HandshakeTimeout time.Duration
	CloseTimeout     time.Duration
}

type ClientOptions struct {
	Record    RecordOptions
	Handshake HandshakeClientOptions
}

func NewClient(conn transport.BufferedConn, clock clock.Clock, opts ClientOptions) (*Conn, error) {
	tlsConn := &Conn{
		underlying:         conn,
		clock:              clock,
		closeTimeout:       opts.Record.CloseTimeout,
		isServer:           false,
		handshaking:        true,
		maxChunkSize:       maxRecordLen,
		in:                 newProtector(),
		out:                newProtector(),
		onNewSessionTicket: opts.Handshake.OnNewSessionTicket,
	}

	hs, err := newHandshakerClient(tlsConn, clock, opts.Handshake)
	if err != nil {
		return nil, errors.Wrap(err, "making handshaker")
	}

	tlsConn.session = hs.session

	if err := doHandshake(tlsConn, hs); err != nil {
		return nil, errors.Wrap(err, "handshake failed")
	}

	return tlsConn, nil
}

type ServerOptions struct {
	Record    RecordOptions
	Handshake HandshakeServerOptions
}

func NewServer(conn transport.BufferedConn, clock clock.Clock, opts ServerOptions) (*Conn, error) {
	tlsConn := &Conn{
		underlying:   conn,
		clock:        clock,
		isServer:     true,
		handshaking:  true,
		maxChunkSize: maxRecordLen,
		in:           newProtector(),
		out:          newProtector(),
	}

	hs, err := newHandshakerServer(tlsConn, clock, opts.Handshake)
	if err != nil {
		return nil, errors.Wrap(err, "making handshaker")
	}

	tlsConn.session = hs.session

	if err := doHandshake(tlsConn, hs); err != nil {
		return nil, errors.Wrap(err, "handshake failed")
	}

	return tlsConn, nil
}

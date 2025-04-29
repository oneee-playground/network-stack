// Package tls imlements Transport Layer Security (TLS)
//
// NOTE: It only supports TLS 1.3
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8446
package tls

import "context"

// Unimplemented:
//
// -  https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2.1

type HandshakeOptions struct {
	// Reference: https://datatracker.ietf.org/doc/html/rfc8446#appendix-D.4
	DisableCompatibilityMode bool

	RandomSource RandomGen
}

type RandomGen interface {
	Random() [32]byte
}

type handshaker interface {
	do(ctx context.Context) error

	exchangeKeys() error
}

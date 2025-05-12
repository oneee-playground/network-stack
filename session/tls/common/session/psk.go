package session

import (
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/internal/util"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.9
type PSKMode uint8

var _ util.VectorConv = PSKMode(0)

func (p PSKMode) Bytes() []byte {
	return []byte{byte(p)}
}

func (p PSKMode) FromBytes(b []byte) (out util.VectorConv, rest []byte, err error) {
	if len(b) < 1 {
		return nil, nil, util.ErrVectorShort
	}

	out = PSKMode(b[0])
	return out, b[1:], nil
}

const (
	PSKModePSK_KE     PSKMode = 0
	PSKModePSK_DHE_KE PSKMode = 1
)

type PSKType string

const (
	PSKTypeResumption PSKType = "res"
	PSKTypeExternal   PSKType = "ext"
)

type PreSharedKey struct {
	Type     PSKType
	Identity []byte

	ObfuscatedTicketAge uint32

	CipherSuite ciphersuite.Suite
}

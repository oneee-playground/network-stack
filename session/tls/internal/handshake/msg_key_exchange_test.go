package handshake

import (
	"testing"

	"network-stack/session/tls/common"
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/internal/handshake/extension"

	"github.com/stretchr/testify/assert"
)

func TestClientHello(t *testing.T) {
	input := &ClientHello{
		Version:            common.VersionTLS12,
		Random:             [32]byte{0x01, 0x02, 0x03, 0x04},
		SessionID:          []byte{0x05, 0x06},
		CipherSuites:       []ciphersuite.ID{},
		CompressionMethods: []byte{0x00},
		Extensions:         extension.ExtensionsFrom(),
	}

	testHandshake(t, input, &ClientHello{}, typeClientHello)
}

func TestServerHello(t *testing.T) {
	input := &ServerHello{
		Version:           common.VersionTLS12,
		Random:            [32]byte{0x07, 0x08, 0x09, 0x0A},
		SessionIDEcho:     []byte{0x0B, 0x0C},
		CipherSuite:       ciphersuite.ID{},
		CompressionMethod: 0x00,
		Extensions:        extension.ExtensionsFrom(),
	}

	testHandshake(t, input, &ServerHello{}, typeServerHello)
}

func TestServerHelloRetry(t *testing.T) {
	input := &ServerHello{
		Version:           common.VersionTLS12,
		SessionIDEcho:     []byte{},
		CipherSuite:       ciphersuite.ID{},
		CompressionMethod: 0x00,
		Extensions:        extension.ExtensionsFrom(),
	}

	input.ToHelloRetry()

	testHandshake(t, input, &ServerHello{}, typeServerHello)
	assert.True(t, input.IsHelloRetry())
}

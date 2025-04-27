package handshake

import (
	"testing"

	"network-stack/session/tls/common"
	"network-stack/session/tls/handshake/extension"

	"github.com/stretchr/testify/assert"
)

func TestClientHello(t *testing.T) {
	input := &clientHello{
		version:            common.VersionTLS12,
		random:             [32]byte{0x01, 0x02, 0x03, 0x04},
		sessionID:          []byte{0x05, 0x06},
		cipherSuites:       []common.CipherSuite{},
		compressionMethods: []byte{0x00},
		extensions:         extension.ExtensionsFrom(),
	}

	testHandshake(t, input, &clientHello{}, typeClientHello)
}

func TestServerHello(t *testing.T) {
	input := &serverHello{
		version:           common.VersionTLS12,
		random:            [32]byte{0x07, 0x08, 0x09, 0x0A},
		sessionIDEcho:     []byte{0x0B, 0x0C},
		cipherSuite:       common.CipherSuite{},
		compressionMethod: 0x00,
		extensions:        extension.ExtensionsFrom(),
	}

	testHandshake(t, input, &serverHello{}, typeServerHello)
}

func TestServerHelloRetry(t *testing.T) {
	input := &serverHello{
		version:           common.VersionTLS12,
		sessionIDEcho:     []byte{},
		cipherSuite:       common.CipherSuite{},
		compressionMethod: 0x00,
		extensions:        extension.ExtensionsFrom(),
	}

	input.toHelloRetry()

	testHandshake(t, input, &serverHello{}, typeServerHello)
	assert.True(t, input.isHelloRetry())
}

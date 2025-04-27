package handshake

import (
	"testing"

	"network-stack/session/tls/handshake/extension"
)

func TestEncryptedExtensions(t *testing.T) {
	input := &encryptedExtensions{
		extensions: extension.ExtensionsFrom(),
	}

	testHandshake(t, input, &encryptedExtensions{}, typeEncryptedExtensions)
}

func TestCertificateRequest(t *testing.T) {
	input := &certificateRequest{
		certRequestContext: []byte{0x01, 0x02},
		extensions:         extension.ExtensionsFrom(),
	}

	testHandshake(t, input, &certificateRequest{}, typeCertificateRequest)
}

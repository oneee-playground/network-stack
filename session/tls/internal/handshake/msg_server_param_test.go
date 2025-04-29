package handshake

import (
	"testing"

	"network-stack/session/tls/internal/handshake/extension"
)

func TestEncryptedExtensions(t *testing.T) {
	input := &EncryptedExtensions{
		Extensions: extension.ExtensionsFrom(),
	}

	testHandshake(t, input, &EncryptedExtensions{}, typeEncryptedExtensions)
}

func TestCertificateRequest(t *testing.T) {
	input := &CertificateRequest{
		CertRequestContext: []byte{0x01, 0x02},
		Extensions:         extension.ExtensionsFrom(),
	}

	testHandshake(t, input, &CertificateRequest{}, typeCertificateRequest)
}

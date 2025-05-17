package handshake

import (
	"testing"
)

func TestEncryptedExtensions(t *testing.T) {
	input := &EncryptedExtensions{}

	testHandshake(t, input, &EncryptedExtensions{}, typeEncryptedExtensions)
}

func TestCertificateRequest(t *testing.T) {
	input := &CertificateRequest{
		CertRequestContext: []byte{0x01, 0x02},
	}

	testHandshake(t, input, &CertificateRequest{}, typeCertificateRequest)
}

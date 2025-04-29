package handshake

import (
	"testing"

	"network-stack/session/tls/internal/handshake/extension"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testHandshake(t *testing.T, input Handshake, decoded Handshake, wantType handshakeType) {
	require.Equal(t, wantType, input.messageType())

	// Encode
	data := input.data()
	assert.Equal(t, input.length().Uint32(), uint32(len(data)))

	require.NoError(t, decoded.fillFrom(data))
	assert.Equal(t, input, decoded)
}

func TestCertificate(t *testing.T) {
	input := &Certificate{
		CertRequestContext: []byte{0x01, 0x02},
		CertList: []CertificateEntry{
			{
				CertData:   []byte{0x03, 0x04, 0x05},
				Extensions: extension.ExtensionsFrom(),
			},
		},
	}

	testHandshake(t, input, &Certificate{}, typeCertificate)
}

func TestCertificateVerify(t *testing.T) {
	input := &CertificateVerify{
		Algorithm: extension.SigScheme_RSA_PKCS1_SHA256,
		Signature: []byte{0x01, 0x02, 0x03},
	}

	testHandshake(t, input, &CertificateVerify{}, typeCertificateVerify)
}

func TestFinished(t *testing.T) {
	input := &Finished{
		VerifyData: []byte{0x01, 0x02, 0x03},
	}

	testHandshake(t, input, &Finished{}, typeFinished)
}

func TestNewSessionTicket(t *testing.T) {
	input := &NewSessionTicket{
		TicketLifetime: 3600,
		TicketAgeAdd:   12345,
		TicketNonce:    []byte{0x01, 0x02},
		Ticket:         []byte{0x03, 0x04, 0x05},
		Extensions:     extension.ExtensionsFrom(),
	}

	testHandshake(t, input, &NewSessionTicket{}, typeNewSessionTicket)
}

func TestKeyUpdate(t *testing.T) {
	input := &KeyUpdate{
		RequestUpdate: UpdateRequested,
	}

	testHandshake(t, input, &KeyUpdate{}, typeKeyUpdate)
}

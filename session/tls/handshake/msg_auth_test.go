package handshake

import (
	"testing"

	"network-stack/session/tls/handshake/extension"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testHandshake(t *testing.T, input handshake, decoded handshake, wantType handshakeType) {
	require.Equal(t, wantType, input.messageType())

	// Encode
	data := input.data()
	assert.Equal(t, input.length().Uint32(), uint32(len(data)))

	require.NoError(t, decoded.fillFrom(data))
	assert.Equal(t, input, decoded)
}

func TestCertificate(t *testing.T) {
	input := &certificate{
		certRequestContext: []byte{0x01, 0x02},
		certList: []certificateEntry{
			{
				certData:   []byte{0x03, 0x04, 0x05},
				extensions: extension.ExtensionsFrom(),
			},
		},
	}

	testHandshake(t, input, &certificate{}, typeCertificate)
}

func TestCertificateVerify(t *testing.T) {
	input := &certificateVerify{
		algorithm: extension.SigScheme_RSA_PKCS1_SHA256,
		signature: []byte{0x01, 0x02, 0x03},
	}

	testHandshake(t, input, &certificateVerify{}, typeCertificateVerify)
}

func TestFinished(t *testing.T) {
	input := &finished{
		verifyData: []byte{0x01, 0x02, 0x03},
	}

	testHandshake(t, input, &finished{}, typeFinished)
}

func TestNewSessionTicket(t *testing.T) {
	input := &newSessionTicket{
		ticketLifetime: 3600,
		ticketAgeAdd:   12345,
		ticketNonce:    []byte{0x01, 0x02},
		ticket:         []byte{0x03, 0x04, 0x05},
		extensions:     extension.ExtensionsFrom(),
	}

	testHandshake(t, input, &newSessionTicket{}, typeNewSessionTicket)
}

func TestKeyUpdate(t *testing.T) {
	input := &keyUpdate{
		requestUpdate: UpdateRequested,
	}

	testHandshake(t, input, &keyUpdate{}, typeKeyUpdate)
}

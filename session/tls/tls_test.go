package tls

import (
	"crypto/rand"
	"crypto/x509"
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/common/keyexchange"
	"network-stack/session/tls/common/signature"
	"network-stack/transport/pipe"
	"network-stack/transport/test"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ConnCompatibilityTestSuite struct {
	test.BufferedConnTestSuite
}

func TestConnCompatibilityTestSuite(t *testing.T) {
	suite.Run(t, new(ConnCompatibilityTestSuite))
}

func (s *ConnCompatibilityTestSuite) SetupTest() {
	s.ConnTestSuite.SetupTest()

	rootCert, priv := newRootCert(s.Clock)

	leaf1, priv1 := issueNewCert(defaultCertTemplate(s.Clock), rootCert, priv)
	leaf2, priv2 := issueNewCert(defaultCertTemplate(s.Clock), rootCert, priv)

	suite, _ := ciphersuite.Get(ciphersuite.TLS_AES_128_GCM_SHA256)
	keGroup, _ := keyexchange.Get(keyexchange.Group_Secp256r1)

	sigAlgo, _ := signature.AlgorithmFromX509Cert(rootCert)

	clientOpts := HandshakeClientOptions{
		HandshakeOptions: HandshakeOptions{
			Random:             rand.Reader,
			CipherSuites:       []ciphersuite.Suite{suite},
			KeyExchangeMethods: []keyexchange.Group{keGroup},
			SignatureAlgos:     []signature.Algorithm{sigAlgo},
			CertChains: []CertificateChain{{
				Chain:   [][]byte{leaf1.Raw},
				PrivKey: priv1,
			}},
			TrustedCerts: []*x509.Certificate{rootCert},
		},
		OfferKeyExchangeMethods: []keyexchange.Group{keGroup},
		ServerName:              "www.example.com",
	}
	serverOpts := HandshakeServerOptions{
		HandshakeOptions: HandshakeOptions{
			Random:             rand.Reader,
			CipherSuites:       []ciphersuite.Suite{suite},
			KeyExchangeMethods: []keyexchange.Group{keGroup},
			SignatureAlgos:     []signature.Algorithm{sigAlgo},
			CertChains: []CertificateChain{{
				Chain:   [][]byte{leaf2.Raw},
				PrivKey: priv2,
			}},
			TrustedCerts: []*x509.Certificate{rootCert},
		},
		RequireServerName: false,
	}

	c1, c2 := pipe.BufferedPipe("a", "b", s.Clock, 1<<13)

	errchan := make(chan error, 2)

	go func() {
		c1, err := NewClient(c1, s.Clock, ClientOptions{
			Record: RecordOptions{
				HandshakeTimeout: 0,
				CloseTimeout:     0,
			},
			Handshake: clientOpts,
		})

		s.C1 = c1
		errchan <- err

	}()
	go func() {
		c2, err := NewServer(c2, s.Clock, ServerOptions{
			Record: RecordOptions{
				HandshakeTimeout: 0,
				CloseTimeout:     0,
			},
			Handshake: serverOpts,
		})

		s.C2 = c2
		errchan <- err
	}()

	s.Require().NoError(<-errchan)
	s.Require().NoError(<-errchan)
}

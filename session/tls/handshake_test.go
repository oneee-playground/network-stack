package tls

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"network-stack/session/tls/common"
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/common/keyexchange"
	"network-stack/session/tls/common/signature"
	"network-stack/session/tls/internal/handshake/extension"
	"network-stack/transport/pipe"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestDetermineSignatureAlgos(t *testing.T) {
	algoExt := &extension.SignatureAlgos{
		SupportedAlgos: []signature.Scheme{signature.Scheme_ECDSA_SHA1},
	}
	algoCertExt := &extension.SignatureAlgosCert{
		SupportedAlgos: []signature.Scheme{signature.Scheme_ECDSA_Secp256r1_SHA256},
	}

	algos, algosCert := determineSignatureAlgos(algoExt, algoCertExt)
	assert.Equal(t, algoExt.SupportedAlgos, algos)
	assert.Equal(t, algoCertExt.SupportedAlgos, algosCert)

	// algoExt replaces algoCertExt.
	algoCertExt = nil
	algos, algosCert = determineSignatureAlgos(algoExt, algoCertExt)
	assert.Equal(t, algoExt.SupportedAlgos, algos)
	assert.Equal(t, algoExt.SupportedAlgos, algosCert)
}

func testHandshake(t *testing.T, clock clock.Clock, clientOpts HandshakeClientOptions, serverOpts HandshakeServerOptions) (*Conn, *Conn) {
	b1, b2 := pipe.BufferedPipe("client", "server", clock, 1<<13)
	timeout := time.Second

	c1 := &Conn{
		underlying:         b1,
		clock:              clock,
		closeTimeout:       timeout,
		isServer:           false,
		handshaking:        true,
		maxChunkSize:       maxRecordLen,
		in:                 newProtector(),
		out:                newProtector(),
		onNewSessionTicket: clientOpts.OnNewSessionTicket,
	}
	c2 := &Conn{
		underlying:   b2,
		clock:        clock,
		closeTimeout: timeout,
		isServer:     true,
		handshaking:  true,
		maxChunkSize: maxRecordLen,
		in:           newProtector(),
		out:          newProtector(),
	}

	ch, err := newHandshakerClient(c1, clock, clientOpts)
	require.NoError(t, err)
	sh, err := newHandshakerServer(c2, clock, serverOpts)
	require.NoError(t, err)

	errchan := make(chan error, 2)
	go func() { errchan <- doHandshake(c1, ch) }()
	go func() { errchan <- doHandshake(c2, sh) }()

	require.NoError(t, <-errchan)
	require.NoError(t, <-errchan)

	return c1, c2
}

type HandshakeTestSuite struct {
	suite.Suite

	clock clock.Clock

	rootCert             *x509.Certificate
	leaf1, leaf2         *x509.Certificate
	leafPriv1, leafPriv2 crypto.PrivateKey
}

func TestHandshakeTestSuite(t *testing.T) {
	suite.Run(t, new(HandshakeTestSuite))
}

func (s *HandshakeTestSuite) SetupTest() {
	s.clock = clock.NewMock()

	rootCert, priv := newRootCert(s.clock)
	s.rootCert = rootCert

	leaf1, priv1 := issueNewCert(defaultCertTemplate(s.clock), s.rootCert, priv)
	leaf2, priv2 := issueNewCert(defaultCertTemplate(s.clock), s.rootCert, priv)
	s.leaf1, s.leaf2 = leaf1, leaf2
	s.leafPriv1, s.leafPriv2 = priv1, priv2
}

func (s *HandshakeTestSuite) Test1RTTWithCertificate() {
	// 1. -> CH
	// 2. <- SH
	// 3. <- EE
	// 4. <- CR
	// 5. <- Cert
	// 6. <- CertVerify
	// 7. <- Finished
	// 8. -> Cert
	// 9. -> CertVerify
	// 10.-> Finished

	suite, _ := ciphersuite.Get(ciphersuite.TLS_AES_128_GCM_SHA256)
	keGroup, _ := keyexchange.Get(keyexchange.Group_Secp256r1)

	sigAlgo, _ := signature.AlgorithmFromX509Cert(s.rootCert)

	clientOpts := HandshakeClientOptions{
		HandshakeOptions: HandshakeOptions{
			Random:             rand.Reader,
			CipherSuites:       []ciphersuite.Suite{suite},
			KeyExchangeMethods: []keyexchange.Group{keGroup},
			SignatureAlgos:     []signature.Algorithm{sigAlgo},
			CertChains: []CertificateChain{{
				Chain:   [][]byte{s.leaf1.Raw},
				PrivKey: s.leafPriv1,
			}},
			TrustedCerts: []*x509.Certificate{s.rootCert},
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
				Chain:   [][]byte{s.leaf2.Raw},
				PrivKey: s.leafPriv2,
			}},
			TrustedCerts: []*x509.Certificate{s.rootCert},
		},
		RequireServerName: false,
	}

	_, _ = testHandshake(s.T(), s.clock, clientOpts, serverOpts)
}

func (s *HandshakeTestSuite) Test2RTTHelloRetryWithCertificate() {
	// 1. -> CH
	// 2. <- HRR
	// 3. -> CH
	// 4. <- SH
	// 5. <- EE
	// 6. <- CR
	// 7. <- Cert
	// 8. <- CertVerify
	// 9. <- Finished
	// 10.-> Cert
	// 11.-> CertVerify
	// 12.-> Finished

	suite, _ := ciphersuite.Get(ciphersuite.TLS_AES_128_GCM_SHA256)
	keGroup, _ := keyexchange.Get(keyexchange.Group_Secp256r1)

	sigAlgo, _ := signature.AlgorithmFromX509Cert(s.rootCert)

	clientOpts := HandshakeClientOptions{
		HandshakeOptions: HandshakeOptions{
			Random:             rand.Reader,
			CipherSuites:       []ciphersuite.Suite{suite},
			KeyExchangeMethods: []keyexchange.Group{keGroup},
			SignatureAlgos:     []signature.Algorithm{sigAlgo},
			CertChains: []CertificateChain{{
				Chain:   [][]byte{s.leaf1.Raw},
				PrivKey: s.leafPriv1,
			}},
			TrustedCerts: []*x509.Certificate{s.rootCert},
		},
		OfferKeyExchangeMethods: []keyexchange.Group{}, // No offered. Server should sent hello retry.
		ServerName:              "www.example.com",
	}
	serverOpts := HandshakeServerOptions{
		HandshakeOptions: HandshakeOptions{
			Random:             rand.Reader,
			CipherSuites:       []ciphersuite.Suite{suite},
			KeyExchangeMethods: []keyexchange.Group{keGroup},
			SignatureAlgos:     []signature.Algorithm{sigAlgo},
			CertChains: []CertificateChain{{
				Chain:   [][]byte{s.leaf2.Raw},
				PrivKey: s.leafPriv2,
			}},
			TrustedCerts: []*x509.Certificate{s.rootCert},
		},
		RequireServerName: false,
	}

	_, _ = testHandshake(s.T(), s.clock, clientOpts, serverOpts)
}

func (s *HandshakeTestSuite) Test1RTTWithoutClientCertificate() {
	// 1. -> CH
	// 2. <- SH
	// 3. <- EE
	// 4. <- Cert
	// 5. <- CertVerify
	// 6. <- Finished
	// 7. -> Finished

	suite, _ := ciphersuite.Get(ciphersuite.TLS_AES_128_GCM_SHA256)
	keGroup, _ := keyexchange.Get(keyexchange.Group_Secp256r1)

	sigAlgo, _ := signature.AlgorithmFromX509Cert(s.rootCert)

	clientOpts := HandshakeClientOptions{
		HandshakeOptions: HandshakeOptions{
			Random:             rand.Reader,
			CipherSuites:       []ciphersuite.Suite{suite},
			KeyExchangeMethods: []keyexchange.Group{keGroup},
			SignatureAlgos:     []signature.Algorithm{sigAlgo},
			TrustedCerts:       []*x509.Certificate{s.rootCert},
			CertChains:         nil, // No certificate to offer.
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
				Chain:   [][]byte{s.leaf2.Raw},
				PrivKey: s.leafPriv2,
			}},
			TrustedCerts: nil, // No trusted certs.
		},
		RequireServerName: false,
	}

	_, _ = testHandshake(s.T(), s.clock, clientOpts, serverOpts)
}

func (s *HandshakeTestSuite) Test1RTTWithoutClientCertificateALPN() {
	// 1. -> CH (alpn)
	// 2. <- SH (alpn)
	// 3. <- EE
	// 4. <- Cert
	// 5. <- CertVerify
	// 6. <- Finished
	// 7. -> Finished

	suite, _ := ciphersuite.Get(ciphersuite.TLS_AES_128_GCM_SHA256)
	keGroup, _ := keyexchange.Get(keyexchange.Group_Secp256r1)

	sigAlgo, _ := signature.AlgorithmFromX509Cert(s.rootCert)

	clientOpts := HandshakeClientOptions{
		HandshakeOptions: HandshakeOptions{
			Random:             rand.Reader,
			CipherSuites:       []ciphersuite.Suite{suite},
			KeyExchangeMethods: []keyexchange.Group{keGroup},
			SignatureAlgos:     []signature.Algorithm{sigAlgo},
			TrustedCerts:       []*x509.Certificate{s.rootCert},
			CertChains:         nil, // No certificate to offer.
			SupportedProtocols: []string{"example"},
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
				Chain:   [][]byte{s.leaf2.Raw},
				PrivKey: s.leafPriv2,
			}},
			TrustedCerts:       nil, // No trusted certs.
			SupportedProtocols: []string{"example"},
		},
		RequireServerName: false,
	}

	c1, c2 := testHandshake(s.T(), s.clock, clientOpts, serverOpts)

	s.Require().Equal(c1.Protocol(), c2.Protocol())
	s.Require().Equal("example", c2.Protocol())
}

func (s *HandshakeTestSuite) Test1RTTWithPSK() {
	// 1. -> CH (psk, key_share)
	// 2. <- SH (accept)
	// 3. <- EE
	// 4. <- Finished
	// 5. -> Finished

	suite, _ := ciphersuite.Get(ciphersuite.TLS_AES_128_GCM_SHA256)
	keGroup, _ := keyexchange.Get(keyexchange.Group_Secp256r1)

	ticket := Ticket{
		Type:           PSKTypeResumption,
		Ticket:         []byte("ticket"),
		Key:            []byte("the psk"),
		LifeTime:       0, // don't care here
		AgeAdd:         0, // don't care here
		Nonce:          []byte("the nonce"),
		EarlyDataLimit: 0,
		Version:        common.VersionTLS12,
		CipherSuite:    suite,
		ServerName:     "www.example.com",
	}

	var clientKeyUsed <-chan uint
	var serverKeyUsed <-chan struct{}

	clientOpts := HandshakeClientOptions{
		HandshakeOptions: HandshakeOptions{
			Random:             rand.Reader,
			CipherSuites:       []ciphersuite.Suite{suite},
			KeyExchangeMethods: []keyexchange.Group{keGroup},
			TrustedCerts:       []*x509.Certificate{s.rootCert},
		},
		OfferKeyExchangeMethods: []keyexchange.Group{keGroup},
		ServerName:              "www.example.com",
		PSKOnly:                 false,
		GetPreSharedKeys: func(ciphersuites []ciphersuite.Suite, serverName string, keyUsed <-chan uint) ([]PreSharedKey, error) {
			clientKeyUsed = keyUsed
			return []PreSharedKey{TicketToPSK(ticket, 0)}, nil
		},
	}
	serverOpts := HandshakeServerOptions{
		HandshakeOptions: HandshakeOptions{
			Random:             rand.Reader,
			CipherSuites:       []ciphersuite.Suite{suite},
			KeyExchangeMethods: []keyexchange.Group{keGroup},
			TrustedCerts:       []*x509.Certificate{s.rootCert},
		},
		RequireServerName: false,
		GetTicketsFromPSKs: func(selectedSuite ciphersuite.Suite, psks []PSKInfo, keyUsed <-chan struct{}) (idx int, _ Ticket, err error) {
			serverKeyUsed = keyUsed
			return 0, ticket, nil
		},
	}

	_, _ = testHandshake(s.T(), s.clock, clientOpts, serverOpts)

	idx, used := <-clientKeyUsed
	s.True(used)
	s.Equal(uint(0), idx)

	_, used = <-serverKeyUsed
	s.True(used)
}

func (s *HandshakeTestSuite) Test2RTTWithPSKHelloRetry() {
	// 1. -> CH (psk, key_share)
	// 2. <- HRR
	// 3. -> CH (psk, key_share)
	// 4. <- SH (accept)
	// 5. <- EE
	// 6. <- Finished
	// 7. -> Finished

	suite, _ := ciphersuite.Get(ciphersuite.TLS_AES_128_GCM_SHA256)
	keGroup, _ := keyexchange.Get(keyexchange.Group_Secp256r1)

	ticket := Ticket{
		Type:           PSKTypeResumption,
		Ticket:         []byte("ticket"),
		Key:            []byte("the psk"),
		LifeTime:       0, // don't care here
		AgeAdd:         0, // don't care here
		Nonce:          []byte("the nonce"),
		EarlyDataLimit: 0,
		Version:        common.VersionTLS12,
		CipherSuite:    suite,
		ServerName:     "www.example.com",
	}

	var clientKeyUsed <-chan uint
	var serverKeyUsed <-chan struct{}

	clientOpts := HandshakeClientOptions{
		HandshakeOptions: HandshakeOptions{
			Random:             rand.Reader,
			CipherSuites:       []ciphersuite.Suite{suite},
			KeyExchangeMethods: []keyexchange.Group{keGroup},
			TrustedCerts:       []*x509.Certificate{s.rootCert},
		},
		OfferKeyExchangeMethods: []keyexchange.Group{}, // This will result in HRR.
		ServerName:              "www.example.com",
		PSKOnly:                 false,
		GetPreSharedKeys: func(ciphersuites []ciphersuite.Suite, serverName string, keyUsed <-chan uint) ([]PreSharedKey, error) {
			clientKeyUsed = keyUsed
			return []PreSharedKey{TicketToPSK(ticket, 0)}, nil
		},
	}
	serverOpts := HandshakeServerOptions{
		HandshakeOptions: HandshakeOptions{
			Random:             rand.Reader,
			CipherSuites:       []ciphersuite.Suite{suite},
			KeyExchangeMethods: []keyexchange.Group{keGroup},
			TrustedCerts:       []*x509.Certificate{s.rootCert},
		},
		RequireServerName: false,
		GetTicketsFromPSKs: func(selectedSuite ciphersuite.Suite, psks []PSKInfo, keyUsed <-chan struct{}) (idx int, _ Ticket, err error) {
			serverKeyUsed = keyUsed
			return 0, ticket, nil
		},
	}

	_, _ = testHandshake(s.T(), s.clock, clientOpts, serverOpts)

	idx, used := <-clientKeyUsed
	s.True(used)
	s.Equal(uint(0), idx)

	_, used = <-serverKeyUsed
	s.True(used)
}

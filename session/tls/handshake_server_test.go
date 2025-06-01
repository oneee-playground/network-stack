package tls

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"network-stack/session/tls/common"
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/common/keyexchange"
	"network-stack/session/tls/common/session"
	"network-stack/session/tls/common/signature"
	"network-stack/session/tls/internal/alert"
	"network-stack/session/tls/internal/handshake"
	"network-stack/session/tls/internal/handshake/extension"
	"testing"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// For internal methods that don't use connection.
type ServerHandshakerTestSuite struct {
	suite.Suite

	clock clock.Clock

	ciphersuite ciphersuite.Suite
	keGroup     keyexchange.Group

	rootCert *x509.Certificate
	rootPriv crypto.PrivateKey

	opts HandshakeServerOptions

	hs *serverHandshaker
}

func TestServerHandshakerTestSuite(t *testing.T) {
	suite.Run(t, new(ServerHandshakerTestSuite))
}

func (s *ServerHandshakerTestSuite) SetupTest() {
	s.clock = clock.NewMock()

	s.ciphersuite, _ = ciphersuite.Get(ciphersuite.TLS_AES_128_GCM_SHA256)
	s.keGroup, _ = keyexchange.Get(keyexchange.Group_Secp256r1)

	s.rootCert, s.rootPriv = newRootCert(s.clock)

	cert, priv := issueNewCert(defaultCertTemplate(s.clock), s.rootCert, s.rootPriv)
	sigAlgo, _ := signature.AlgorithmFromX509Cert(cert)

	s.opts = HandshakeServerOptions{
		HandshakeOptions: HandshakeOptions{
			Random:             rand.Reader,
			CipherSuites:       []ciphersuite.Suite{s.ciphersuite},
			KeyExchangeMethods: []keyexchange.Group{s.keGroup},
			SignatureAlgos:     []signature.Algorithm{sigAlgo},
			CertChains: []CertificateChain{{
				Chain:   [][]byte{cert.Raw},
				PrivKey: priv,
			}},
			TrustedCerts: []*x509.Certificate{s.rootCert},
		},
		RequireServerName: false,
	}

	hs, err := newHandshakerServer(nil, s.clock, s.opts)
	s.Require().NoError(err)
	s.hs = hs
}

func (s *ServerHandshakerTestSuite) TestSaveSpecFromCH() {
	exampleCA := pkix.Name{Country: []string{"hello"}}
	seq := exampleCA.ToRDNSequence()
	raw, err := asn1.Marshal(seq)
	s.Require().NoError(err)

	exampleCA = pkix.Name{}
	_, err = asn1.Unmarshal(raw, &seq)
	s.Require().NoError(err)
	exampleCA.FillFromRDNSequence(&seq)

	testcases := []struct {
		desc    string
		ch      *handshake.ClientHello
		expect  func(session *Session, cri *certificateRequestInfo)
		wantErr bool
	}{
		{
			desc: "example",
			ch: &handshake.ClientHello{
				CipherSuites: []ciphersuite.ID{s.ciphersuite.ID()},
				ExtSignatureAlgos: &extension.SignatureAlgos{
					SupportedAlgos: []signature.Scheme{signature.Scheme_ECDSA_SHA1},
				},
				ExtSignatureAlgosCert: &extension.SignatureAlgosCert{
					SupportedAlgos: []signature.Scheme{signature.Scheme_ECDSA_Secp521r1_SHA512},
				},
				ExtCertAuthorities: &extension.CertAuthorities{
					Authorities: []extension.DistinguishedName{raw},
				},
				ExtServerNameList: &extension.ServerNameList{
					ServerNameList: []extension.ServerName{
						{NameType: extension.ServerNameTypeHostName, Name: []byte("example.com")},
					},
				},
			},
			expect: func(session *Session, cri *certificateRequestInfo) {
				expected := certificateRequestInfo{
					requestContext:          nil,
					signatureAlgorithms:     []signature.Scheme{signature.Scheme_ECDSA_SHA1},
					signatureAlgorithmsCert: []signature.Scheme{signature.Scheme_ECDSA_Secp521r1_SHA512},
					acceptableCA:            []pkix.Name{exampleCA},
					serverNames:             []string{"example.com"},
				}
				s.Equal(&expected, cri)
				s.Equal(s.ciphersuite.ID(), session.cipherSuite.ID())
				s.NotNil(session.transcript)
			},
		},
		{
			desc: "invalid CA name",
			ch: &handshake.ClientHello{
				ExtSignatureAlgos: &extension.SignatureAlgos{
					SupportedAlgos: []signature.Scheme{signature.Scheme_ECDSA_SHA1},
				},
				ExtCertAuthorities: &extension.CertAuthorities{
					Authorities: []extension.DistinguishedName{
						[]byte("ayo the pizza here"),
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		s.Run(tc.desc, func() {
			err := s.hs.saveSpecFromCH(tc.ch)
			if tc.wantErr {
				s.Error(err)
				return
			}
			s.Require().NoError(err)
			tc.expect(s.hs.session, &s.hs.certStore.remoteCertRequest)
		})
	}
}

func (s *ServerHandshakerTestSuite) TestMakeServerHello() {
	p512, _ := keyexchange.Get(keyexchange.Group_Secp521r1)
	_, remotePub1, err := s.keGroup.KeyExchange().GenKeyPair(rand.Reader)
	s.Require().NoError(err)
	_, remotePub2, err := p512.KeyExchange().GenKeyPair(rand.Reader)
	s.Require().NoError(err)

	testcases := []struct {
		desc       string
		modifyOpts func(opts *HandshakeServerOptions)
		ch         *handshake.ClientHello
		expect     func(sh *handshake.ServerHello, hs *serverHandshaker)
		wantErr    bool
	}{
		{
			desc:       "example",
			modifyOpts: func(opts *HandshakeServerOptions) {},
			ch: &handshake.ClientHello{
				SessionID: []byte("random"),
				ExtSupportedGroups: &extension.SupportedGroups{
					NamedGroupList: []keyexchange.GroupID{s.keGroup.ID()},
				},
				ExtKeyShares: &extension.KeyShareCH{
					KeyShares: []extension.KeyShareEntry{
						{
							Group:       s.keGroup.ID(),
							KeyExchange: remotePub1,
						},
					},
				},
			},
			expect: func(sh *handshake.ServerHello, hs *serverHandshaker) {
				// Validate fields.
				s.Equal(common.VersionTLS12, sh.Version)
				s.Len(sh.Random, 32)
				s.Equal(sh.SessionIDEcho, []byte("random"))
				s.Zero(sh.CompressionMethod)
				s.Equal(s.ciphersuite.ID(), sh.CipherSuite)

				// Key Share
				s.Require().NotNil(sh.ExtKeyShareSH)
				s.Equal(s.keGroup.ID(), sh.ExtKeyShareSH.KeyShare.Group)

				// Pre-Shared Key
				s.Nil(sh.ExtPreSharedKey)

				s.True(hs.usedMostPreferredKE)

				s.Nil(hs.earlySecret)
				s.NotNil(hs.sharedSecret)
			},
		},
		{
			desc: "alpn negotiated",
			modifyOpts: func(opts *HandshakeServerOptions) {
				opts.SupportedProtocols = []string{"example"}
			},
			ch: &handshake.ClientHello{
				ExtSupportedGroups: &extension.SupportedGroups{
					NamedGroupList: []keyexchange.GroupID{s.keGroup.ID()},
				},
				ExtKeyShares: &extension.KeyShareCH{
					KeyShares: []extension.KeyShareEntry{
						{
							Group:       s.keGroup.ID(),
							KeyExchange: remotePub1,
						},
					},
				},
				ExtALPN: &extension.ALPNProtocols{
					ProtocolNameList: []extension.ALPNProtocolName{
						extension.ALPNProtocolName("example"),
					},
				},
			},
			expect: func(sh *handshake.ServerHello, hs *serverHandshaker) {
				// Skip validating fields.

				s.Equal("example", hs.protocol)
			},
		},
		{
			desc: "didn't use most preffered",
			modifyOpts: func(opts *HandshakeServerOptions) {
				opts.KeyExchangeMethods = []keyexchange.Group{s.keGroup, p512}
			},
			ch: &handshake.ClientHello{
				ExtSupportedGroups: &extension.SupportedGroups{
					NamedGroupList: []keyexchange.GroupID{p512.ID()},
				},
				ExtKeyShares: &extension.KeyShareCH{
					KeyShares: []extension.KeyShareEntry{
						{
							Group:       p512.ID(),
							KeyExchange: remotePub2,
						},
					},
				},
			},
			expect: func(sh *handshake.ServerHello, hs *serverHandshaker) {
				// Skip validating fields.

				// Key Share
				s.Require().NotNil(sh.ExtKeyShareSH)
				s.Equal(p512.ID(), sh.ExtKeyShareSH.KeyShare.Group)

				s.False(hs.usedMostPreferredKE)

				s.Nil(hs.earlySecret)
				s.NotNil(hs.sharedSecret)
			},
		},
		{
			desc: "hello retry",
			modifyOpts: func(opts *HandshakeServerOptions) {
				opts.KeyExchangeMethods = []keyexchange.Group{s.keGroup}
			},
			ch: &handshake.ClientHello{
				ExtSupportedGroups: &extension.SupportedGroups{
					NamedGroupList: []keyexchange.GroupID{p512.ID(), s.keGroup.ID()},
				},
				ExtKeyShares: &extension.KeyShareCH{
					KeyShares: []extension.KeyShareEntry{
						{
							Group:       p512.ID(),
							KeyExchange: remotePub2,
						},
					},
				},
			},
			expect: func(sh *handshake.ServerHello, hs *serverHandshaker) {
				// Skip validating fields.
				s.True(sh.IsHelloRetry())
				s.NotNil(sh.ExtCookie)

				// Key Share
				s.Require().NotNil(sh.ExtKeyShareHRR)
				s.Equal(s.keGroup.ID(), sh.ExtKeyShareHRR.SelectedGroup)

				s.False(hs.usedMostPreferredKE)

				s.Nil(hs.earlySecret)
				s.Nil(hs.sharedSecret)
			},
			wantErr: true,
		},
		{
			desc:       "no common ke method",
			modifyOpts: func(opts *HandshakeServerOptions) {},
			ch: &handshake.ClientHello{
				ExtSupportedGroups: &extension.SupportedGroups{
					NamedGroupList: []keyexchange.GroupID{},
				},
			},
			expect:  func(sh *handshake.ServerHello, hs *serverHandshaker) {},
			wantErr: true,
		},
		{
			desc: "no common protocol",
			modifyOpts: func(opts *HandshakeServerOptions) {
				opts.SupportedProtocols = []string{"example1"}
			},
			ch: &handshake.ClientHello{
				ExtSupportedGroups: &extension.SupportedGroups{
					NamedGroupList: []keyexchange.GroupID{s.keGroup.ID()},
				},
				ExtKeyShares: &extension.KeyShareCH{
					KeyShares: []extension.KeyShareEntry{
						{
							Group:       s.keGroup.ID(),
							KeyExchange: remotePub1,
						},
					},
				},
				ExtALPN: &extension.ALPNProtocols{
					ProtocolNameList: []extension.ALPNProtocolName{
						extension.ALPNProtocolName("example2"),
					},
				},
			},
			expect:  func(sh *handshake.ServerHello, hs *serverHandshaker) {},
			wantErr: true,
		},
		{
			desc:       "invalid pubkey",
			modifyOpts: func(opts *HandshakeServerOptions) {},
			ch: &handshake.ClientHello{
				SessionID: []byte("random"),
				ExtSupportedGroups: &extension.SupportedGroups{
					NamedGroupList: []keyexchange.GroupID{s.keGroup.ID()},
				},
				ExtKeyShares: &extension.KeyShareCH{
					KeyShares: []extension.KeyShareEntry{
						{
							Group:       s.keGroup.ID(),
							KeyExchange: remotePub2, // pub for p512.
						},
					},
				},
			},
			expect:  func(sh *handshake.ServerHello, hs *serverHandshaker) {},
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		s.Run(tc.desc, func() {
			// Maybe just seperate it using test functions?
			s.hs.usedMostPreferredKE = false
			s.hs.earlySecret = nil
			s.hs.sharedSecret = nil
			s.hs.session.version = common.VersionTLS13
			s.hs.session.cipherSuite = s.ciphersuite
			s.hs.conn = &Conn{in: newProtector(), out: newProtector()}
			s.hs.opts = s.opts

			tc.modifyOpts(&s.hs.opts)

			sh, err := s.hs.makeServerHello(tc.ch)

			defer tc.expect(sh, s.hs)

			if !tc.wantErr {
				s.NoError(err)
				return
			}

			s.Error(err)
		})
	}
}

func (s *ServerHandshakerTestSuite) TestValidateClientHello() {
	exampleCH := handshake.ClientHello{
		Version:            common.VersionTLS12,
		SessionID:          make([]byte, 1),
		CipherSuites:       []ciphersuite.ID{ciphersuite.TLS_AES_128_GCM_SHA256},
		CompressionMethods: []byte{},
		ExtSupportedVersions: &extension.SupportedVersionsCH{
			Versions: []common.Version{common.VersionTLS13},
		},
		ExtSupportedGroups: &extension.SupportedGroups{},
		ExtSignatureAlgos:  &extension.SignatureAlgos{},
	}

	testcases := []struct {
		desc            string
		modifyExampleCH func(ch *handshake.ClientHello)
		wantErr         bool
		alert           alert.Description
	}{
		{
			desc:            "example",
			modifyExampleCH: func(ch *handshake.ClientHello) {},
			wantErr:         false,
		},
		{
			desc: "example (psk, psk_ke)",
			modifyExampleCH: func(ch *handshake.ClientHello) {
				ch.ExtSupportedGroups = nil
				ch.ExtPreSharedKey = &extension.PreSharedKeyCH{}
				ch.ExtPskMode = &extension.PskKeyExchangeModes{KeModes: []session.PSKMode{
					session.PSKModePSK_KE,
				}}
			},
			wantErr: false,
		},
		{
			desc: "example (psk, psk_dhe_ke)",
			modifyExampleCH: func(ch *handshake.ClientHello) {
				ch.ExtPreSharedKey = &extension.PreSharedKeyCH{}
				ch.ExtPskMode = &extension.PskKeyExchangeModes{KeModes: []session.PSKMode{
					session.PSKModePSK_DHE_KE,
				}}
			},
			wantErr: false,
		},
		{
			desc: "invalid (psk, psk_dhe_ke with no supported groups)",
			modifyExampleCH: func(ch *handshake.ClientHello) {
				ch.ExtSupportedGroups = nil
				ch.ExtPreSharedKey = &extension.PreSharedKeyCH{}
				ch.ExtPskMode = &extension.PskKeyExchangeModes{KeModes: []session.PSKMode{
					session.PSKModePSK_DHE_KE,
				}}
			},
			wantErr: true,
			alert:   alert.MissingExtension,
		},
		{
			desc: "invalid (psk, no ke_mode)",
			modifyExampleCH: func(ch *handshake.ClientHello) {
				ch.ExtPreSharedKey = &extension.PreSharedKeyCH{}
			},
			wantErr: true,
			alert:   alert.MissingExtension,
		},
		{
			desc: "invalid (psk, supported groups on psk_ke)",
			modifyExampleCH: func(ch *handshake.ClientHello) {
				ch.ExtPreSharedKey = &extension.PreSharedKeyCH{}
				ch.ExtPskMode = &extension.PskKeyExchangeModes{KeModes: []session.PSKMode{
					session.PSKModePSK_KE,
				}}
			},
			wantErr: true,
			alert:   alert.IllegalParameter,
		},
		{
			desc: "invalid (no psk, no supported groups)",
			modifyExampleCH: func(ch *handshake.ClientHello) {
				ch.ExtSupportedGroups = nil
			},
			wantErr: true,
			alert:   alert.MissingExtension,
		},
		{
			desc: "invalid version",
			modifyExampleCH: func(ch *handshake.ClientHello) {
				ch.ExtSupportedVersions = &extension.SupportedVersionsCH{
					Versions: []common.Version{common.VersionTLS11},
				}
			},
			wantErr: true,
			alert:   alert.IllegalParameter,
		},
		{
			desc: "version mismatch",
			modifyExampleCH: func(ch *handshake.ClientHello) {
				ch.ExtSupportedVersions = nil
			},
			wantErr: true,
			alert:   alert.ProtocolVersion,
		},
		{
			desc: "compression method isn't valid",
			modifyExampleCH: func(ch *handshake.ClientHello) {
				ch.CompressionMethods = []byte{0x11}
			},
			wantErr: true,
			alert:   alert.IllegalParameter,
		},
		{
			desc: "no signature algos",
			modifyExampleCH: func(ch *handshake.ClientHello) {
				ch.ExtSignatureAlgos = nil
			},
			wantErr: true,
			alert:   alert.MissingExtension,
		},
	}

	for _, tc := range testcases {
		s.Run(tc.desc, func() {
			ch := exampleCH
			tc.modifyExampleCH(&ch)

			err := s.hs.validateClientHello(&ch)
			if tc.wantErr {
				var alertErr alert.Error
				s.Require().ErrorAs(err, &alertErr)
				s.Equal(tc.alert, alertErr.Description)
				return
			}
			s.NoError(err)
		})
	}
}

func (s *ServerHandshakerTestSuite) TestMakeEncryptedExtensions() {
	// TODO: later.
}

func (s *ServerHandshakerTestSuite) TestMakeCertRequest() {
	// TODO: do we need it?
}

func TestWarnHijacked(t *testing.T) {
	b, warn := warnHijacked(common.VersionTLS13)
	assert.False(t, warn)
	assert.Zero(t, b)

	b, warn = warnHijacked(common.VersionTLS12)
	assert.True(t, warn)
	assert.Equal(t, handshake.DowngradeTLS12[:], b)

	b, warn = warnHijacked(common.VersionTLS11)
	assert.True(t, warn)
	assert.Equal(t, handshake.DowngradeTLS11[:], b)
}

func TestDetermineSupportedVersions(t *testing.T) {
	testcases := []struct {
		desc     string
		ch       handshake.ClientHello
		wantVers []common.Version
		wantErr  bool
	}{
		{
			desc: "example",
			ch: handshake.ClientHello{
				Version: common.VersionTLS12,
				ExtSupportedVersions: &extension.SupportedVersionsCH{
					Versions: []common.Version{common.VersionTLS13},
				},
			},
			wantVers: []common.Version{common.VersionTLS12, common.VersionTLS13},
		},
		{
			desc: "TLS 1.2 and no supported versions",
			ch: handshake.ClientHello{
				Version: common.VersionTLS12,
			},
			wantVers: []common.Version{common.VersionTLS12},
		},
		{
			desc: "TLS 1.1",
			ch: handshake.ClientHello{
				Version: common.VersionTLS11,
			},
			wantVers: []common.Version{common.VersionTLS11},
		},
		{
			desc: "extension has lesser version than 1.3",
			ch: handshake.ClientHello{
				Version: common.VersionTLS12,
				ExtSupportedVersions: &extension.SupportedVersionsCH{
					Versions: []common.Version{common.VersionTLS12},
				},
			},
			wantErr: true,
		},
		{
			desc: "field version is more than 1.2",
			ch: handshake.ClientHello{
				Version: common.VersionTLS13,
			},
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			vers, err := determineSupportedVersions(&tc.ch)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.Equal(t, tc.wantVers, vers)
		})
	}
}

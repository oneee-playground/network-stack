package tls

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	sliceutil "network-stack/lib/slice"
	"network-stack/session/tls/common"
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/common/keyexchange"
	"network-stack/session/tls/common/signature"
	"network-stack/session/tls/internal/alert"
	"network-stack/session/tls/internal/handshake"
	"network-stack/session/tls/internal/handshake/extension"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// For internal methods that don't use connection.
type ClientHandshakerTestSuite struct {
	suite.Suite

	clock clock.Clock

	ciphersuite ciphersuite.Suite
	keGroup     keyexchange.Group

	rootCert *x509.Certificate
	rootPriv crypto.PrivateKey

	opts HandshakeClientOptions

	hs *clientHandshaker
}

func TestClientHandshakerTestSuite(t *testing.T) {
	suite.Run(t, new(ClientHandshakerTestSuite))
}

func (s *ClientHandshakerTestSuite) SetupTest() {
	s.clock = clock.NewMock()

	s.ciphersuite, _ = ciphersuite.Get(ciphersuite.TLS_AES_128_GCM_SHA256)
	s.keGroup, _ = keyexchange.Get(keyexchange.Group_Secp256r1)

	s.rootCert, s.rootPriv = newRootCert(s.clock)

	cert, priv := issueNewCert(defaultCertTemplate(s.clock), s.rootCert, s.rootPriv)
	sigAlgo, _ := signature.AlgorithmFromX509Cert(cert)

	s.opts = HandshakeClientOptions{
		HandshakeOptions: HandshakeOptions{
			Random:             rand.Reader,
			CipherSuites:       []ciphersuite.Suite{s.ciphersuite},
			KeyExchangeMethods: []keyexchange.Group{s.keGroup},
			SignatureAlgos:     []signature.Algorithm{sigAlgo},
			CertChains: []CertificateChain{{
				Chain:   [][]byte{cert.Raw},
				PrivKey: priv,
			}},
			TrustedCerts:       []*x509.Certificate{s.rootCert},
			SupportedProtocols: []string{"example"},
		},
		PSKOnly:    false,
		ServerName: "example.com",

		OfferKeyExchangeMethods: []keyexchange.Group{s.keGroup},
	}

	hs, err := newHandshakerClient(nil, s.clock, s.opts)
	s.Require().NoError(err)
	s.hs = hs
}

func (s *ClientHandshakerTestSuite) TestMakeClientHello() {
	testcases := []struct {
		desc       string
		modifyOpts func(opts *HandshakeClientOptions)
		expect     func(ch *handshake.ClientHello)
		wantErr    bool
	}{
		{
			desc:       "exmaple",
			modifyOpts: func(opts *HandshakeClientOptions) {},
			expect: func(ch *handshake.ClientHello) {
				// Validate fields.
				s.Equal(common.VersionTLS12, ch.Version)
				s.Len(ch.Random, 32)
				s.Empty(ch.SessionID)
				s.Empty(ch.CompressionMethods)
				s.Equal([]ciphersuite.ID{s.ciphersuite.ID()}, ch.CipherSuites)

				// Supported Versions
				s.Require().NotNil(ch.ExtSupportedVersions)
				s.Equal([]common.Version{common.VersionTLS13}, ch.ExtSupportedVersions.Versions)

				// Signature Algorithms
				s.Require().NotNil(ch.ExtSignatureAlgos)
				expectedSigAlgos := signature.AsSchemes(s.opts.SignatureAlgos)
				s.Equal(expectedSigAlgos, ch.ExtSignatureAlgos.SupportedAlgos)

				// Supported Groups (key exchange)
				s.Require().NotNil(ch.ExtSupportedGroups)
				s.Equal(keyexchange.AsIDs(s.opts.KeyExchangeMethods), ch.ExtSupportedGroups.NamedGroupList)

				// Early Data. TODO: Support this.
				s.Nil(ch.ExtEarlyData)

				// Certificate extensions.
				s.Require().NotNil(ch.ExtSignatureAlgosCert)
				s.Equal(s.hs.certStore.signatureAlgosCert, ch.ExtSignatureAlgosCert.SupportedAlgos)

				s.Require().NotNil(ch.ExtCertAuthorities)
				expectedCAs := sliceutil.Map(s.hs.certStore.certAuthorities, func(ca []byte) extension.DistinguishedName { return ca })
				s.Equal(expectedCAs, ch.ExtCertAuthorities.Authorities)

				// Server Name
				s.Require().NotNil(ch.ExtServerNameList)
				s.Require().Len(ch.ExtServerNameList.ServerNameList, 1)
				serverName := ch.ExtServerNameList.ServerNameList[0]
				s.Equal(extension.ServerNameTypeHostName, serverName.NameType)
				s.Equal([]byte("example.com"), serverName.Name)

				// Key Share
				s.Require().NotNil(ch.ExtKeyShares)
				s.Require().Len(ch.ExtKeyShares.KeyShares, 1)
				s.Equal(s.keGroup.ID(), ch.ExtKeyShares.KeyShares[0].Group)

				s.Require().NotNil(ch.ExtALPN)
				s.Require().Len(ch.ExtALPN.ProtocolNameList, 1)
				s.Equal(extension.ALPNProtocolName("example"), ch.ExtALPN.ProtocolNameList[0])

				// Pre-Shared Key
				s.Nil(ch.ExtPreSharedKey)
				s.Nil(ch.ExtPskMode)
			},
		},
		{
			desc: "psk",
			modifyOpts: func(opts *HandshakeClientOptions) {
				opts.GetPreSharedKeys = func(
					ciphersuites []ciphersuite.Suite,
					serverName string,
					maxEarlyData uint32,
					protocols []string,
					keyUsed <-chan uint,
				) ([]PreSharedKey, error) {
					return []PreSharedKey{
						{
							Type:          PSKTypeResumption,
							Identity:      []byte("hi"),
							ObfuscatedAge: time.Hour,
							CipherSuite:   s.ciphersuite,
							Key:           []byte("key"),
						},
					}, nil
				}
			},
			expect: func(ch *handshake.ClientHello) {
				// Skip validating other fields.

				// Pre-Shared Key
				s.NotNil(ch.ExtPskMode)
				s.Require().NotNil(ch.ExtPreSharedKey)

				// Detailed test is at injectPSKExtensions.
			},
		},
	}

	for _, tc := range testcases {
		s.Run(tc.desc, func() {
			s.hs.opts = s.opts

			tc.modifyOpts(&s.hs.opts)

			ch, err := s.hs.makeClientHello()
			if tc.wantErr {
				s.Require().Error(err)
				return
			}
			s.Require().NoError(err)
			s.Require().NotNil(ch)

			tc.expect(ch)
		})
	}
}

func (s *ClientHandshakerTestSuite) TestValidateServerHello() {
	exampleCH := &handshake.ClientHello{
		SessionID:    make([]byte, 1),
		CipherSuites: []ciphersuite.ID{ciphersuite.TLS_AES_128_GCM_SHA256},
	}

	exampleSH := handshake.ServerHello{
		Version:           common.VersionTLS12,
		SessionIDEcho:     exampleCH.SessionID,
		CipherSuite:       exampleCH.CipherSuites[0],
		CompressionMethod: 0,
		ExtSupportedVersions: &extension.SupportedVersionsSH{
			SelectedVersion: common.VersionTLS13,
		},
	}
	exampleSH.ToHelloRetry()

	testcases := []struct {
		desc             string
		modifyExampleSH  func(hs *handshake.ServerHello)
		requestedPSKOnly bool
		protocols        []string
		wantErr          bool
		alert            alert.Description
	}{
		{
			desc:            "example (hello retry)",
			modifyExampleSH: func(hs *handshake.ServerHello) {},
			wantErr:         false,
		},
		{
			desc: "example (alpn)",
			modifyExampleSH: func(hs *handshake.ServerHello) {
				hs.ExtALPN = &extension.ALPNProtocols{ProtocolNameList: []extension.ALPNProtocolName{
					extension.ALPNProtocolName("hello"),
				}}
			},
			protocols: []string{"hello"},
			wantErr:   false,
		},
		{
			desc: "example (alpn, invalid length)",
			modifyExampleSH: func(hs *handshake.ServerHello) {
				hs.ExtALPN = &extension.ALPNProtocols{ProtocolNameList: []extension.ALPNProtocolName{
					extension.ALPNProtocolName("hello"),
					extension.ALPNProtocolName("abc"),
				}}
			},
			protocols: []string{"hello"},
			wantErr:   true,
			alert:     alert.IllegalParameter,
		},
		{
			desc: "example (non hello retry, keyshare)",
			modifyExampleSH: func(hs *handshake.ServerHello) {
				hs.Random = [32]byte{}
				hs.ExtKeyShareSH = &extension.KeyShareSH{}
			},
			wantErr: false,
		},
		{
			desc: "example (non hello retry, psk, psk only requested)",
			modifyExampleSH: func(hs *handshake.ServerHello) {
				hs.Random = [32]byte{}
				hs.ExtPreSharedKey = &extension.PreSharedKeySH{}
			},
			requestedPSKOnly: true,
			wantErr:          false,
		},
		{
			desc: "example (non hello retry, psk, psk only not requested)",
			modifyExampleSH: func(hs *handshake.ServerHello) {
				hs.Random = [32]byte{}
				hs.ExtPreSharedKey = &extension.PreSharedKeySH{}
				hs.ExtKeyShareSH = &extension.KeyShareSH{}
			},
			wantErr: false,
		},
		{
			desc: "invalid (non hello retry, psk and keyshare not provided)",
			modifyExampleSH: func(hs *handshake.ServerHello) {
				hs.Random = [32]byte{}
			},
			wantErr: true,
			alert:   alert.MissingExtension,
		},
		{
			desc: "invalid (non hello retry, key share on psk only requested)",
			modifyExampleSH: func(hs *handshake.ServerHello) {
				hs.Random = [32]byte{}
				hs.ExtPreSharedKey = &extension.PreSharedKeySH{}
				hs.ExtKeyShareSH = &extension.KeyShareSH{}
			},
			wantErr:          true,
			requestedPSKOnly: true,
			alert:            alert.IllegalParameter,
		},
		{
			desc: "invalid (non hello retry, no key share on psk only not requested)",
			modifyExampleSH: func(hs *handshake.ServerHello) {
				hs.Random = [32]byte{}
				hs.ExtPreSharedKey = &extension.PreSharedKeySH{}
			},
			wantErr: true,
			alert:   alert.MissingExtension,
		},
		{
			desc: "invalid version",
			modifyExampleSH: func(hs *handshake.ServerHello) {
				hs.ExtSupportedVersions = &extension.SupportedVersionsSH{
					SelectedVersion: common.VersionTLS11,
				}
			},
			wantErr: true,
			alert:   alert.IllegalParameter,
		},
		{
			desc: "version mismatch",
			modifyExampleSH: func(hs *handshake.ServerHello) {
				hs.ExtSupportedVersions = nil
			},
			wantErr: true,
			alert:   alert.ProtocolVersion,
		},
		{
			desc: "session id mismatch",
			modifyExampleSH: func(hs *handshake.ServerHello) {
				hs.SessionIDEcho = []byte("this doesn't match")
			},
			wantErr: true,
			alert:   alert.IllegalParameter,
		},
		{
			desc: "compression method isn't valid",
			modifyExampleSH: func(hs *handshake.ServerHello) {
				hs.CompressionMethod = 0x11
			},
			wantErr: true,
			alert:   alert.IllegalParameter,
		},
		{
			desc: "not offered cipher suite",
			modifyExampleSH: func(hs *handshake.ServerHello) {
				hs.CipherSuite = ciphersuite.TLS_AES_128_CCM_8_SHA256
			},
			wantErr: true,
			alert:   alert.IllegalParameter,
		},
	}

	for _, tc := range testcases {
		s.Run(tc.desc, func() {
			sh := exampleSH
			tc.modifyExampleSH(&sh)

			s.hs.opts.PSKOnly = tc.requestedPSKOnly
			s.hs.opts.SupportedProtocols = tc.protocols

			err := s.hs.validateServerHello(exampleCH, &sh)
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

func (s *ClientHandshakerTestSuite) TestRemakeCH() {
	s.hs.session.CipherSuite = s.ciphersuite
	s.hs.session.transcript = s.ciphersuite.Hash().New()

	testcases := []struct {
		desc string

		changeState func(hs *clientHandshaker)

		hrr *handshake.ServerHello

		checkResultCH func(ch *handshake.ClientHello)
		changed       bool
		wantErr       bool
	}{
		{
			desc: "example",
			changeState: func(hs *clientHandshaker) {
				x25519, _ := keyexchange.Get(keyexchange.Group_X25519)

				hs.opts.KeyExchangeMethods = []keyexchange.Group{
					s.keGroup, x25519,
				}
			},
			hrr: &handshake.ServerHello{
				ExtKeyShareHRR: &extension.KeyShareHRR{
					SelectedGroup: keyexchange.Group_X25519,
				},
				ExtCookie: &extension.Cookie{Cookie: []byte("cookie")},
			},
			changed: true,
			checkResultCH: func(ch *handshake.ClientHello) {
				s.Equal([]byte("cookie"), ch.ExtCookie.Cookie)

				s.Require().NotNil(ch.ExtKeyShares)
				s.Require().Len(ch.ExtKeyShares.KeyShares, 1)
				s.Equal(keyexchange.Group_X25519, ch.ExtKeyShares.KeyShares[0].Group)
			},
		},
		{
			desc:        "key share not offered",
			changeState: func(hs *clientHandshaker) {},
			hrr: &handshake.ServerHello{
				ExtKeyShareHRR: &extension.KeyShareHRR{
					SelectedGroup: keyexchange.Group_X448,
				},
			},
			checkResultCH: func(ch *handshake.ClientHello) {},
			wantErr:       true,
		},
		{
			desc:        "key share already offered",
			changeState: func(hs *clientHandshaker) {},
			hrr: &handshake.ServerHello{
				ExtKeyShareHRR: &extension.KeyShareHRR{
					SelectedGroup: s.keGroup.ID(),
				},
			},
			checkResultCH: func(ch *handshake.ClientHello) {},
			wantErr:       true,
		},
		{
			desc: "remake psk",
			changeState: func(hs *clientHandshaker) {
				suite, _ := ciphersuite.Get(ciphersuite.TLS_AES_256_GCM_SHA384)

				hs.notifyPSKUsed = make(chan uint) // for preventing closing nil chan.
				hs.opts.GetPreSharedKeys = func(
					ciphersuites []ciphersuite.Suite,
					serverName string,
					maxEarlyData uint32,
					protocols []string,
					keyUsed <-chan uint,
				) ([]PreSharedKey, error) {
					return []PreSharedKey{
						{
							Type:          PSKTypeResumption,
							Identity:      []byte("1"),
							ObfuscatedAge: 0,
							CipherSuite:   s.ciphersuite,
						},
						{
							Type:          PSKTypeResumption,
							Identity:      []byte("2"),
							ObfuscatedAge: 0,
							CipherSuite:   suite,
						},
					}, nil
				}
			},
			hrr:     &handshake.ServerHello{},
			changed: true,
			checkResultCH: func(ch *handshake.ClientHello) {
				s.Require().NotNil(ch.ExtPreSharedKey)
				s.Require().Len(ch.ExtPreSharedKey.Binders, 2)
				s.Require().Len(ch.ExtPreSharedKey.Identities, 2)

				s.Equal([]byte("1"), ch.ExtPreSharedKey.Identities[0].Identity)
				s.Equal([]byte("2"), ch.ExtPreSharedKey.Identities[1].Identity)
			},
		},
		{
			desc:          "unchanged",
			changeState:   func(hs *clientHandshaker) {},
			hrr:           &handshake.ServerHello{},
			changed:       false,
			checkResultCH: func(ch *handshake.ClientHello) {},
		},
		{
			desc: "reject early data",
			changeState: func(hs *clientHandshaker) {
				hs.opts.EarlyData = NewEarlyDataWriter(0)
			},
			hrr:     &handshake.ServerHello{},
			changed: true,
			checkResultCH: func(ch *handshake.ClientHello) {
				s.Nil(ch.ExtEarlyData)
			},
		},
	}

	for _, tc := range testcases {
		s.Run(tc.desc, func() {
			s.hs.opts = s.opts

			kePriv, kePub, err := s.keGroup.KeyExchange().GenKeyPair(rand.Reader)
			s.Require().NoError(err)

			s.hs.keyCandidates = map[keyexchange.GroupID]keyCandidate{
				s.keGroup.ID(): {
					method:  s.keGroup.KeyExchange(),
					privKey: kePriv,
					pubKey:  kePub,
				},
			}

			tc.changeState(s.hs)

			initialCH := handshake.ClientHello{ExtEarlyData: &extension.EarlyDataCH{}}

			newCH, changed, err := s.hs.remakeCH(&initialCH, tc.hrr)
			if tc.wantErr {
				s.Error(err)
				return
			}
			s.Require().NoError(err)

			s.Equal(tc.changed, changed)

			tc.checkResultCH(newCH)
		})
	}
}

func (s *ClientHandshakerTestSuite) TestSaveKeyExchangeSpec() {
	sh := &handshake.ServerHello{
		Version:     common.VersionTLS11, // Just for testing.
		CipherSuite: s.ciphersuite.ID(),
	}

	s.Require().NoError(s.hs.saveKeyExchangeSpec(sh))
	s.Equal(sh.CipherSuite, s.hs.session.CipherSuite.ID())
	s.NotNil(s.hs.session.transcript)

	// Not offered
	sh.CipherSuite = ciphersuite.TLS_AES_128_CCM_8_SHA256
	s.Error(s.hs.saveKeyExchangeSpec(sh))
}

func (s *ClientHandshakerTestSuite) TestCheckKeyExchangeSpec() {
	s.hs.session.Version = common.VersionTLS12
	s.hs.session.CipherSuite = s.ciphersuite

	sh := &handshake.ServerHello{
		Version:     common.VersionTLS12,
		CipherSuite: s.ciphersuite.ID(),
	}

	s.NoError(s.hs.checkKeyExchangeSpec(sh))

	sh = &handshake.ServerHello{
		Version:     common.VersionTLS11, // Wrong version.
		CipherSuite: s.ciphersuite.ID(),
	}
	s.Error(s.hs.checkKeyExchangeSpec(sh))

	sh = &handshake.ServerHello{
		Version:     common.VersionTLS12,
		CipherSuite: ciphersuite.TLS_AES_128_CCM_8_SHA256,
	}
	s.Error(s.hs.checkKeyExchangeSpec(sh))
}

func (s *ClientHandshakerTestSuite) TestSaveNegotiatedSpec() {
	_, remotePub, err := s.keGroup.KeyExchange().GenKeyPair(rand.Reader)
	s.Require().NoError(err)

	testcases := []struct {
		desc string

		sh      *handshake.ServerHello
		wantErr bool
	}{
		{
			desc: "key share",
			sh: &handshake.ServerHello{
				ExtKeyShareSH: &extension.KeyShareSH{
					KeyShare: extension.KeyShareEntry{
						Group:       s.keGroup.ID(),
						KeyExchange: remotePub,
					},
				},
			},
			wantErr: false,
		},
		{
			desc: "key share (non-offered group)",
			sh: &handshake.ServerHello{
				ExtKeyShareSH: &extension.KeyShareSH{
					KeyShare: extension.KeyShareEntry{
						Group:       keyexchange.Group_FFDHE2048,
						KeyExchange: remotePub,
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "key share (invalid pubkey)",
			sh: &handshake.ServerHello{
				ExtKeyShareSH: &extension.KeyShareSH{
					KeyShare: extension.KeyShareEntry{
						Group:       s.keGroup.ID(),
						KeyExchange: []byte("this has to be invalid"),
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "no psk provided but selected one",
			sh: &handshake.ServerHello{
				ExtPreSharedKey: &extension.PreSharedKeySH{
					SelectedIdentity: 0,
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		s.Run(tc.desc, func() {
			s.hs.session.CipherSuite = s.ciphersuite
			s.hs.session.transcript = s.ciphersuite.Hash().New()
			s.hs.conn = &Conn{in: newProtector(), out: newProtector()}

			kePriv, kePub, err := s.keGroup.KeyExchange().GenKeyPair(rand.Reader)
			s.Require().NoError(err)

			s.hs.keyCandidates = map[keyexchange.GroupID]keyCandidate{
				s.keGroup.ID(): {
					method:  s.keGroup.KeyExchange(),
					privKey: kePriv,
					pubKey:  kePub,
				},
			}

			err = s.hs.saveNegotiatedSpec(tc.sh)
			if tc.wantErr {
				s.Error(err)
				return
			}
			s.NoError(err)
		})
	}
}

func (s *ClientHandshakerTestSuite) TestSaveParameters() {
	s.hs.opts.EarlyData = NewEarlyDataWriter(0)
	s.hs.certStore.serverName = "example"

	err := s.hs.saveParameters(&handshake.EncryptedExtensions{
		ExtServerNameList: &extension.ServerNameList{},
	})
	s.Require().NoError(err)

	s.Nil(s.opts.EarlyData)
	s.Equal("example", s.hs.session.ServerName)

}

func (s *ClientHandshakerTestSuite) TestValidateCertRequest() {
	cr := &handshake.CertificateRequest{}

	s.Error(s.hs.validateCertRequest(cr))

	cr.ExtSignatureAlgos = &extension.SignatureAlgos{}
	s.NoError(s.hs.validateCertRequest(cr))
}

func (s *ClientHandshakerTestSuite) TestSaveCertRequest() {
	exampleCA := pkix.Name{Country: []string{"hello"}}
	seq := exampleCA.ToRDNSequence()
	raw, err := asn1.Marshal(seq)
	s.Require().NoError(err)

	exampleCA = pkix.Name{}
	_, err = asn1.Unmarshal(raw, &seq)
	s.Require().NoError(err)
	exampleCA.FillFromRDNSequence(&seq)

	testcases := []struct {
		desc     string
		cr       *handshake.CertificateRequest
		expected certificateRequestInfo
		wantErr  bool
	}{
		{
			desc: "example",
			cr: &handshake.CertificateRequest{
				CertRequestContext: []byte("context"),
				ExtSignatureAlgos: &extension.SignatureAlgos{
					SupportedAlgos: []signature.Scheme{signature.Scheme_ECDSA_SHA1},
				},
				ExtSignatureAlgosCert: &extension.SignatureAlgosCert{
					SupportedAlgos: []signature.Scheme{signature.Scheme_ECDSA_Secp521r1_SHA512},
				},
				ExtCertAuthorities: &extension.CertAuthorities{
					Authorities: []extension.DistinguishedName{raw},
				},
			},
			expected: certificateRequestInfo{
				requestContext:          []byte("context"),
				signatureAlgorithms:     []signature.Scheme{signature.Scheme_ECDSA_SHA1},
				signatureAlgorithmsCert: []signature.Scheme{signature.Scheme_ECDSA_Secp521r1_SHA512},
				acceptableCA:            []pkix.Name{exampleCA},
			},
		},
		{
			desc: "invalid CA name",
			cr: &handshake.CertificateRequest{
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
			err := s.hs.saveCertRequest(tc.cr)
			if tc.wantErr {
				s.Error(err)
				return
			}
			s.NoError(err)
			s.Equal(tc.expected, s.hs.certStore.remoteCertRequest)
		})
	}
}

func TestNewKeyShareCandidates(t *testing.T) {
	x25519, _ := keyexchange.Get(keyexchange.Group_X25519)
	ecdsa, _ := keyexchange.Get(keyexchange.Group_Secp256r1)

	methods := []keyexchange.Group{ecdsa, x25519}

	candidates, err := newKeyShareCandidates(methods, rand.Reader)
	require.NoError(t, err)

	require.Len(t, candidates, 2)

	for _, method := range methods {
		candidate, ok := candidates[method.ID()]
		require.True(t, ok)

		assert.Equal(t, method.KeyExchange(), candidate.method)
	}
}

func TestInjectPSKExtensions(t *testing.T) {
	// TODO: make this test validate more properties.

	ch := &handshake.ClientHello{}

	suite, _ := ciphersuite.Get(ciphersuite.TLS_AES_128_GCM_SHA256)

	psk := PreSharedKey{
		Type:          PSKTypeResumption,
		Identity:      []byte("A"),
		ObfuscatedAge: 0,
		CipherSuite:   suite,
	}
	pskOnly := true

	candidates, err := injectPSKExtensions(ch, []PreSharedKey{psk}, pskOnly)
	require.NoError(t, err)

	assert.Len(t, candidates, 1)

	require.NotNil(t, ch.ExtPreSharedKey)
	assert.Len(t, ch.ExtPreSharedKey.Binders, 1)
	assert.Len(t, ch.ExtPreSharedKey.Identities, 1)

	require.NotNil(t, ch.ExtPskMode)
	require.Len(t, ch.ExtPskMode.KeModes, 1)
	assert.Equal(t, extension.PSKModePSK_KE, ch.ExtPskMode.KeModes[0])
}

func TestDetermineSelectedVersion(t *testing.T) {
	testcases := []struct {
		desc    string
		sh      handshake.ServerHello
		wantVer common.Version
		wantErr bool
	}{
		{
			desc: "example",
			sh: handshake.ServerHello{
				Version: common.VersionTLS12,
				ExtSupportedVersions: &extension.SupportedVersionsSH{
					SelectedVersion: common.VersionTLS13,
				},
			},
			wantVer: common.VersionTLS13,
		},
		{
			desc: "TLS 1.2 and no supported versions",
			sh: handshake.ServerHello{
				Version: common.VersionTLS12,
			},
			wantVer: common.VersionTLS12,
		},
		{
			desc: "TLS 1.1",
			sh: handshake.ServerHello{
				Version: common.VersionTLS11,
				ExtSupportedVersions: &extension.SupportedVersionsSH{
					SelectedVersion: common.VersionTLS13,
				},
			},
			wantVer: common.VersionTLS11,
		},
		{
			desc: "extension has lesser version than 1.3",
			sh: handshake.ServerHello{
				Version: common.VersionTLS12,
				ExtSupportedVersions: &extension.SupportedVersionsSH{
					SelectedVersion: common.VersionTLS12,
				},
			},
			wantErr: true,
		},
		{
			desc: "field version is more than 1.2",
			sh: handshake.ServerHello{
				Version: common.VersionTLS13,
			},
			wantErr: true,
		},
		{
			desc: "selected version is less than 1.3 and is hijacked",
			sh: handshake.ServerHello{
				Version: common.VersionTLS11,
				Random:  [32]byte(append(make([]byte, 24), handshake.DowngradeTLS11[:]...)),
			},
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			ver, err := determineSelectedVersion(&tc.sh)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.Equal(t, tc.wantVer, ver)
		})
	}
}

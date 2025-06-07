package tls

import (
	"bytes"
	"crypto/hmac"
	"crypto/x509/pkix"
	"hash"
	"network-stack/lib/misc"
	sliceutil "network-stack/lib/slice"
	"network-stack/session/tls/common"
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/common/keyexchange"
	"network-stack/session/tls/common/signature"
	"network-stack/session/tls/internal/alert"
	"network-stack/session/tls/internal/handshake"
	"network-stack/session/tls/internal/handshake/extension"
	"network-stack/session/tls/internal/util/hkdf"
	"slices"
	"sync"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/pkg/errors"
)

// State Machine: datatracker.ietf.org/doc/html/rfc8446#appendix-A.2
type serverHandshaker struct {
	conn  *Conn
	clock clock.Clock

	opts HandshakeServerOptions

	session   *Session
	certStore certStore

	earlyDataHandler *earlyDataHandler

	usedMostPreferredKE  bool
	clientCert           bool
	usedMostPreferredPSK bool
	maxEarlyDataSize     uint32

	// cookie is opaque sequence of bytes to be used on HRR.
	// RFC doesn't specify which parameters should consist the cookie.
	cookie []byte

	earlySecret  []byte
	sharedSecret []byte
	protocol     string
}

func newHandshakerServer(conn *Conn, clock clock.Clock, opts HandshakeServerOptions) (*serverHandshaker, error) {
	sh := &serverHandshaker{
		conn:    conn,
		clock:   clock,
		opts:    opts,
		session: &Session{},
	}

	for idx, chain := range opts.CertChains {
		if err := chain.load(); err != nil {
			return nil, errors.Wrap(err, "failed to load certificate chain")
		}
		opts.CertChains[idx] = chain
	}

	sh.certStore = certStore{
		isServer:       true,
		signatureAlgos: opts.SignatureAlgos,
		trusted:        newCertPoolOrNil(opts.TrustedCerts),
		chains:         opts.CertChains,
	}

	signatureAlgosCert, authorities, err := signatureAlgoAndCAFromCerts(opts.TrustedCerts)
	if err != nil {
		return nil, errors.Wrap(err, "extracting parameeters from trusted certs")
	}
	sh.certStore.signatureAlgosCert = signatureAlgosCert
	sh.certStore.certAuthorities = authorities

	return sh, nil
}

var _ handshaker = (*serverHandshaker)(nil)

func (s *serverHandshaker) keyExchange() (err error) {
	defer func() {
		if err != nil {
			return
		}

		if err = s.saveNegotiatedSpec(); err != nil {
			err = errors.Wrap(err, "encrypting handshake")
		}
	}()

	clientHello, err := s.recvClientHello(nil)
	if err != nil {
		return errors.Wrap(err, "receiving client hello")
	}

	if err := s.saveSpecFromCH(clientHello); err != nil {
		return alert.NewError(err, alert.HandshakeFailure)
	}

	serverHello, err := s.sendServerHello(clientHello, false, nil)
	if err != nil {
		return errors.Wrap(err, "sending server hello")
	}

	if !serverHello.IsHelloRetry() {
		if err := s.startOrRejectEarlyData(clientHello); err != nil {
			return errors.Wrap(err, "starting early data")
		}

		// Add transcript.
		s.session.transcript.Write(handshake.ToBytes(clientHello))
		s.session.transcript.Write(handshake.ToBytes(serverHello))
		return
	}

	// On HRR, we use message_hash instead of initial client hello.
	// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.1
	messageHash := handshake.MakeMessageHash(s.session.CipherSuite, clientHello)
	s.session.transcript.Reset()
	s.session.transcript.Write(handshake.ToBytes(messageHash))
	s.session.transcript.Write(handshake.ToBytes(serverHello))

	retriedHello, err := s.recvRetriedHello(clientHello)
	if err != nil {
		return errors.Wrap(err, "receiving retried hello")
	}

	_, err = s.sendServerHello(retriedHello, true, s.session.transcript)
	if err != nil {
		return errors.Wrap(err, "making server hello for retried client hello")
	}

	return nil
}

func (s *serverHandshaker) saveSpecFromCH(ch *handshake.ClientHello) error {
	// Don't need to check error since it was
	// already done in expectClientHello.
	_, _ = determineSupportedVersions(ch)

	// Select version. It only supports TLS 1.3 at the moment.
	version := common.VersionTLS13
	s.session.Version = version

	suite, ok := s.selectCipherSuite(ch.CipherSuites)
	if !ok {
		return errors.New("no common cipher suites")
	}

	s.session.CipherSuite = suite
	s.session.transcript = suite.Hash().New()

	if s.certStore.wantAuth() {
		cri := certificateRequestInfo{requestContext: nil}

		algo, algoCert := determineSignatureAlgos(ch.ExtSignatureAlgos, ch.ExtSignatureAlgosCert)
		cri.signatureAlgorithms = algo
		cri.signatureAlgorithmsCert = algoCert

		if ca := ch.ExtCertAuthorities; ca != nil {
			cri.acceptableCA = make([]pkix.Name, 0, len(ca.Authorities))

			for _, authority := range ca.Authorities {
				name, err := unmarshalPKIXName(authority)
				if err != nil {
					return errors.Wrap(err, "unmarshaling authority")
				}

				cri.acceptableCA = append(cri.acceptableCA, name)
			}
		}

		if sni := ch.ExtServerNameList; sni != nil {
			for _, name := range sni.ServerNameList {
				if name.NameType != extension.ServerNameTypeHostName {
					continue
				}

				cri.serverNames = append(cri.serverNames, string(name.Name))
			}
		}

		s.certStore.remoteCertRequest = cri
	}

	if edi := ch.ExtEarlyData; s.opts.OnEarlyData != nil && edi != nil {
		// Prepare to accept early data.
		s.earlyDataHandler = &earlyDataHandler{handshakeP: &s.conn.in, p: newProtector()}
		s.earlyDataHandler.cond.L = &sync.Mutex{}

		s.conn.earlyDataHandler = s.earlyDataHandler
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
func (s *serverHandshaker) sendServerHello(
	clientHello *handshake.ClientHello,
	retried bool,
	transcript hash.Hash,
) (*handshake.ServerHello, error) {
	sh, err := s.makeServerHello(clientHello)
	if err != nil && (sh == nil || !sh.IsHelloRetry()) {
		return nil, errors.Wrap(err, "creating server hello")
	}

	if retried {
		if sh.IsHelloRetry() {
			err := errors.Wrap(err, "cannot retry anymore")
			return nil, alert.NewError(err, alert.HandshakeFailure)
		}

		// We didn't write it when we got client hello.
		s.session.transcript.Write(handshake.ToBytes(clientHello))
	}

	if edh := s.earlyDataHandler; edh != nil && sh.IsHelloRetry() {
		// Making it nil so we don't wait for EOED later.
		edh.retried = true
	}

	if err := s.conn.writeHandshake(sh, transcript); err != nil {
		return nil, errors.Wrap(err, "writing server hello")
	}

	return sh, nil
}

// This also saves negotiated spec.
func (s *serverHandshaker) makeServerHello(ch *handshake.ClientHello) (sh *handshake.ServerHello, err error) {
	var retryErr error

	defer func() {
		if err != nil {
			return
		}

		if retryErr != nil {
			sh.ToHelloRetry()

			// This is temporary.
			s.cookie = handshake.ToBytes(ch)
			sh.ExtCookie = &extension.Cookie{Cookie: s.cookie}

			err = retryErr
		}
	}()

	random, err := random32(s.opts.Random)
	if err != nil {
		return nil, errors.Wrap(err, "generating random")
	}

	sh = &handshake.ServerHello{
		Version:           common.VersionTLS12,
		Random:            random,
		CipherSuite:       s.session.CipherSuite.ID(),
		SessionIDEcho:     ch.SessionID,
		CompressionMethod: 0x00,
	}

	if s.session.Version == common.VersionTLS13 {
		// We don't need to do this since we reject versions other than TLS 1.3.
		// But I'll leave it for future use.
		if b, warn := warnHijacked(s.session.Version); warn {
			copy(sh.Random[24:32], b)
		}
	}

	sh.ExtSupportedVersions = &extension.SupportedVersionsSH{SelectedVersion: s.session.Version}

	if alpn := ch.ExtALPN; len(s.opts.SupportedProtocols) > 0 && alpn != nil {
		selected, found := s.selectProtocol(alpn.ProtocolNameList)
		if !found {
			err := errors.New("no common protocol found")
			return nil, alert.NewError(err, alert.NoApplicationProtocol)
		}

		s.protocol = string(selected)

		sh.ExtALPN = &extension.ALPNProtocols{
			ProtocolNameList: []extension.ALPNProtocolName{selected},
		}
	}

	// DHE key exchange extension exists when:
	// - PSK is not used
	// - PSK is used and psk mode is psk_dhe_ke
	if sg := ch.ExtSupportedGroups; sg != nil {
		useKe := s.selectKeyExchangeGroup(sg.NamedGroupList)
		if len(useKe) == 0 {
			// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.1
			err := errors.New("no common ke methods")
			return nil, alert.NewError(err, alert.HandshakeFailure)
		}

		ks := ch.ExtKeyShares

		group, remotePubKey, ok := s.selectKeyShare(useKe, ks.KeyShares)
		if !ok {
			retryErr = errors.New("key share doesn't include preferred ke method")
			sh.ExtKeyShareHRR = &extension.KeyShareHRR{SelectedGroup: useKe[0].ID()}
			return sh, nil
		}

		// This will be used later for determining if we should send supported_groups in EE.
		if group.ID() == s.opts.KeyExchangeMethods[0].ID() {
			s.usedMostPreferredKE = true
		}

		ke := group.KeyExchange()

		privKey, pubKey, err := ke.GenKeyPair(s.opts.Random)
		if err != nil {
			return nil, errors.Wrap(err, "generating key pair")
		}

		sh.ExtKeyShareSH = &extension.KeyShareSH{
			KeyShare: extension.KeyShareEntry{
				Group:       group.ID(),
				KeyExchange: pubKey,
			},
		}

		shared, err := ke.GenSharedSecret(privKey, remotePubKey)
		if err != nil {
			err := errors.Wrap(err, "generating shared secret")
			return nil, alert.NewError(err, alert.IllegalParameter)
		}
		s.sharedSecret = shared
	}

	if psk := ch.ExtPreSharedKey; psk != nil {
		_ = ch.ExtPskMode.KeModes[0] // Just indicating it exists.

		idx, ticket, keyUsed, err := s.getTicketFromPSK(psk)
		if err != nil {
			return nil, errors.Wrap(err, "getting ticket")
		}
		defer close(keyUsed)

		if idx >= 0 {
			receivedBinder := psk.Binders[idx]

			earlySecret, err := hkdf.Extract(s.session.CipherSuite, ticket.Key, nil)
			if err != nil {
				return nil, errors.Wrap(err, "deriving early secret")
			}

			transcript := misc.CopyHash(s.session.transcript)
			transcript.Write(handshake.ToBytes(makeCHForPSKBinder(ch)))

			if err := s.validatePSKBinder(receivedBinder, earlySecret, transcript.Sum(nil), ticket); err != nil {
				return nil, errors.Wrap(err, "invalid psk binder value")
			}

			s.earlySecret = earlySecret
			sh.ExtPreSharedKey = &extension.PreSharedKeySH{SelectedIdentity: uint16(idx)}

			keyUsed <- struct{}{}

			if idx == 0 {
				s.usedMostPreferredPSK = true
				s.maxEarlyDataSize = ticket.EarlyDataLimit
			}
		}
	}

	return sh, nil
}

func (s *serverHandshaker) getTicketFromPSK(psk *extension.PreSharedKeyCH) (int, Ticket, chan<- struct{}, error) {
	keyUsed := make(chan struct{}, 1)
	suite := s.session.CipherSuite

	if s.opts.GetTicketsFromPSKs == nil {
		return -1, Ticket{}, keyUsed, nil
	}

	infos := sliceutil.Map(psk.Identities, func(id extension.PSKIdentity) PSKInfo {
		return PSKInfo{
			Identity:      id.Identity,
			ObfuscatedAge: time.Duration(id.ObfuscatedTicketAge) * time.Millisecond,
		}
	})

	idx, ticket, err := s.opts.GetTicketsFromPSKs(suite, infos, s.protocol, keyUsed)
	if err != nil {
		return 0, Ticket{}, nil, errors.Wrap(err, "getting ticket from psk")
	}

	if idx >= len(infos) {
		close(keyUsed)
		return 0, Ticket{}, nil, errors.New("index not less than given length")
	}

	return idx, ticket, keyUsed, err
}

func makeCHForPSKBinder(ch *handshake.ClientHello) *handshake.ClientHello {
	ret := *ch

	ret.ExtPreSharedKey = &extension.PreSharedKeyCH{
		Identities: ch.ExtPreSharedKey.Identities,
	}

	for _, binder := range ch.ExtPreSharedKey.Binders {
		ret.ExtPreSharedKey.Binders = append(
			ret.ExtPreSharedKey.Binders,
			extension.PSKBinderEntry(make([]byte, len(binder))),
		)
	}

	return &ret
}

func (s *serverHandshaker) validatePSKBinder(received, earlySecret, transcript []byte, ticket Ticket) error {
	computed, err := computePSKBinderEntry(s.session.CipherSuite, ticket.Type, earlySecret, transcript)
	if err != nil {
		return errors.Wrap(err, "computing binder entry")
	}

	if !bytes.Equal(computed, received) {
		err := errors.New("binder value doesn't match")
		return alert.NewError(err, alert.IllegalParameter)
	}

	return nil
}

func warnHijacked(negotiated common.Version) (_ []byte, warn bool) {
	switch {
	case negotiated == common.VersionTLS12:
		return handshake.DowngradeTLS12[:], true
	case negotiated <= common.VersionTLS11:
		return handshake.DowngradeTLS11[:], true
	}
	return nil, false
}

func (s *serverHandshaker) selectCipherSuite(suites []ciphersuite.ID) (ciphersuite.Suite, bool) {
	mines := ciphersuite.AsIDs(s.opts.CipherSuites)
	for idx, mine := range mines {
		if slices.Contains(suites, mine) {
			return s.opts.CipherSuites[idx], true
		}
	}

	return ciphersuite.Suite{}, false
}

// Order: most preferred -> least preferred.
func (s *serverHandshaker) selectKeyExchangeGroup(groups []keyexchange.GroupID) []keyexchange.Group {
	out := make([]keyexchange.Group, 0)

	mines := keyexchange.AsIDs(s.opts.KeyExchangeMethods)
	for idx, mine := range mines {
		if slices.Contains(groups, mine) {
			out = append(out, s.opts.KeyExchangeMethods[idx])
		}
	}

	return out
}

func (s *serverHandshaker) selectKeyShare(
	selected []keyexchange.Group,
	keyshares []extension.KeyShareEntry,
) (group keyexchange.Group, pubKey []byte, found bool) {
	for _, group := range selected {
		for _, entry := range keyshares {
			if entry.Group != group.ID() {
				continue
			}

			return group, entry.KeyExchange, true
		}
	}

	return keyexchange.Group{}, nil, false
}

func (s *serverHandshaker) selectProtocol(
	names []extension.ALPNProtocolName,
) (selected extension.ALPNProtocolName, found bool) {
	for _, proto := range s.opts.SupportedProtocols {
		mine := extension.ALPNProtocolName(proto)

		for _, given := range names {
			if !bytes.Equal(given, mine) {
				continue
			}

			return given, true
		}
	}
	return nil, false

}

func (s *serverHandshaker) saveNegotiatedSpec() error {
	s.conn.session.ALPN = s.protocol

	if s.earlySecret != nil {
		s.session.resumed = true
	}

	if err := s.session.setEarlySecret(s.earlySecret); err != nil {
		return errors.Wrap(err, "setting early secret")
	}

	if err := s.session.setHandshakeSecret(s.conn, s.sharedSecret); err != nil {
		return errors.Wrap(err, "setting handshake secret")
	}

	return nil
}

func (s *serverHandshaker) startOrRejectEarlyData(ch *handshake.ClientHello) error {
	edh := s.earlyDataHandler
	if edh == nil {
		return nil
	}

	if s.usedMostPreferredPSK {
		edh.maxEarlyData = s.maxEarlyDataSize

		// Early data is permitted.
		suite := s.session.CipherSuite

		hash := suite.Hash().New()
		hash.Write(handshake.ToBytes(ch))

		if err := setEarlyTrafficSecret(&edh.p, suite, s.earlySecret, hash.Sum(nil)); err != nil {
			return errors.Wrap(err, "setting early secret for early data")
		}

		s.opts.OnEarlyData(edh, s.protocol)

		return nil
	}

	// Early data is rejected.
	edh.rejected = true
	s.earlyDataHandler = nil

	return nil
}

func (s *serverHandshaker) recvClientHello(transcript hash.Hash) (*handshake.ClientHello, error) {
	var clientHello handshake.ClientHello
	if _, err := s.conn.readHandshake(&clientHello, transcript); err != nil {
		return nil, errors.Wrap(err, "readinig client hello")
	}

	if err := s.validateClientHello(&clientHello); err != nil {
		return nil, errors.Wrap(err, "client hello is invalid")
	}

	return &clientHello, nil
}

func (s *serverHandshaker) validateClientHello(ch *handshake.ClientHello) error {
	versions, err := determineSupportedVersions(ch)
	if err != nil {
		return errors.Wrap(err, "getting supported version")
	}

	// Check if it contains at least one version that the server supports.
	if !slices.Contains(versions, common.VersionTLS13) {
		return alert.NewError(errors.New("only TLS 1.3 is supported"), alert.ProtocolVersion)
	}

	if len(ch.CompressionMethods) > 0 {
		return alert.NewError(errors.New("only null compression is allowed"), alert.IllegalParameter)
	}

	if s.certStore.wantAuth() && ch.ExtSignatureAlgos == nil {
		// If server uses certificate to authenticate,
		// then CH must have signature algos.
		return alert.NewError(errors.New("signature algorithms are required"), alert.MissingExtension)
	}

	needDHEKey := true
	if psk := ch.ExtPreSharedKey; psk != nil {
		if len(psk.Binders) != len(psk.Identities) {
			err := errors.New("binder count should be equal to identity count")
			return alert.NewError(err, alert.IllegalParameter)
		}

		// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.9
		mode := ch.ExtPskMode
		if mode == nil || len(mode.KeModes) == 0 {
			return alert.NewError(errors.New("psk mode is required"), alert.MissingExtension)
		}

		// We'll only use first element for simplicity.
		// (+ RFC doesn't specify what to do with multiple values)
		if mode.KeModes[0] == extension.PSKModePSK_KE {
			needDHEKey = false
		}
	}
	if needDHEKey && ch.ExtSupportedGroups == nil {
		return alert.NewError(errors.New("supported groups are required"), alert.MissingExtension)
	}
	if !needDHEKey && ch.ExtSupportedGroups != nil {
		return alert.NewError(errors.New("supported groups are forbidden"), alert.IllegalParameter)
	}

	return nil
}

func (s *serverHandshaker) recvRetriedHello(initial *handshake.ClientHello) (*handshake.ClientHello, error) {
	retriedHello, err := s.recvClientHello(nil)
	if err != nil {
		return nil, errors.Wrap(err, "receiving client hello")
	}

	hasCookie, err := initial.RetryValid(retriedHello, s.cookie)
	if err != nil {
		err = errors.Wrap(err, "retried CH is invalid")
		return nil, alert.NewError(err, alert.IllegalParameter)
	}

	if s.cookie != nil && !hasCookie {
		err = errors.Wrap(err, "missing cookie")
		return nil, alert.NewError(err, alert.MissingExtension)
	}

	if edh := s.earlyDataHandler; edh != nil {
		// No more early data should be received after second CH.
		edh.expectNoMoreEarlyData()

		s.earlyDataHandler = nil
	}

	return retriedHello, nil
}

func determineSupportedVersions(clientHello *handshake.ClientHello) ([]common.Version, error) {
	// NOTE: Assuming this is TLS 1.3 client.
	versions := []common.Version{clientHello.Version}

	if versions[0] > common.VersionTLS12 {
		err := errors.New("version field cannot be more than TLS 1.2")
		return nil, alert.NewError(err, alert.IllegalParameter)
	}

	if clientHello.Version == common.VersionTLS12 {
		// Extract an actual supported version.
		// If not found, it means that it is actually TLS 1.2.
		sv := clientHello.ExtSupportedVersions
		if sv == nil {
			return versions, nil
		}

		for _, ver := range sv.Versions {
			if ver < common.VersionTLS13 {
				err := errors.New("version from supported versions cannot be less than TLS 1.3")
				return nil, alert.NewError(err, alert.IllegalParameter)
			}

			versions = append(versions, ver)
		}
	}

	return versions, nil
}

func (s *serverHandshaker) serverParameters() error {
	_, err := s.sendEncryptedExtensions()
	if err != nil {
		return errors.Wrap(err, "sending encrypted extensions")
	}

	if !s.session.resumed && s.certStore.needRemoteAuth() {
		// We need to authenticate client.
		if _, err := s.sendCertRequest(); err != nil {
			return errors.Wrap(err, "sending certificate request")
		}
	}

	return nil
}

func (s *serverHandshaker) sendEncryptedExtensions() (*handshake.EncryptedExtensions, error) {
	ee, err := s.makeEncryptedExtensions()
	if err != nil {
		return nil, errors.Wrap(err, "making encrypted extensions")
	}

	if err := s.conn.writeHandshake(ee, s.session.transcript); err != nil {
		return nil, errors.Wrap(err, "writing encryted extensions")
	}

	return ee, nil
}

func (s *serverHandshaker) makeEncryptedExtensions() (*handshake.EncryptedExtensions, error) {
	ee := &handshake.EncryptedExtensions{}

	if len(s.certStore.remoteCertRequest.serverNames) > 0 {
		// We advertise that we are using provided sni.
		ee.ExtServerNameList = &extension.ServerNameList{}
	}

	if !s.session.resumed && !s.usedMostPreferredKE {
		ee.ExtSupportedGroups = &extension.SupportedGroups{
			NamedGroupList: keyexchange.AsIDs(s.opts.KeyExchangeMethods),
		}
	}

	if s.earlyDataHandler != nil {
		ee.ExtEarlyData = &extension.EarlyDataEE{}
	}

	return ee, nil
}

func (s *serverHandshaker) sendCertRequest() (*handshake.CertificateRequest, error) {
	cr, err := s.makeCertRequest()
	if err != nil {
		return nil, errors.Wrap(err, "making certificate request")
	}

	if err := s.conn.writeHandshake(cr, s.session.transcript); err != nil {
		return nil, errors.Wrap(err, "writing certificate request")
	}

	s.clientCert = true

	return cr, nil
}

func (s *serverHandshaker) makeCertRequest() (*handshake.CertificateRequest, error) {
	sigAlgos := signature.AsSchemes(s.certStore.signatureAlgos)
	certAlgos := s.certStore.signatureAlgosCert
	authorities := sliceutil.Map(s.certStore.certAuthorities, func(ca []byte) extension.DistinguishedName {
		return ca
	})

	cr := &handshake.CertificateRequest{
		CertRequestContext:    nil,
		ExtSignatureAlgos:     &extension.SignatureAlgos{SupportedAlgos: sigAlgos},
		ExtSignatureAlgosCert: &extension.SignatureAlgosCert{SupportedAlgos: certAlgos},
		ExtCertAuthorities:    &extension.CertAuthorities{Authorities: authorities},
	}

	return cr, nil
}

func (s *serverHandshaker) authentication() error {
	if !s.session.resumed {
		chain, ok := s.certStore.findCertChain()
		if !ok {
			err := errors.New("could not find matching chain")
			return alert.NewError(err, alert.HandshakeFailure)
		}

		if err := s.sendCertificate(chain); err != nil {
			return errors.Wrap(err, "sending certificate")
		}

		if err := s.sendCertVerify(chain); err != nil {
			return errors.Wrap(err, "sending certificate verify")
		}
	}

	if err := s.sendFinished(); err != nil {
		return errors.Wrap(err, "sending finished")
	}

	if err := s.session.setMasterSecret(s.conn); err != nil {
		return errors.Wrap(err, "setting application traffic key")
	}

	if !s.session.resumed && s.clientCert {
		cert, err := s.recvCertificate()
		if err != nil {
			return errors.Wrap(err, "receiving certificate")
		}

		if err := s.validateCert(cert); err != nil {
			return errors.Wrap(err, "invalid certificate")
		}

		verify, err := s.recvCertVerify()
		if err != nil {
			return errors.Wrap(err, "receiving certificate verify")
		}

		if err := s.validateCertVerify(verify); err != nil {
			return errors.Wrap(err, "invalid certificate verify")
		}

		// Didn't write transcript when receiving
		// since we need transcript until cert verify for validation.
		s.session.transcript.Write(handshake.ToBytes(verify))
	}

	fin, err := s.recvFinished()
	if err != nil {
		return errors.Wrap(err, "receiving finished")
	}

	if err := s.validateFinished(fin); err != nil {
		return errors.Wrap(err, "finished is invalid")
	}

	// Same as certificate verify. We needed to use trasncript in validation.
	s.session.transcript.Write(handshake.ToBytes(fin))

	return nil
}

func (s *serverHandshaker) sendCertificate(chain CertificateChain) error {
	if err := s.conn.writeHandshake(makeCertMessage(chain, nil), s.session.transcript); err != nil {
		return errors.Wrap(err, "writing handshake")
	}

	return nil
}

func (s *serverHandshaker) sendCertVerify(chain CertificateChain) error {
	transcript := s.session.transcript.Sum(nil)

	scheme, signature, err := s.certStore.makeSignature(chain, transcript, s.opts.Random)
	if err != nil {
		return errors.Wrap(err, "computing signature")
	}

	verify := handshake.CertificateVerify{
		Algorithm: scheme,
		Signature: signature,
	}

	if err := s.conn.writeHandshake(&verify, s.session.transcript); err != nil {
		return errors.Wrap(err, "writing handshake")
	}

	return nil
}

func (s *serverHandshaker) sendFinished() error {
	hash, err := s.session.makeFinishedHash()
	if err != nil {
		return errors.Wrap(err, "making hash for finished")
	}

	fin := handshake.Finished{VerifyData: hash}

	if err := s.conn.writeHandshake(&fin, s.session.transcript); err != nil {
		return errors.Wrap(err, "writing finished")
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
func (s *serverHandshaker) recvCertificate() (*handshake.Certificate, error) {
	var cert handshake.Certificate
	if _, err := s.conn.readHandshake(&cert, s.session.transcript); err != nil {
		return nil, errors.Wrap(err, "reading certificate")
	}

	return &cert, nil
}

func (s *serverHandshaker) validateCert(cert *handshake.Certificate) error {
	if len(cert.CertList) == 0 {
		err := errors.New("certificate is required")
		return alert.NewError(err, alert.CertificateRequired)
	}

	chain, err := chainFromCertificate(cert)
	if err != nil {
		err := errors.Wrap(err, "failed to create chain from certificate")
		return alert.NewError(err, alert.BadCertificate)
	}

	if err := s.certStore.validateChain(chain, s.clock.Now()); err != nil {
		return alert.NewError(err, alert.BadCertificate)
	}

	return nil
}

func (s *serverHandshaker) recvCertVerify() (*handshake.CertificateVerify, error) {
	var certVerify handshake.CertificateVerify
	if _, err := s.conn.readHandshake(&certVerify, nil); err != nil {
		return nil, errors.Wrap(err, "reading certificate verify")
	}

	return &certVerify, nil
}

func (s *serverHandshaker) validateCertVerify(verify *handshake.CertificateVerify) error {
	transcript := s.session.transcript.Sum(nil)

	if err := s.certStore.validateSignature(verify.Algorithm, transcript, verify.Signature); err != nil {
		return alert.NewError(err, alert.DecryptError)
	}

	return nil
}

func (s *serverHandshaker) recvFinished() (*handshake.Finished, error) {
	edh := s.earlyDataHandler

	if edh != nil && edh.isFinished() {
		// Somewhen before we sent finished, early data stream sent EOED.
		err := errors.New("end of early data cannot be received before we send finished")
		return nil, alert.NewError(err, alert.UnexpectedMessage)
	}

	var finished handshake.Finished
	if _, err := s.conn.readHandshake(&finished, nil); err != nil {
		return nil, errors.Wrap(err, "reading finished")
	}

	if edh != nil && !edh.isFinished() {
		// EOED isn't received before we receive finished.
		err := errors.New("end of early data should be received before finished")
		return nil, alert.NewError(err, alert.UnexpectedMessage)
	}

	return &finished, nil
}

func (s *serverHandshaker) validateFinished(fin *handshake.Finished) error {
	expectedHMAC, err := s.session.makeFinishedHash()
	if err != nil {
		return errors.Wrap(err, "computing finished hash for server finished validation")
	}

	if !hmac.Equal(expectedHMAC, fin.VerifyData) {
		err := errors.New("incorrect verify data")
		return alert.NewError(err, alert.DecryptError)
	}

	return nil
}

package tls

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/x509/pkix"
	"hash"
	"io"
	"network-stack/lib/misc"
	sliceutil "network-stack/lib/slice"
	"network-stack/session/tls/common"
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/common/keyexchange"
	"network-stack/session/tls/common/session"
	"network-stack/session/tls/common/signature"
	"network-stack/session/tls/internal/alert"
	"network-stack/session/tls/internal/handshake"
	"network-stack/session/tls/internal/handshake/extension"
	"network-stack/session/tls/internal/util/hkdf"
	"slices"

	"github.com/benbjohnson/clock"
	"github.com/pkg/errors"
)

type keyExchange struct {
	method  keyexchange.KeyExchange
	privKey []byte
	pubKey  []byte
}

// State Machine: datatracker.ietf.org/doc/html/rfc8446#appendix-A.1
type clientHandshaker struct {
	conn  *Conn
	clock clock.Clock

	opts HandshakeClientOptions

	session   *Session
	certStore certStore

	// Used for making shared secret.
	keyCandidates map[keyexchange.GroupID]keyExchange
	// includes candidates of psk.
	pskCandidates [][]byte

	// Encrypted extensions.
	clientCert bool
	earlyData  bool
}

func newHandshakerClient(conn *Conn, clock clock.Clock, opts HandshakeClientOptions) (*clientHandshaker, error) {
	ch := &clientHandshaker{
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

	ch.certStore = certStore{
		isServer:       false,
		signatureAlgos: opts.SignatureAlgos,
		trusted:        newCertPoolOrNil(opts.TrustedCerts),
		serverName:     opts.ServerName,
		chains:         opts.CertChains,
	}

	signatureAlgosCert, authorities, err := signatureAlgoAndCAFromCerts(opts.TrustedCerts)
	if err != nil {
		return nil, errors.Wrap(err, "extracting parameeters from trusted certs")
	}
	ch.certStore.signatureAlgosCert = signatureAlgosCert
	ch.certStore.certAuthorities = authorities

	return ch, nil
}

var _ handshaker = (*clientHandshaker)(nil)

func (c *clientHandshaker) keyExchange() (err error) {
	var serverHello *handshake.ServerHello
	defer func() {
		if err != nil {
			return
		}

		// It could be either initial SH or SH after HRR.
		if err = c.saveNegotiatedSpec(serverHello); err != nil {
			err = errors.Wrap(err, "saving netogiated spec")
			return
		}
	}()

	initialCH, err := c.sendClientHello()
	if err != nil {
		return errors.Wrap(err, "sending client hello")
	}

	// // Early data is allowed after initial hello.
	// if err := c.startEarlyData(); err != nil {
	// 	return errors.Wrap(err, "starting to send early data")
	// }

	serverHello, err = c.recvServerHello(initialCH, nil)
	if err != nil {
		return errors.Wrap(err, "expecting server hello")
	}

	// Save ciphersuite, version.
	if err := c.saveKeyExchangeSpec(serverHello); err != nil {
		return errors.Wrap(err, "saving necessary key exchange spec")
	}

	if !serverHello.IsHelloRetry() {
		// Add transcript.
		c.session.transcript.Write(handshake.ToBytes(initialCH))
		c.session.transcript.Write(handshake.ToBytes(serverHello))

		return nil
	}

	// On HRR, we use message_hash instead of initial client hello.
	// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.1
	messageHash := handshake.MakeMessageHash(c.session.cipherSuite, initialCH)
	c.session.transcript.Reset()
	c.session.transcript.Write(handshake.ToBytes(messageHash))
	c.session.transcript.Write(handshake.ToBytes(serverHello))

	retriedCH, err := c.retryHello(initialCH, serverHello)
	if err != nil {
		return errors.Wrap(err, "retrying hello")
	}

	serverHello, err = c.recvServerHello(retriedCH, c.session.transcript)
	if err != nil {
		return errors.Wrap(err, "expecting server hello")
	}

	if serverHello.IsHelloRetry() {
		// Server cannot send hello retry more than once.
		err := errors.New("unexpected hello retry")
		return alert.NewError(err, alert.UnexpectedMessage)
	}

	if err := c.checkKeyExchangeSpec(serverHello); err != nil {
		return errors.Wrap(err, "saving netogiated spec")
	}

	return nil
}

func (c *clientHandshaker) makeClientHello() (*handshake.ClientHello, error) {
	random, err := random32(c.opts.Random)
	if err != nil {
		return nil, errors.Wrap(err, "generating random")
	}

	ch := &handshake.ClientHello{
		Version:            common.VersionTLS12,
		Random:             random,
		SessionID:          []byte{}, // zero-length vector.
		CompressionMethods: []byte{}, // zero-length vector.
		CipherSuites:       ciphersuite.AsIDs(c.opts.CipherSuites),
	}

	// Add extensions.
	ch.ExtSupportedVersions = &extension.SupportedVersionsCH{
		Versions: []common.Version{common.VersionTLS13},
	}
	// Signature algorithms
	ch.ExtSignatureAlgos = &extension.SignatureAlgos{
		SupportedAlgos: signature.AsSchemes(c.certStore.signatureAlgos),
	}
	// Supported key exchange methods.
	ch.ExtSupportedGroups = &extension.SupportedGroups{
		NamedGroupList: keyexchange.AsIDs(c.opts.KeyExchangeMethods),
	}

	if c.opts.EarlyData != nil {
		// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.10
		ch.ExtEarlyData = &extension.EarlyDataCH{}
	}

	// Certificate requirements.
	if c.certStore.needRemoteAuth() {
		ch.ExtSignatureAlgosCert = &extension.SignatureAlgosCert{
			SupportedAlgos: c.certStore.signatureAlgosCert,
		}
		ch.ExtCertAuthorities = &extension.CertAuthorities{
			Authorities: sliceutil.Map(c.certStore.certAuthorities, func(ca []byte) extension.DistinguishedName {
				return ca
			}),
		}
	}

	// Certificate requirement for endpoint's host name.
	if c.certStore.serverName != "" {
		// Reference: https://datatracker.ietf.org/doc/html/rfc6066#section-3
		ch.ExtServerNameList = &extension.ServerNameList{
			ServerNameList: []extension.ServerName{{
				NameType: extension.ServerNameTypeHostName,
				Name:     []byte(c.certStore.serverName),
			}},
		}
	}

	if len(c.opts.SupportedProtocols) > 0 {
		protocols := sliceutil.Map(c.opts.SupportedProtocols, func(s string) extension.ALPNProtocolName {
			return []byte(s)
		})

		ch.ExtALPN = &extension.ALPNProtocols{ProtocolNameList: protocols}
	}

	// Key exchange method to use.
	offered := c.opts.OfferKeyExchangeMethods
	c.keyCandidates, err = newKeyShareCandidates(offered, c.opts.Random)
	if err != nil {
		return nil, errors.Wrap(err, "creating key share candidates")
	}
	ch.ExtKeyShares = &extension.KeyShareCH{KeyShares: keyshareEntries(offered, c.keyCandidates)}

	// Make pre-shared key.
	if len(c.opts.PreSharedKeys) > 0 {
		c.pskCandidates, err = injectPSKExtensions(ch, c.opts.PreSharedKeys, c.opts.PSKOnly)
		if err != nil {
			return nil, errors.Wrap(err, "injecting psk extensions to client hello")
		}
	}

	return ch, nil
}

func newKeyShareCandidates(methods []keyexchange.Group, random io.Reader) (map[keyexchange.GroupID]keyExchange, error) {
	candidates := make(map[keyexchange.GroupID]keyExchange, len(methods))
	for _, method := range methods {
		privKey, pubKey, err := method.KeyExchange().GenKeyPair(random)
		if err != nil {
			return nil, errors.Wrap(err, "generating keypair for key exchange")
		}

		candidates[method.ID()] = keyExchange{
			method:  method.KeyExchange(),
			privKey: privKey,
			pubKey:  pubKey,
		}
	}
	return candidates, nil
}

func keyshareEntries(methods []keyexchange.Group, candidates map[keyexchange.GroupID]keyExchange) []extension.KeyShareEntry {
	return sliceutil.Map(methods, func(group keyexchange.Group) extension.KeyShareEntry {
		return extension.KeyShareEntry{
			Group:       group.ID(),
			KeyExchange: candidates[group.ID()].pubKey,
		}
	})
}

func injectPSKExtensions(ch *handshake.ClientHello, keys []session.PreSharedKey, pskOnly bool) (candidates [][]byte, err error) {
	// PSK key exchange mode.
	var mode session.PSKMode
	if pskOnly {
		mode = session.PSKModePSK_KE
	} else {
		mode = session.PSKModePSK_DHE_KE
	}
	ch.ExtPskMode = &extension.PskKeyExchangeModes{KeModes: []session.PSKMode{mode}}

	pskCH := makePSKEmptyBinders(keys)
	ch.ExtPreSharedKey = &pskCH

	rawCH := handshake.ToBytes(ch)

	newTranscript := func(hash crypto.Hash) []byte {
		h := hash.New()
		h.Write(rawCH)
		return h.Sum(nil)
	}

	candidates, binders, err := makePSKCandidates(keys, newTranscript)
	if err != nil {
		return nil, errors.Wrap(err, "making psk candidates")
	}

	pskCH.Binders = sliceutil.Map(binders, func(b []byte) extension.PSKBinderEntry { return b })

	return candidates, nil
}

func makePSKEmptyBinders(keys []session.PreSharedKey) (psk extension.PreSharedKeyCH) {
	zeros := make(map[int][]byte, 0)

	for _, key := range keys {
		size := key.CipherSuite.Hash().Size()
		if _, ok := zeros[size]; !ok {
			zeros[size] = make([]byte, size)
		}

		psk.Binders = append(psk.Binders, zeros[size])
		psk.Identities = append(psk.Identities, extension.PSKIdentity{
			Identity:            key.Identity,
			ObfuscatedTicketAge: key.ObfuscatedTicketAge,
		})
	}

	return psk
}

func makePSKCandidates(
	keys []session.PreSharedKey,
	deriveTranscript func(hash crypto.Hash) []byte,
) (candidates, binders [][]byte, err error) {
	candidates = make([][]byte, len(keys))
	binders = make([][]byte, len(keys))

	for idx, key := range keys {
		// Transcript hash for the key.
		hash := key.CipherSuite.Hash()
		transcript := deriveTranscript(hash)

		candidate, binder, err := newPSKCandidate(key, transcript)
		if err != nil {
			return nil, nil, errors.Wrap(err, "creating new psk candidate")
		}

		candidates[idx] = candidate
		binders[idx] = binder
	}

	return candidates, binders, nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11.2
func newPSKCandidate(key session.PreSharedKey, transcript []byte) (candidate, binder []byte, err error) {
	suite := key.CipherSuite

	earlysecret, err := hkdf.Extract(suite, key.Identity, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "extracting early_secret")
	}

	binderEntry, err := computePSKBinderEntry(suite, key.Type, earlysecret, transcript)
	if err != nil {
		return nil, nil, errors.Wrap(err, "computing binder entry")
	}

	return earlysecret, binderEntry, nil
}

func (c *clientHandshaker) sendClientHello() (ch *handshake.ClientHello, err error) {
	ch, err = c.makeClientHello()
	if err != nil {
		return nil, errors.Wrap(err, "making client hello")
	}

	return ch, c.conn.writeHandshake(ch, nil)
}

func (c *clientHandshaker) startEarlyData() error {
	earlyData := c.opts.EarlyData
	if earlyData == nil {
		return nil
	}

	if len(c.pskCandidates) == 0 {
		return errors.New("cannot encrypt early data since there is no psk")
	}

	// If pre-shared keys exist, use first one as an input.
	// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.10
	earlySecret := c.pskCandidates[0]
	cipherSuite := c.opts.PreSharedKeys[0].CipherSuite

	if err := earlyData.p.setKey(earlySecret, cipherSuite); err != nil {
		return errors.Wrap(err, "setting key for early data")
	}

	earlyData.start(c.conn)

	return nil
}

func (c *clientHandshaker) recvServerHello(clientHello *handshake.ClientHello, transcript hash.Hash) (*handshake.ServerHello, error) {
	var sh handshake.ServerHello
	raw, err := c.conn.readHandshake(&sh, nil)
	if err != nil {
		return nil, errors.Wrap(err, "reading server hello")
	}

	if err := c.validateServerHello(clientHello, &sh); err != nil {
		return nil, errors.Wrap(err, "serverHello is invalid")
	}

	if transcript != nil {
		transcript.Write(raw)
	}

	return &sh, nil
}

func (c *clientHandshaker) validateServerHello(replyTo *handshake.ClientHello, got *handshake.ServerHello) error {
	selected, err := determineSelectedVersion(got)
	if err != nil {
		return errors.Wrap(err, "getting supported version")
	}

	if selected != common.VersionTLS13 {
		return alert.NewError(errors.New("only TLS 1.3 is supported"), alert.ProtocolVersion)
	}

	if !bytes.Equal(got.SessionIDEcho, replyTo.SessionID) {
		// It is responding to the wrong client hello.
		err := errors.New("session id not equal to the client hello")
		return alert.NewError(err, alert.IllegalParameter)
	}

	if got.CompressionMethod != 0x00 {
		// On TLS 1.3, compression method should set to zero. meaning null.
		return alert.NewError(errors.New("only null compression is allowed"), alert.IllegalParameter)
	}

	if !slices.Contains(replyTo.CipherSuites, got.CipherSuite) {
		err := errors.New("cipher suite must be offered by clientHello")
		return alert.NewError(err, alert.IllegalParameter)
	}

	if !got.IsHelloRetry() {
		// Server might simply have ignored psk.
		if got.ExtPreSharedKey != nil {
			// We have psk.
			if c.opts.PSKOnly && got.ExtKeyShareSH != nil {
				// If using psk_ke, we don't expect key_share to be received.
				// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
				err := errors.New("key share is invalid on psk_ke mode")
				return alert.NewError(err, alert.IllegalParameter)
			}
			if !c.opts.PSKOnly && got.ExtKeyShareSH == nil {
				// If using psk_dhe_ke, key_share must be provided.
				err := errors.New("key share must be provided on psk_dhe_ke mode")
				return alert.NewError(err, alert.MissingExtension)
			}
		} else if got.ExtKeyShareSH == nil {
			// DHE key exchange is required.
			err := errors.New("key share or pre-shared key must be provided")
			return alert.NewError(err, alert.MissingExtension)
		}
	}

	if len(c.opts.SupportedProtocols) > 0 && got.ExtALPN != nil {
		// Reference: https://datatracker.ietf.org/doc/html/rfc7301#section-3.1
		if len(got.ExtALPN.ProtocolNameList) != 1 {
			err := errors.New("alpn from server hello must only contain one name")
			return alert.NewError(err, alert.IllegalParameter)
		}
	}

	return nil
}

func determineSelectedVersion(serverHello *handshake.ServerHello) (common.Version, error) {
	// NOTE: Assuming this is TLS 1.3 client.
	version := serverHello.Version

	if version > common.VersionTLS12 {
		err := errors.New("version field cannot be more than TLS 1.2")
		return 0, alert.NewError(err, alert.IllegalParameter)
	}

	if version == common.VersionTLS12 {
		// Extract an actual supported version.
		// If not found, it means that it is actually TLS 1.2.
		if sv := serverHello.ExtSupportedVersions; sv != nil {
			version = sv.SelectedVersion

			if version < common.VersionTLS13 {
				err := errors.New("version from supported versions cannot be less than TLS 1.3")
				return 0, alert.NewError(err, alert.IllegalParameter)
			}
		}
	}

	if version <= common.VersionTLS12 {
		// If random contains certain pattern,
		// the client hello was hijacked and downgraded by attacker.
		hijacked12 := version == common.VersionTLS12 && bytes.HasSuffix(serverHello.Random[:], handshake.DowngradeTLS12[:])
		hijacked11 := version <= common.VersionTLS11 && bytes.HasSuffix(serverHello.Random[:], handshake.DowngradeTLS11[:])

		if hijacked11 || hijacked12 {
			err := errors.New("the client hello was hijacked by attacker")
			return 0, alert.NewError(err, alert.IllegalParameter)
		}
	}

	return version, nil
}

func (c *clientHandshaker) retryHello(
	initial *handshake.ClientHello,
	hrr *handshake.ServerHello,
) (*handshake.ClientHello, error) {
	newHello, changed, err := c.remakeCH(initial, hrr)
	if err != nil {
		return nil, errors.Wrap(err, "remaking CH from HRR")
	}

	if !changed {
		err := errors.New("hello retry request didn't result in any change")
		return nil, alert.NewError(err, alert.UnexpectedMessage)
	}

	if err := c.conn.writeHandshake(newHello, c.session.transcript); err != nil {
		return nil, errors.Wrap(err, "sending another hello")
	}

	return newHello, nil
}

// Reference:
// - https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
// - https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4
func (c *clientHandshaker) remakeCH(
	initial *handshake.ClientHello,
	hrr *handshake.ServerHello,
) (_ *handshake.ClientHello, changed bool, err error) {
	// Make clientHello based on initial one.
	newHello := *initial

	// If HRR provides key_share, replace mine with the provided one.
	if keyShare := hrr.ExtKeyShareHRR; keyShare != nil {
		// We should check that our supported_groups contains selected_group
		// and key_share doesn't contain selected_group.
		// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
		if _, alreadyOffered := c.keyCandidates[keyShare.SelectedGroup]; alreadyOffered {
			err := errors.New("exchange group already offered")
			return nil, false, alert.NewError(err, alert.IllegalParameter)
		}

		supports := keyexchange.AsIDs(c.opts.KeyExchangeMethods)

		idx := slices.Index(supports, keyShare.SelectedGroup)
		if idx == -1 {
			err := errors.New("exchange method not supported")
			return nil, false, alert.NewError(err, alert.IllegalParameter)
		}

		method := c.opts.KeyExchangeMethods[idx]
		newCandidates := []keyexchange.Group{method}

		var err error
		c.keyCandidates, err = newKeyShareCandidates(newCandidates, c.opts.Random)
		if err != nil {
			return nil, false, errors.Wrap(err, "generating keypair for selected group")
		}

		newHello.ExtKeyShares = &extension.KeyShareCH{
			KeyShares: []extension.KeyShareEntry{{
				Group:       keyShare.SelectedGroup,
				KeyExchange: c.keyCandidates[method.ID()].pubKey,
			}},
		}

		changed = true
	}

	// Early data is not allowed after HRR.
	newHello.ExtEarlyData = nil

	// Include a cookie extension if one was provided in the HRR.
	if cookie := hrr.ExtCookie; cookie != nil {
		newHello.ExtCookie = cookie
	}

	// If psk exists in initial hello, re-compute the obfuscated_ticket_age
	// and binder values. Also remove the psks that don't match negotiated cipher suite.
	// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
	if len(c.opts.PreSharedKeys) > 0 {
		newHello.ExtPreSharedKey = nil

		suite := c.session.cipherSuite

		// Filter usable psks.
		newPSKs := make([]session.PreSharedKey, 0)
		for _, key := range c.opts.PreSharedKeys {
			// compare with negotiated hash spec.
			if key.CipherSuite.Hash() != suite.Hash() {
				continue
			}

			// TODO: check ticket age.

			newPSKs = append(newPSKs, key)
		}

		pskCH := makePSKEmptyBinders(newPSKs)
		newHello.ExtPreSharedKey = &pskCH

		transcriptHash := misc.CopyHash(c.session.transcript)
		transcriptHash.Write(handshake.ToBytes(&newHello))
		transcript := transcriptHash.Sum(nil)

		candidates, binders, err := makePSKCandidates(newPSKs, func(hash crypto.Hash) []byte { return transcript })
		if err != nil {
			return nil, false, errors.Wrap(err, "remaking psk candidates")
		}

		c.pskCandidates = candidates
		pskCH.Binders = sliceutil.Map(binders,
			func(b []byte) extension.PSKBinderEntry {
				return b
			},
		)

		changed = true
	}

	return &newHello, changed, nil
}

func (c *clientHandshaker) saveKeyExchangeSpec(serverHello *handshake.ServerHello) error {
	// We don't need to check error since it is already checked.
	c.session.version, _ = determineSelectedVersion(serverHello)

	// Determine cipher suite.
	idx := slices.IndexFunc(c.opts.CipherSuites, func(suite ciphersuite.Suite) bool {
		return suite.ID() == serverHello.CipherSuite
	})
	if idx == -1 {
		err := errors.New("cipher suite was not offered")
		return alert.NewError(err, alert.IllegalParameter)
	}

	suite := c.opts.CipherSuites[idx]

	c.session.cipherSuite = suite
	c.session.transcript = suite.Hash().New()

	return nil
}

// This means this is ServerHello after HRR.
// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4
func (c *clientHandshaker) checkKeyExchangeSpec(serverHello *handshake.ServerHello) error {
	ver, _ := determineSelectedVersion(serverHello)
	if c.session.version != ver {
		err := errors.New("version changed after HRR")
		return alert.NewError(err, alert.IllegalParameter)
	}

	if c.session.cipherSuite.ID() != serverHello.CipherSuite {
		err := errors.New("cipher suite doesn't match the one offered in HRR")
		return alert.NewError(err, alert.IllegalParameter)
	}

	return nil
}

func (c *clientHandshaker) saveNegotiatedSpec(serverHello *handshake.ServerHello) (err error) {
	if alpn := serverHello.ExtALPN; len(c.opts.SupportedProtocols) > 0 && alpn != nil {
		selected := string(alpn.ProtocolNameList[0])
		c.conn.protocol = selected
	}

	var earlySecret []byte
	if psk := serverHello.ExtPreSharedKey; psk != nil {
		psk := serverHello.ExtPreSharedKey

		idx := int(psk.SelectedIdentity)
		if idx >= len(c.pskCandidates) {
			return alert.NewError(errors.New("psk index out of range"), alert.IllegalParameter)
		}

		// Early secret.
		earlySecret = c.pskCandidates[idx]
	}
	if err := c.session.setEarlySecret(earlySecret); err != nil {
		return errors.Wrap(err, "setting early secret")
	}

	var shared []byte
	if keyShare := serverHello.ExtKeyShareSH; keyShare != nil {
		ke, ok := c.keyCandidates[keyShare.KeyShare.Group]
		if !ok {
			return alert.NewError(errors.New("exchange method not expected"), alert.IllegalParameter)
		}

		remotePubKey := keyShare.KeyShare.KeyExchange

		shared, err = ke.method.GenSharedSecret(ke.privKey, remotePubKey)
		if err != nil {
			err = errors.Wrap(err, "generating shared secret")
			return alert.NewError(err, alert.IllegalParameter)
		}
	}
	if err := c.session.setHandshakeSecret(c.conn, shared); err != nil {
		return errors.Wrap(err, "setting application traffic key")
	}

	return nil
}

func (c *clientHandshaker) serverParameters() error {
	ee, err := c.recvEncryptedExtensions()
	if err != nil {
		return errors.Wrap(err, "receiving encrypted extensions")
	}

	if err := c.saveParameters(ee); err != nil {
		return errors.Wrap(err, "processing encrypted extensions")
	}

	if !c.session.resumed {
		// Server might request for client certificate if pre-shared key is not used.
		cr, err := c.maybeRecvCertRequest()
		if err != nil {
			return errors.Wrap(err, "reeciving cert request")
		}

		if cr != nil {
			if err := c.saveCertRequest(cr); err != nil {
				return errors.Wrap(err, "saving certificate request")
			}
		}
	}

	return nil
}

func (c *clientHandshaker) recvEncryptedExtensions() (*handshake.EncryptedExtensions, error) {
	// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.1
	var ee handshake.EncryptedExtensions
	if _, err := c.conn.readHandshake(&ee, c.session.transcript); err != nil {
		return nil, errors.Wrap(err, "reading encrypted extensions")
	}

	return &ee, nil
}

func (c *clientHandshaker) saveParameters(ee *handshake.EncryptedExtensions) error {
	if earlyData := c.opts.EarlyData; earlyData != nil {
		edi := ee.ExtEarlyData

		if edi != nil {
			// Early data is allowed.
			c.earlyData = true
		} else {
			// Early data rejected. Notify it to the application.
			earlyData.notifyRejected()
		}
	}

	if sni := ee.ExtServerNameList; sni != nil {
		// Maybe see if there is SNI? But it is useless for now.
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
func (c *clientHandshaker) maybeRecvCertRequest() (*handshake.CertificateRequest, error) {
	var cr handshake.CertificateRequest
	if _, err := c.conn.readHandshake(&cr, c.session.transcript); err != nil {
		if errors.Is(err, handshake.ErrNotExpectedHandshakeType) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "reading cert request")
	}

	if err := c.validateCertRequest(&cr); err != nil {
		return nil, errors.Wrap(err, "validating cert request")
	}

	return &cr, nil
}

func (c *clientHandshaker) validateCertRequest(cr *handshake.CertificateRequest) error {
	if cr.ExtSignatureAlgos == nil {
		err := errors.New("CR must have signature_algorithms")
		return alert.NewError(err, alert.MissingExtension)
	}

	return nil
}

func (c *clientHandshaker) saveCertRequest(cr *handshake.CertificateRequest) error {
	// We should echo it later.
	cri := certificateRequestInfo{requestContext: cr.CertRequestContext}

	algo, algoCert := determineSignatureAlgos(cr.ExtSignatureAlgos, cr.ExtSignatureAlgosCert)
	cri.signatureAlgorithms = algo
	cri.signatureAlgorithmsCert = algoCert

	if ca := cr.ExtCertAuthorities; ca != nil {
		cri.acceptableCA = make([]pkix.Name, 0, len(ca.Authorities))

		for _, authority := range ca.Authorities {
			name, err := unmarshalPKIXName(authority)
			if err != nil {
				return errors.Wrap(err, "unmarshaling authority")
			}

			cri.acceptableCA = append(cri.acceptableCA, name)
		}
	}

	// TODO: OID filters

	c.certStore.remoteCertRequest = cri
	c.clientCert = true

	return nil
}

func (c *clientHandshaker) authentication() error {
	if !c.session.resumed {
		cert, err := c.recvCertificate()
		if err != nil {
			return errors.Wrap(err, "receiving certificate")
		}

		if err := c.validateCert(cert); err != nil {
			return errors.Wrap(err, "verifying certificate")
		}

		verify, err := c.recvCertVerify()
		if err != nil {
			return errors.Wrap(err, "receiving certificate verify")
		}

		if err := c.validateCertVerify(verify); err != nil {
			return errors.Wrap(err, "invalid cert verify")
		}

		// Didn't write transcript when receiving
		// since we need transcript until cert verify for validation.
		c.session.transcript.Write(handshake.ToBytes(verify))
	}

	serverFin, err := c.recvFinished()
	if err != nil {
		return errors.Wrap(err, "reeciving server finished")
	}

	if err := c.validateFinished(serverFin); err != nil {
		return errors.Wrap(err, "invalid server finished")
	}

	// Same as certificate verify. We needed to use trasncript in validation.
	c.session.transcript.Write(handshake.ToBytes(serverFin))

	if err := c.session.setMasterSecret(c.conn); err != nil {
		return errors.Wrap(err, "setting application traffic key")
	}

	if !c.session.resumed && c.clientCert {
		chain, send := c.certStore.findCertChain()

		if err := c.sendCertificate(chain); err != nil {
			return errors.Wrap(err, "sending certificate")
		}

		// We send clientVerify only when certificate is non-zero length.
		if send {
			if err := c.sendCertVerify(chain); err != nil {
				return errors.Wrap(err, "sending certificate verify")
			}
		}
	}

	if err := c.sendFinished(); err != nil {
		return errors.Wrap(err, "sending finished")
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
func (c *clientHandshaker) recvCertificate() (*handshake.Certificate, error) {
	var cert handshake.Certificate
	if _, err := c.conn.readHandshake(&cert, c.session.transcript); err != nil {
		return nil, errors.Wrap(err, "reading certificate")
	}

	return &cert, nil
}

func (c *clientHandshaker) validateCert(cert *handshake.Certificate) error {
	if len(cert.CertList) == 0 {
		err := errors.New("certificate is required")
		return alert.NewError(err, alert.CertificateRequired)
	}

	chain, err := chainFromCertificate(cert)
	if err != nil {
		err := errors.Wrap(err, "failed to create chain from certificate")
		return alert.NewError(err, alert.BadCertificate)
	}

	if err := c.certStore.validateChain(chain, c.clock.Now()); err != nil {
		return alert.NewError(err, alert.BadCertificate)
	}

	return nil
}

func (c *clientHandshaker) recvCertVerify() (*handshake.CertificateVerify, error) {
	var certVerify handshake.CertificateVerify
	if _, err := c.conn.readHandshake(&certVerify, nil); err != nil {
		return nil, errors.Wrap(err, "reading certificate verify")
	}

	return &certVerify, nil
}

func (c *clientHandshaker) validateCertVerify(verify *handshake.CertificateVerify) error {
	transcript := c.session.transcript.Sum(nil)

	if err := c.certStore.validateSignature(verify.Algorithm, transcript, verify.Signature); err != nil {
		return alert.NewError(err, alert.DecryptError)
	}

	return nil
}

func (c *clientHandshaker) recvFinished() (*handshake.Finished, error) {
	var finished handshake.Finished
	if _, err := c.conn.readHandshake(&finished, nil); err != nil {
		return nil, errors.Wrap(err, "reading finished")
	}

	return &finished, nil
}

func (c *clientHandshaker) validateFinished(fin *handshake.Finished) error {
	expectedHMAC, err := c.session.makeFinishedHash()
	if err != nil {
		return errors.Wrap(err, "computing finished hash for server finished validation")
	}

	if !hmac.Equal(expectedHMAC, fin.VerifyData) {
		err := errors.New("incorrect verify data")
		return alert.NewError(err, alert.DecryptError)
	}

	return nil
}

func (c *clientHandshaker) sendCertificate(chain CertificateChain) error {
	context := c.certStore.remoteCertRequest.requestContext
	if err := c.conn.writeHandshake(makeCertMessage(chain, context), c.session.transcript); err != nil {
		return errors.Wrap(err, "writing handshake")
	}

	return nil
}

func (c *clientHandshaker) sendCertVerify(chain CertificateChain) error {
	transcript := c.session.transcript.Sum(nil)

	scheme, signature, err := c.certStore.makeSignature(chain, transcript, c.opts.Random)
	if err != nil {
		return errors.Wrap(err, "computing signature")
	}

	verify := handshake.CertificateVerify{
		Algorithm: scheme,
		Signature: signature,
	}

	if err := c.conn.writeHandshake(&verify, c.session.transcript); err != nil {
		return errors.Wrap(err, "writing handshake")
	}

	return nil
}

func (c *clientHandshaker) sendFinished() error {
	hash, err := c.session.makeFinishedHash()
	if err != nil {
		return errors.Wrap(err, "making hash for finished")
	}

	fin := handshake.Finished{VerifyData: hash}

	if err := c.conn.writeHandshake(&fin, c.session.transcript); err != nil {
		return errors.Wrap(err, "writing finished")
	}

	return nil
}

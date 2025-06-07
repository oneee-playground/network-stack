package tls

import (
	"crypto/hmac"
	"crypto/x509"
	"io"
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/common/keyexchange"
	"network-stack/session/tls/common/signature"
	"network-stack/session/tls/internal/alert"
	"network-stack/session/tls/internal/handshake/extension"
	"network-stack/session/tls/internal/util/hkdf"

	"github.com/pkg/errors"
)

type HandshakeOptions struct {
	CipherSuites []ciphersuite.Suite

	// Signature algorithms used for message verification.
	SignatureAlgos []signature.Algorithm

	// cert.RawSubject must not be empty.
	TrustedCerts []*x509.Certificate
	CertChains   []CertificateChain

	KeyExchangeMethods []keyexchange.Group

	// Used for ALPN.
	SupportedProtocols []string

	Random io.Reader
}

type HandshakeClientOptions struct {
	HandshakeOptions

	// Key exchange methods to be sent on key_shares
	// on initial ClientHello.
	OfferKeyExchangeMethods []keyexchange.Group

	// Only use psk for key exchange.
	PSKOnly bool

	// Server name for certificate.
	ServerName string

	EarlyData *earlyDataWriter

	OnNewSessionTicket func(ticket Ticket) error
	// GetPreSharedKeys gets psk of given spec.
	// It should find the matching psk that satisfies below:
	// 1. key is encrypted with one of: cipherSuites.
	// 2. key is issued on server of: serverName.
	// 3. key can handle early data of size: earlyDataSize.
	// 3. key must use one of the provided alpns. ordered in preference.
	// keyUsed is the indication of which key is used. it will either send index of the key, or be closed, meaning not used.
	GetPreSharedKeys func(
		ciphersuites []ciphersuite.Suite,
		serverName string,
		earlyDataSize uint32,
		protocols []string,
		keyUsed <-chan uint,
	) ([]PreSharedKey, error)
}

type HandshakeServerOptions struct {
	HandshakeOptions

	RequireServerName bool

	// OnEarlyData should be non-blocking.
	OnEarlyData func(r io.Reader, alpn string)

	// GetTicketsFromPSKs retrieves ticket from given cipher suite and psk information.
	// It should retrieve most preferred ticket using given spec. If not found, it should return idx of <0.
	// keyUsed is the indication of whether key is used. it will either send empty struct, or be closed, meaning not used.
	GetTicketsFromPSKs func(
		selectedSuite ciphersuite.Suite,
		psks []PSKInfo,
		protocol string,
		keyUsed <-chan struct{},
	) (idx int, ticket Ticket, err error)
}

type handshaker interface {
	keyExchange() error
	serverParameters() error
	authentication() error
}

func doHandshake(conn *Conn, h handshaker) (err error) {
	defer func() {
		conn.mu.Lock()
		conn.handshaking = false
		conn.mu.Unlock()

		if err == nil {
			return
		}

		if alertErr := new(alert.Error); errors.As(err, alertErr) {
			err = conn.sendAlert(alertErr.Description, alertErr.Cause())
		} else {
			err = conn.sendAlert(alert.InternalError, err)
		}

		conn.Close()
	}()

	// Negotiate handshake spec.
	if err := h.keyExchange(); err != nil {
		return errors.Wrap(err, "exchanging keys")
	}

	// Receive server parameters.
	if err := h.serverParameters(); err != nil {
		return errors.Wrap(err, "receiving server parameters")
	}

	// Authenticate client/server.
	if err := h.authentication(); err != nil {
		return errors.Wrap(err, "authenticating endpoints")
	}

	return nil
}

func random32(rand io.Reader) ([32]byte, error) {
	b := make([]byte, 32)

	if _, err := io.ReadFull(rand, b); err != nil {
		return [32]byte{}, err
	}

	return [32]byte(b), nil
}

func determineSignatureAlgos(
	algoExt *extension.SignatureAlgos, algoCertExt *extension.SignatureAlgosCert,
) (algo, algoCert []signature.Scheme) {
	algo = algoExt.SupportedAlgos
	algoCert = algo

	if algoCertExt != nil {
		algoCert = algoCertExt.SupportedAlgos
	}

	return algo, algoCert
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
func computeFinishedHash(
	suite ciphersuite.Suite,
	baseKey []byte,
	transcriptHash []byte,
) ([]byte, error) {
	finishedKey, err := hkdf.ExpandLabel(suite, baseKey, "finished", "", suite.Hash().Size())
	if err != nil {
		return nil, errors.Wrap(err, "expanding finished key")
	}

	hmac := hmac.New(suite.Hash().New, finishedKey)
	hmac.Write(transcriptHash)

	return hmac.Sum(nil), nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11.2
func computePSKBinderEntry(suite ciphersuite.Suite, t PSKType, earlySecret, transcriptHash []byte) ([]byte, error) {
	binderKey, err := hkdf.DeriveSecret(suite, earlySecret, string(t)+" binder", transcriptHash)
	if err != nil {
		return nil, errors.Wrap(err, "deriving binder key")
	}

	binderEntry, err := computeFinishedHash(suite, binderKey, transcriptHash)
	if err != nil {
		return nil, errors.Wrap(err, "computing finished hash")
	}

	return binderEntry, nil
}

// Used for deriving handshake_secret, master_secret.
func deriveNextSecret(suite ciphersuite.Suite, current, salt []byte) ([]byte, error) {
	if salt == nil {
		salt = make([]byte, suite.Hash().Size())
	}

	derivedSecret, err := hkdf.DeriveSecret(suite, current, "derived", nil)
	if err != nil {
		return nil, errors.Wrap(err, "deriving deriveSecret")
	}

	nextSecret, err := hkdf.Extract(suite, salt, derivedSecret)
	if err != nil {
		return nil, errors.Wrap(err, "deriving next secret")
	}

	return nextSecret, nil
}

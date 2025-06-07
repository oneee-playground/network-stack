package tls

import (
	"hash"
	"network-stack/session/tls/common"
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/internal/util/hkdf"
	"time"

	"github.com/pkg/errors"
)

type Session struct {
	resumed bool

	// secret for each stage. [early_secret, handshake_secret, master_secret]
	secret     []byte
	transcript hash.Hash

	Version     common.Version
	CipherSuite ciphersuite.Suite
	ServerName  string
	ALPN        string
}

func (s *Session) setEarlySecret(secret []byte) (err error) {
	if secret == nil {
		secret, err = hkdf.Extract(s.CipherSuite, nil, nil)
		if err != nil {
			return errors.Wrap(err, "deriving early_secret")
		}
	}

	s.secret = secret
	return nil
}

func (s *Session) setHandshakeSecret(conn *Conn, sharedSecret []byte) error {
	handshakeSecret, err := deriveNextSecret(s.CipherSuite, s.secret, sharedSecret)
	if err != nil {
		return errors.Wrap(err, "deriving handshake secret")
	}

	s.secret = handshakeSecret

	// client_handshake_traffic_secret, server_handshake_traffic_secret
	ours, theirs := "c hs traffic", "s hs traffic"
	if conn.isServer {
		ours, theirs = theirs, ours
	}

	transcript := s.transcript.Sum(nil)
	if err := conn.setTrafficKeys(ours, theirs, s.CipherSuite, s.secret, transcript); err != nil {
		return errors.Wrap(err, "setting handshake traffic keys")
	}

	return nil
}

func (s *Session) setMasterSecret(conn *Conn) error {
	masterSecret, err := deriveNextSecret(s.CipherSuite, s.secret, nil)
	if err != nil {
		return errors.Wrap(err, "deriving master secret")
	}

	s.secret = masterSecret

	// client_application_traffic_secret_0, server_application_traffic_secret_0
	ours, theirs := "c ap traffic", "s ap traffic"
	if conn.isServer {
		ours, theirs = theirs, ours
	}
	transcript := s.transcript.Sum(nil)
	if err := conn.setTrafficKeys(ours, theirs, s.CipherSuite, s.secret, transcript); err != nil {
		return errors.Wrap(err, "setting handshake traffic keys")
	}

	return nil
}

func (s *Session) ComputeResumpitonSecret() ([]byte, error) {
	resumption, err := hkdf.DeriveSecret(s.CipherSuite, s.secret, "res master", s.transcript.Sum(nil))
	if err != nil {
		return nil, errors.Wrap(err, "deriving resumption master secret")
	}

	return resumption, nil
}

func (s *Session) makeFinishedHash() ([]byte, error) {
	hash, err := computeFinishedHash(s.CipherSuite, s.secret, s.transcript.Sum(nil))
	if err != nil {
		return nil, errors.Wrap(err, "computing finished hash for client finished")
	}
	return hash, nil
}

// LifeTime, AgeAdd is truncated to seconds.
type Ticket struct {
	Type   PSKType
	Ticket []byte

	// PSK associated with the ticket.
	Key []byte

	LifeTime       time.Duration
	AgeAdd         time.Duration
	Nonce          []byte
	EarlyDataLimit uint32

	// Session info.
	Version     common.Version
	CipherSuite ciphersuite.Suite
	ServerName  string
	ALPN        string
}

func ComputePSK(suite ciphersuite.Suite, resumptionSecret []byte, nonce []byte) (psk []byte, err error) {
	hashLen := suite.Hash().Size()

	psk, err = hkdf.ExpandLabel(suite, resumptionSecret, "resumption", string(nonce), hashLen)
	if err != nil {
		return nil, errors.Wrap(err, "expanding psk")
	}

	return psk, nil
}

type PSKType string

const (
	PSKTypeResumption PSKType = "res"
	PSKTypeExternal   PSKType = "ext"
)

// PreSharedKey is client-side view of pre-shared key.
// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
type PreSharedKey struct {
	Type     PSKType
	Identity []byte

	ObfuscatedAge time.Duration

	CipherSuite ciphersuite.Suite
	Key         []byte
}

// PSKInfo is server-side view of pre-shared key.
type PSKInfo struct {
	Identity      []byte
	ObfuscatedAge time.Duration
}

func TicketToPSK(ticket Ticket, timePassed time.Duration) PreSharedKey {
	obfuscated := timePassed + ticket.AgeAdd

	return PreSharedKey{
		Type:          ticket.Type,
		Identity:      ticket.Ticket,
		ObfuscatedAge: obfuscated,
		CipherSuite:   ticket.CipherSuite,
		Key:           ticket.Key,
	}
}

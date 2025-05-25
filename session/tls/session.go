package tls

import (
	"hash"
	"network-stack/session/tls/common"
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/internal/util/hkdf"

	"github.com/pkg/errors"
)

type Session struct {
	id      []byte
	resumed bool

	version     common.Version
	cipherSuite ciphersuite.Suite

	// secret for each stage. [early_secret, handshake_secret, master_secret]
	secret []byte

	transcript hash.Hash
}

func (s *Session) setEarlySecret(secret []byte) (err error) {
	if secret == nil {
		secret, err = hkdf.Extract(s.cipherSuite, nil, nil)
		if err != nil {
			return errors.Wrap(err, "deriving early_secret")
		}
	} else {
		s.resumed = true
	}

	s.secret = secret
	return nil
}

func (s *Session) setHandshakeSecret(conn *Conn, sharedSecret []byte) error {
	handshakeSecret, err := deriveNextSecret(s.cipherSuite, s.secret, sharedSecret)
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
	if err := conn.setTrafficKeys(ours, theirs, s.cipherSuite, s.secret, transcript); err != nil {
		return errors.Wrap(err, "setting handshake traffic keys")
	}

	return nil
}

func (s *Session) setMasterSecret(conn *Conn) error {
	masterSecret, err := deriveNextSecret(s.cipherSuite, s.secret, nil)
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
	if err := conn.setTrafficKeys(ours, theirs, s.cipherSuite, s.secret, transcript); err != nil {
		return errors.Wrap(err, "setting handshake traffic keys")
	}

	return nil
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

func (s *Session) makeFinishedHash() ([]byte, error) {
	hash, err := computeFinishedHash(s.cipherSuite, s.secret, s.transcript.Sum(nil))
	if err != nil {
		return nil, errors.Wrap(err, "computing finished hash for client finished")
	}
	return hash, nil
}

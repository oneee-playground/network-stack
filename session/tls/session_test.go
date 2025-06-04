package tls

import (
	"network-stack/session/tls/common"
	"network-stack/session/tls/common/ciphersuite"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SessionTestSuite struct {
	suite.Suite

	ciphersuite ciphersuite.Suite
	session     *Session
}

func TestSessionTestSuite(t *testing.T) {
	suite.Run(t, new(SessionTestSuite))
}

func (s *SessionTestSuite) SetupTest() {
	suite, _ := ciphersuite.Get(ciphersuite.TLS_AES_128_GCM_SHA256)
	s.ciphersuite = suite

	s.session = &Session{
		CipherSuite: suite,
		transcript:  suite.Hash().New(),
	}
}

func (s *SessionTestSuite) TestSetEarlySecretNoSecret() {
	// Providing nil secret will make session create a new one.
	s.NoError(s.session.setEarlySecret(nil))

	s.NotNil(s.session.secret)
}

func (s *SessionTestSuite) TestSetEarlySecretPreSharedSecret() {
	secret := []byte("haha missed me?")

	// Providing secret will make session use it right away.
	s.NoError(s.session.setEarlySecret(secret))

	s.Equal(secret, s.session.secret)
}

func TestTicketToPSK(t *testing.T) {
	ticket := Ticket{
		Type:           PSKTypeExternal,
		Ticket:         []byte("ticket"),
		Key:            []byte("key"),
		LifeTime:       time.Hour,
		AgeAdd:         time.Hour,
		Nonce:          []byte("nonce"),
		EarlyDataLimit: 1,
		Version:        common.VersionTLS12,
		CipherSuite:    ciphersuite.Suite{},
		ServerName:     "www.example.com",
	}

	timePassed := time.Hour

	psk := TicketToPSK(ticket, timePassed)

	assert.Equal(t, ticket.Type, psk.Type)
	assert.Equal(t, ticket.Ticket, psk.Identity)
	assert.Equal(t, ticket.Key, psk.Key)
	assert.Equal(t, ticket.AgeAdd, psk.ObfuscatedAge-timePassed)
	assert.Equal(t, ticket.CipherSuite, psk.CipherSuite)
}

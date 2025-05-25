package tls

import (
	"network-stack/session/tls/common/ciphersuite"
	"testing"

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
		cipherSuite: suite,
		transcript:  suite.Hash().New(),
	}
}

func (s *SessionTestSuite) TestSetEarlySecretNoSecret() {
	// Providing nil secret will make session create a new one.
	s.NoError(s.session.setEarlySecret(nil))

	s.False(s.session.resumed)
	s.NotNil(s.session.secret)
}

func (s *SessionTestSuite) TestSetEarlySecretPreSharedSecret() {
	secret := []byte("haha missed me?")

	// Providing secret will make session use it right away.
	s.NoError(s.session.setEarlySecret(secret))

	s.True(s.session.resumed)
	s.Equal(secret, s.session.secret)
}

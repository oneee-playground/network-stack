package keyexchange

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/suite"
)

type ECDHEKeyExchangeTestSuite struct {
	suite.Suite

	ke ecdheKeyExchange
}

func TestECDHEKeyExchangeTestSuite(t *testing.T) {
	suite.Run(t, new(ECDHEKeyExchangeTestSuite))
}

func (s *ECDHEKeyExchangeTestSuite) SetupTest() {
	s.ke = ecdheKeyExchange{curve: ecdh.P256()}
}

func (s *ECDHEKeyExchangeTestSuite) TestGenKeyPair() {
	priv, pub, err := s.ke.GenKeyPair(rand.Reader)
	s.Require().NoError(err)

	s.NotNil(priv)
	s.NotNil(pub)

	privKey, err := s.ke.curve.NewPrivateKey(priv)
	s.Require().NoError(err)
	s.NotNil(privKey)

	pubKey, err := s.ke.curve.NewPublicKey(pub)
	s.Require().NoError(err)
	s.NotNil(pubKey)
}

func (s *ECDHEKeyExchangeTestSuite) TestGenSharedSecret() {
	// Generate key pairs for two parties
	privA, pubA, err := s.ke.GenKeyPair(rand.Reader)
	s.Require().NoError(err)

	privB, pubB, err := s.ke.GenKeyPair(rand.Reader)
	s.Require().NoError(err)

	// Generate shared secrets
	sharedA, err := s.ke.GenSharedSecret(privA, pubB)
	s.Require().NoError(err)

	sharedB, err := s.ke.GenSharedSecret(privB, pubA)
	s.Require().NoError(err)

	// Shared secrets should be equal
	s.Equal(sharedA, sharedB)
}

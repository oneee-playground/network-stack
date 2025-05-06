package keyexchange

import (
	"crypto/ecdh"
	"io"

	"github.com/pkg/errors"
)

type KeyExchange interface {
	GenKeyPair(rand io.Reader) (priv, pub []byte, err error)
	GenSharedSecret(priv, pub []byte) (shared []byte, err error)
}

type ecdheKeyExchange struct{ curve ecdh.Curve }

var _ KeyExchange = ecdheKeyExchange{}

func (e ecdheKeyExchange) GenKeyPair(rand io.Reader) (priv []byte, pub []byte, err error) {
	privKey, err := e.curve.GenerateKey(rand)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating key via ecdh")
	}

	pubKey := privKey.PublicKey()

	return privKey.Bytes(), pubKey.Bytes(), nil
}

func (e ecdheKeyExchange) GenSharedSecret(priv []byte, pub []byte) (shared []byte, err error) {
	privKey, err := e.curve.NewPrivateKey(priv)
	if err != nil {
		return nil, errors.Wrap(err, "parsing private key")
	}

	pubKey, err := e.curve.NewPublicKey(pub)
	if err != nil {
		return nil, errors.Wrap(err, "parsing public key")
	}

	if shared, err = privKey.ECDH(pubKey); err != nil {
		return nil, errors.Wrap(err, "creating shared secret")
	}

	return shared, nil
}

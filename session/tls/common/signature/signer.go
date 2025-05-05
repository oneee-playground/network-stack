package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

var ErrUnsupportedKey = errors.New("unsupported private/public key")

type Signer interface {
	Sign(data []byte, hash crypto.Hash, privKey crypto.PrivateKey) (out []byte, err error)
	Verify(data, signature []byte, hash crypto.Hash, publicKey crypto.PublicKey) (err error)
}

type signerRSA_PKCS1v15 struct{}

var _ Signer = signerRSA_PKCS1v15{}

func (s signerRSA_PKCS1v15) Sign(data []byte, hash crypto.Hash, privKey crypto.PrivateKey) (out []byte, err error) {
	key, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrUnsupportedKey
	}
	return rsa.SignPKCS1v15(nil, key, hash, data)
}

func (s signerRSA_PKCS1v15) Verify(data []byte, signature []byte, hash crypto.Hash, publicKey crypto.PublicKey) (err error) {
	key, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return ErrUnsupportedKey
	}
	return rsa.VerifyPKCS1v15(key, hash, data, signature)
}

type signerECDSA struct{ curve elliptic.Curve }

var _ Signer = signerECDSA{}

func (s signerECDSA) Sign(data []byte, hash crypto.Hash, privKey crypto.PrivateKey) (out []byte, err error) {
	key, ok := privKey.(*ecdsa.PrivateKey)
	if !ok || key.Curve != s.curve {
		return nil, ErrUnsupportedKey
	}

	return ecdsa.SignASN1(rand.Reader, key, data) // TODO: make rand reader configurable.
}

func (s signerECDSA) Verify(data []byte, signature []byte, hash crypto.Hash, publicKey crypto.PublicKey) (err error) {
	key, ok := publicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != s.curve {
		return ErrUnsupportedKey
	}

	if ok = ecdsa.VerifyASN1(key, data, signature); !ok {
		return errors.New("invalid signature")
	}
	return nil
}

type signerRSA_PSS struct{}

var _ Signer = signerRSA_PSS{}

func (s signerRSA_PSS) Sign(data []byte, hash crypto.Hash, privKey crypto.PrivateKey) (out []byte, err error) {
	key, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrUnsupportedKey
	}

	return rsa.SignPSS(rand.Reader, key, hash, data, &rsa.PSSOptions{
		SaltLength: hash.Size(),
		Hash:       hash,
	}) // TODO: make rand reader configurable.
}

func (s signerRSA_PSS) Verify(data []byte, signature []byte, hash crypto.Hash, publicKey crypto.PublicKey) (err error) {
	key, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return ErrUnsupportedKey
	}

	return rsa.VerifyPSS(key, hash, data, signature, &rsa.PSSOptions{
		SaltLength: hash.Size(),
		Hash:       hash,
	})
}

type signerEdDSA struct{}

var _ Signer = signerEdDSA{}

func (s signerEdDSA) Sign(data []byte, hash crypto.Hash, privKey crypto.PrivateKey) (out []byte, err error) {
	key, ok := privKey.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrUnsupportedKey
	}

	return ed25519.Sign(key, data), nil
}

func (s signerEdDSA) Verify(data []byte, signature []byte, hash crypto.Hash, publicKey crypto.PublicKey) (err error) {
	key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return ErrUnsupportedKey
	}

	return ed25519.VerifyWithOptions(key, data, signature, &ed25519.Options{
		Hash: hash,
	})
}

package signature

import (
	"crypto"

	"github.com/pkg/errors"
)

type Algorithm struct {
	id     Scheme
	signer Signer
	hash   crypto.Hash
}

func (a Algorithm) ID() Scheme { return a.id }

func (a Algorithm) Sign(data []byte, privKey any) (out []byte, err error) {
	if a.hash.Available() {
		h := a.hash.New()
		h.Write(data)
		data = a.hash.New().Sum(nil)
	}

	if out, err = a.signer.Sign(data, a.hash, privKey); err != nil {
		return nil, errors.Wrap(err, "signing data")
	}

	return out, nil
}

func (a Algorithm) Verify(data, signature []byte, publicKey any) (ok bool, err error) {
	if a.hash.Available() {
		h := a.hash.New()
		h.Write(data)
		data = a.hash.New().Sum(nil)
	}

	if err = a.signer.Verify(data, signature, a.hash, publicKey); err != nil {
		return false, errors.Wrap(err, "verifying data")
	}

	return true, nil
}

func NewAlgorithm(id Scheme, signer Signer, hash crypto.Hash) Algorithm {
	return Algorithm{
		id:     id,
		signer: signer,
		hash:   hash,
	}
}

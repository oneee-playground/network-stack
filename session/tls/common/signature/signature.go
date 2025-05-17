package signature

import (
	"crypto"
	"crypto/x509"
	"io"

	"github.com/pkg/errors"
)

type Algorithm struct {
	id     Scheme
	signer Signer
	hash   crypto.Hash
}

func (a Algorithm) ID() Scheme { return a.id }

func (a Algorithm) Sign(rand io.Reader, data []byte, privKey any) (out []byte, err error) {
	if a.hash.Available() {
		h := a.hash.New()
		h.Write(data)
		data = a.hash.New().Sum(nil)
	}

	if out, err = a.signer.Sign(rand, data, a.hash, privKey); err != nil {
		return nil, errors.Wrap(err, "signing data")
	}

	return out, nil
}

func (a Algorithm) Verify(data, signature []byte, publicKey any) (err error) {
	if a.hash.Available() {
		h := a.hash.New()
		h.Write(data)
		data = a.hash.New().Sum(nil)
	}

	if err = a.signer.Verify(data, signature, a.hash, publicKey); err != nil {
		return errors.Wrap(err, "verifying data")
	}

	return nil
}

func NewAlgorithm(id Scheme, signer Signer, hash crypto.Hash) Algorithm {
	return Algorithm{
		id:     id,
		signer: signer,
		hash:   hash,
	}
}

func AlgorithmFromX509Cert(cert *x509.Certificate) (algo Algorithm, err error) {
	var ok bool
	switch cert.SignatureAlgorithm {
	case x509.SHA1WithRSA:
		algo, ok = Get(Scheme_RSA_PKCS1_SHA1)
	case x509.SHA256WithRSA:
		algo, ok = Get(Scheme_RSA_PKCS1_SHA256)
	case x509.SHA384WithRSA:
		algo, ok = Get(Scheme_RSA_PKCS1_SHA384)
	case x509.SHA512WithRSA:
		algo, ok = Get(Scheme_RSA_PKCS1_SHA512)
	case x509.ECDSAWithSHA1:
		algo, ok = Get(Scheme_ECDSA_SHA1)
	case x509.ECDSAWithSHA256:
		algo, ok = Get(Scheme_ECDSA_Secp256r1_SHA256)
	case x509.ECDSAWithSHA384:
		algo, ok = Get(Scheme_ECDSA_Secp384r1_SHA384)
	case x509.ECDSAWithSHA512:
		algo, ok = Get(Scheme_ECDSA_Secp521r1_SHA512)
	case x509.SHA256WithRSAPSS:
		algo, ok = Get(Scheme_RSA_PSS_PSS_SHA256)
	case x509.SHA384WithRSAPSS:
		algo, ok = Get(Scheme_RSA_PSS_PSS_SHA384)
	case x509.SHA512WithRSAPSS:
		algo, ok = Get(Scheme_RSA_PSS_PSS_SHA512)
	case x509.PureEd25519:
		algo, ok = Get(Scheme_Ed25519)
	default:
		ok = false
	}

	if !ok {
		return Algorithm{}, errors.New("unsupported algorithm")
	}

	return algo, nil
}

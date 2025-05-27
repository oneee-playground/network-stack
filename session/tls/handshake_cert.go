package tls

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	sliceutil "network-stack/lib/slice"
	"network-stack/session/tls/common/signature"
	"network-stack/session/tls/internal/handshake"
	"network-stack/session/tls/internal/handshake/extension"
	"slices"
	"time"

	"github.com/pkg/errors"
)

type certificateRequestInfo struct {
	serverNames             []string
	requestContext          []byte
	signatureAlgorithms     []signature.Scheme
	signatureAlgorithmsCert []signature.Scheme
	acceptableCA            []pkix.Name
}

func (cri *certificateRequestInfo) matches(chain CertificateChain) (err error) {
	for idx, cert := range chain.cachedX509Certs {
		// First check if all the certs in chain uses supported signature.
		algo, err := signature.AlgorithmFromX509Cert(cert)
		if err != nil {
			return errors.Wrap(err, "getting signature algorithm for cert")
		}
		if !slices.Contains(cri.signatureAlgorithmsCert, algo.ID()) {
			return errors.New("signature algorithm not allowed")
		}

		if idx == 0 {
			// Leaf certificate.
			for _, name := range cri.serverNames {
				if err := cert.VerifyHostname(name); err != nil {
					return errors.Wrap(err, "name doesn't match")
				}
			}
			if !slices.Contains(cri.signatureAlgorithms, algo.ID()) {
				return errors.New("signature algorithm not allowed")
			}
		}

		// See if cert contains acceptable CA.
		caOK := slices.ContainsFunc(cri.acceptableCA, func(ca pkix.Name) bool {
			return cert.Issuer.String() == ca.String()
		})

		if caOK {
			return nil
		}
	}

	return errors.New("no matching ca")
}

type CertificateChain struct {
	Chain   [][]byte
	PrivKey crypto.PrivateKey

	cachedX509Certs []*x509.Certificate
}

func (chain *CertificateChain) load() error {
	chain.cachedX509Certs = make([]*x509.Certificate, 0, len(chain.Chain))
	for _, rawCert := range chain.Chain {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return errors.Wrap(err, "parsing certificate")
		}

		chain.cachedX509Certs = append(chain.cachedX509Certs, cert)
	}

	return nil
}

// chainFromCertificate parses remote certificate chain. Private key will be nil.
func chainFromCertificate(cert *handshake.Certificate) (CertificateChain, error) {
	chain := CertificateChain{
		Chain: make([][]byte, len(cert.CertList)),
	}
	for idx, raw := range cert.CertList {
		chain.Chain[idx] = raw.CertData
	}

	return chain, chain.load()
}

func makeCertMessage(chain CertificateChain, context []byte) *handshake.Certificate {
	entries := sliceutil.Map(chain.Chain, func(cert []byte) handshake.CertificateEntry {
		return handshake.CertificateEntry{
			CertData:   cert,
			Extensions: []extension.Extension{},
		}
	})

	return &handshake.Certificate{
		CertRequestContext: context,
		CertList:           entries,
	}
}

// utility for operations related to certificates.
type certStore struct {
	signatureAlgos []signature.Algorithm

	isServer bool

	// For remote validation.
	trusted            *x509.CertPool
	signatureAlgosCert []signature.Scheme
	certAuthorities    [][]byte
	serverName         string
	remoteCert         *x509.Certificate

	// For sending.
	remoteCertRequest certificateRequestInfo

	chains []CertificateChain
}

func (cs *certStore) needRemoteAuth() bool { return cs.trusted != nil }
func (cs *certStore) wantAuth() bool       { return len(cs.chains) > 0 }

func (cs *certStore) findCertChain() (CertificateChain, bool) {
	// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2.2
	for _, chain := range cs.chains {
		if err := cs.remoteCertRequest.matches(chain); err == nil {
			return chain, true
		}
	}

	return CertificateChain{}, false
}

// validate validates chain with trusted and stores remote certificate.
func (cs *certStore) validateChain(chain CertificateChain, now time.Time) error {
	// Validate certificate.
	leaf := chain.cachedX509Certs[0]

	intermediates := newCertPoolOrNil(chain.cachedX509Certs[1:])

	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       cs.serverName,
		Roots:         cs.trusted,
		Intermediates: intermediates,
		CurrentTime:   now,
	})
	if err != nil {
		return err
	}

	cs.remoteCert = leaf

	return nil
}

func (cs *certStore) makeSignature(
	chain CertificateChain, transcript []byte, random io.Reader,
) (scheme signature.Scheme, sig []byte, err error) {
	data := certificateSignatureInput(transcript, cs.isServer)

	algo, _ := signature.AlgorithmFromX509Cert(chain.cachedX509Certs[0])

	signature, err := algo.Sign(random, data, chain.PrivKey)
	if err != nil {
		return 0, nil, errors.Wrap(err, "computing signature")
	}

	return algo.ID(), signature, nil
}

func (cs *certStore) validateSignature(scheme signature.Scheme, transcript, signature []byte) error {
	isRemoteServer := !cs.isServer

	data := certificateSignatureInput(transcript, isRemoteServer)

	for _, algo := range cs.signatureAlgos {
		if scheme != algo.ID() {
			continue
		}

		if err := algo.Verify(data, signature, cs.remoteCert.PublicKey); err != nil {
			return errors.Wrap(err, "invalid signature")
		}

		return nil
	}

	return errors.New("no supported algorithm")
}

var signatureInputprefix = [64]byte{
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20,
}

func certificateSignatureInput(
	transcriptHash []byte,
	isServer bool,
) []byte {
	context := "TLS 1.3, client CertificateVerify"
	if isServer {
		context = "TLS 1.3, server CertificateVerify"
	}

	data := append(signatureInputprefix[:], []byte(context)...)
	data = append(data, 0x00)
	data = append(data, transcriptHash...)
	return data
}

func unmarshalPKIXName(b []byte) (name pkix.Name, err error) {
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(b, &rdn); err != nil {
		return pkix.Name{}, err
	}

	name.FillFromRDNSequence(&rdn)

	return name, nil
}

func newCertPoolOrNil(certs []*x509.Certificate) *x509.CertPool {
	if len(certs) == 0 {
		return nil
	}

	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

func signatureAlgoAndCAFromCerts(
	certs []*x509.Certificate,
) (algos []signature.Scheme, authorities [][]byte, err error) {
	algos = make([]signature.Scheme, len(certs))
	authorities = make([][]byte, len(certs))

	for idx, cert := range certs {
		algo, err := signature.AlgorithmFromX509Cert(cert)
		if err != nil {
			return nil, nil, errors.Wrap(err, "getting signature algorithm from certificate")
		}

		algos[idx] = algo.ID()
		authorities[idx] = cert.RawSubject
	}

	return algos, authorities, nil
}

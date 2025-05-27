package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"network-stack/session/tls/common/signature"
	"testing"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestCertificateRequestInfoMatches(t *testing.T) {
	root, priv := newRootCert(clock.New())
	cert, raw, myPriv := issueNewCert(defaultCertTemplate(clock.New()), root, priv)

	chain := CertificateChain{
		Chain:   [][]byte{raw},
		PrivKey: myPriv,
	}
	require.NoError(t, chain.load())

	cri := certificateRequestInfo{
		serverNames:             cert.DNSNames,
		signatureAlgorithms:     []signature.Scheme{signature.Scheme_ECDSA_Secp256r1_SHA256},
		signatureAlgorithmsCert: []signature.Scheme{signature.Scheme_ECDSA_Secp256r1_SHA256},
		acceptableCA:            []pkix.Name{root.Subject},
	}

	assert.NoError(t, cri.matches(chain))
}

type CertificateChainTestSuite struct {
	suite.Suite
}

func TestCertificateChainTestSuite(t *testing.T) {
	suite.Run(t, new(CertificateChainTestSuite))
}

func (s *CertificateChainTestSuite) TestLoad() {
	// This could be the example usage of how to pass certificate.

	root, priv := newRootCert(clock.New())
	_, raw, myPriv := issueNewCert(defaultCertTemplate(clock.New()), root, priv)

	chain := CertificateChain{
		Chain:   [][]byte{raw},
		PrivKey: myPriv,
	}

	s.NoError(chain.load())
}

type CertStoreTestSuite struct {
	suite.Suite

	store *certStore
	cert  *x509.Certificate
}

func TestCertStoreTestSuite(t *testing.T) {
	suite.Run(t, new(CertStoreTestSuite))
}

func (s *CertStoreTestSuite) SetupTest() {
	algo, _ := signature.Get(signature.Scheme_ECDSA_Secp256r1_SHA256)
	algos := []signature.Scheme{algo.ID()}

	root, priv := newRootCert(clock.New())
	cert, raw, myPriv := issueNewCert(defaultCertTemplate(clock.New()), root, priv)

	s.cert = cert

	chain := CertificateChain{
		Chain:   [][]byte{raw},
		PrivKey: myPriv,
	}
	s.Require().NoError(chain.load())

	s.store = &certStore{
		signatureAlgos:     []signature.Algorithm{algo},
		isServer:           true,
		trusted:            newCertPoolOrNil([]*x509.Certificate{root}),
		signatureAlgosCert: algos,
		certAuthorities:    [][]byte{root.RawSubject},
		serverName:         cert.DNSNames[0],
		chains:             []CertificateChain{chain},
	}
}
func (s *CertStoreTestSuite) TestValidateChain() {
	// It was signed by store's trusted cert. So it should be valid.
	chain := s.store.chains[0]

	s.NoError(s.store.validateChain(chain, clock.New().Now()))
}

func (s *CertStoreTestSuite) TestSignature() {
	// We test makeSignature & validateSignature at once. Since it is more convinient.
	chain := s.store.chains[0]
	transcript := []byte("ayo the pizza here")

	scheme, signature, err := s.store.makeSignature(chain, transcript, rand.Reader)
	s.Require().NoError(err)

	// We make our certStore to be remote so we can validate it without problems.
	s.store.isServer = !s.store.isServer
	s.store.remoteCert = s.cert

	s.NoError(s.store.validateSignature(scheme, transcript, signature))
}

func TestCertificateSignatureInput(t *testing.T) {
	// Example on RFC: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3
	expected := []byte{
		// 64 spaces (0x20)
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,

		// "TLS 1.3, server CertificateVerify"
		0x54, 0x4c, 0x53, 0x20, 0x31, 0x2e, 0x33, 0x2c,
		0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20,
		0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
		0x61, 0x74, 0x65, 0x56, 0x65, 0x72, 0x69, 0x66,
		0x79,

		// Separator
		0x00,

		// 32 bytes of 0x01
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	}

	transcript := []byte{
		// 32 bytes of 0x01
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	}

	input := certificateSignatureInput(transcript, true)

	assert.Equal(t, expected, input)
}

func TestNewCertPoolOrNil(t *testing.T) {
	assert.Nil(t, newCertPoolOrNil([]*x509.Certificate{}))
	assert.NotNil(t, newCertPoolOrNil([]*x509.Certificate{{}, {}}))
}

func TestSignatureAlgoAndCAFromCerts(t *testing.T) {
	cert, _ := newRootCert(clock.New())

	algos, authorities, err := signatureAlgoAndCAFromCerts([]*x509.Certificate{cert})
	require.NoError(t, err)

	assert.Equal(t, []signature.Scheme{signature.Scheme_ECDSA_Secp256r1_SHA256}, algos)
	assert.Equal(t, [][]byte{cert.RawSubject}, authorities)
}

func TestUnmarshalPKIXName(t *testing.T) {
	name, raw := newPKIXName()

	got, err := unmarshalPKIXName(raw)
	require.NoError(t, err)

	assert.Equal(t, name.ToRDNSequence().String(), got.ToRDNSequence().String())
}

func newPKIXName() (pkix.Name, []byte) {
	name := pkix.Name{
		CommonName:         "example.com",
		Country:            []string{"US"},
		Organization:       []string{"Example Corp"},
		OrganizationalUnit: []string{"IT Department"},
		Locality:           []string{"San Francisco"},
		Province:           []string{"California"},
		StreetAddress:      []string{"123 Example St"},
		PostalCode:         []string{"94101"},
	}

	// Convert to RDNSequence (ASN.1 structure for Distinguished Name)
	rdn := name.ToRDNSequence()

	// Marshal to DER-encoded ASN.1 bytes
	derBytes, err := asn1.Marshal(rdn)
	if err != nil {
		panic(err)
	}

	return name, derBytes
}

func newRootCert(clock clock.Clock) (*x509.Certificate, crypto.PrivateKey) {
	// Generate ECDSA root key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Create a certificate template for the root CA
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Example Root CA",
			Organization: []string{"Example Org"},
			Country:      []string{"US"},
		},
		NotBefore:             clock.Now(),
		NotAfter:              clock.Now().AddDate(10, 0, 0), // valid for 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	// Self-sign the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}

	// Parse the DER-encoded certificate
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		panic(err)
	}

	return cert, priv
}

func issueNewCert(template, parent *x509.Certificate, parentKey crypto.PrivateKey) (*x509.Certificate, []byte, crypto.PrivateKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &priv.PublicKey, parentKey)
	if err != nil {
		panic(err)
	}

	// Parse the DER-encoded certificate
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		panic(err)
	}

	return cert, derBytes, priv
}

func defaultCertTemplate(clock clock.Clock) *x509.Certificate {
	return &x509.Certificate{
		DNSNames:     []string{"www.example.com"},
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "example.com",
			Organization: []string{"Example Org"},
		},
		NotBefore:             clock.Now(),
		NotAfter:              clock.Now().AddDate(1, 0, 0), // available for an year.
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
}

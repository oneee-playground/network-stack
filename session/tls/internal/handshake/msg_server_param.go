package handshake

import (
	"bytes"
	"network-stack/lib/types"
	"network-stack/session/tls/internal/handshake/extension"
	"network-stack/session/tls/internal/util"

	"github.com/pkg/errors"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.1
type EncryptedExtensions struct {
	ExtServerNameList  *extension.ServerNameList
	ExtSupportedGroups *extension.SupportedGroups
	ExtEarlyData       *extension.EarlyDataEE
}

var _ Handshake = (*EncryptedExtensions)(nil)

func (*EncryptedExtensions) messageType() handshakeType {
	return typeEncryptedExtensions
}

func (e *EncryptedExtensions) data() []byte {
	buf := bytes.NewBuffer(nil)
	raws := extension.ToRaw(
		e.ExtServerNameList,
		e.ExtSupportedGroups,
		e.ExtEarlyData,
	)
	extension.WriteRaws(raws, buf)

	return buf.Bytes()
}

func (e *EncryptedExtensions) length() types.Uint24 {
	l := 2 + uint32(extension.ByteLen(
		e.ExtServerNameList,
		e.ExtSupportedGroups,
		e.ExtEarlyData,
	))
	return types.NewUint24(l)
}

func (e *EncryptedExtensions) fillFrom(b []byte) (err error) {
	raws, err := extension.Parse(b, false)
	if err != nil {
		return errors.Wrap(err, "reading encryptedExtensions")
	}

	if e.ExtServerNameList, err = extension.Extract(raws, e.ExtServerNameList); err != nil {
		return errors.Wrap(err, "sni")
	}
	if e.ExtSupportedGroups, err = extension.Extract(raws, e.ExtSupportedGroups); err != nil {
		return errors.Wrap(err, "supported groups")
	}
	if e.ExtEarlyData, err = extension.Extract(raws, e.ExtEarlyData); err != nil {
		return errors.Wrap(err, "early data")
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
type CertificateRequest struct {
	CertRequestContext []byte

	ExtSignatureAlgos     *extension.SignatureAlgos
	ExtSignatureAlgosCert *extension.SignatureAlgosCert
	ExtCertAuthorities    *extension.CertAuthorities
	ExtOIDFilters         *extension.OIDFilters
}

var _ Handshake = (*CertificateRequest)(nil)

func (*CertificateRequest) messageType() handshakeType {
	return typeCertificateRequest
}

func (e *CertificateRequest) data() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(util.ToVectorOpaque(1, e.CertRequestContext))

	raws := extension.ToRaw(
		e.ExtSignatureAlgos,
		e.ExtSignatureAlgosCert,
		e.ExtCertAuthorities,
		e.ExtOIDFilters,
	)
	extension.WriteRaws(raws, buf)

	return buf.Bytes()
}

func (e *CertificateRequest) length() types.Uint24 {
	l := uint32(1 + len(e.CertRequestContext))
	l += 2 + uint32(extension.ByteLen(
		e.ExtSignatureAlgos,
		e.ExtSignatureAlgosCert,
		e.ExtCertAuthorities,
		e.ExtOIDFilters,
	))
	return types.NewUint24(l)
}

func (e *CertificateRequest) fillFrom(b []byte) (err error) {
	e.CertRequestContext, b, err = util.FromVectorOpaque(1, b, true)
	if err != nil {
		return errors.Wrap(err, "reading certRequestContext")
	}

	raws, err := extension.Parse(b, false)
	if err != nil {
		return errors.Wrap(err, "reading extensions")
	}

	if e.ExtSignatureAlgos, err = extension.Extract(raws, e.ExtSignatureAlgos); err != nil {
		return errors.Wrap(err, "signature algorithms")
	}
	if e.ExtSignatureAlgosCert, err = extension.Extract(raws, e.ExtSignatureAlgosCert); err != nil {
		return errors.Wrap(err, "signature algorithms cert")
	}
	if e.ExtCertAuthorities, err = extension.Extract(raws, e.ExtCertAuthorities); err != nil {
		return errors.Wrap(err, "cert authorities")
	}
	if e.ExtOIDFilters, err = extension.Extract(raws, e.ExtOIDFilters); err != nil {
		return errors.Wrap(err, "oid filters")
	}

	return nil
}

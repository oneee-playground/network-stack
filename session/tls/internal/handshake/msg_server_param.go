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
	Extensions extension.Extensions
}

var _ Handshake = (*EncryptedExtensions)(nil)

func (*EncryptedExtensions) messageType() handshakeType {
	return typeEncryptedExtensions
}

func (e *EncryptedExtensions) data() []byte {
	buf := bytes.NewBuffer(nil)
	e.Extensions.WriteTo(buf)
	return buf.Bytes()
}

func (e *EncryptedExtensions) length() types.Uint24 {
	l := 2 + uint32(e.Extensions.Length())
	return types.NewUint24(l)
}

func (e *EncryptedExtensions) fillFrom(b []byte) (err error) {
	e.Extensions, err = extension.ExtensionsFromRaw(b)
	if err != nil {
		return errors.Wrap(err, "reading encryptedExtensions")
	}
	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
type CertificateRequest struct {
	CertRequestContext []byte
	Extensions         extension.Extensions
}

var _ Handshake = (*CertificateRequest)(nil)

func (*CertificateRequest) messageType() handshakeType {
	return typeCertificateRequest
}

func (e *CertificateRequest) data() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(util.ToVectorOpaque(1, e.CertRequestContext))
	e.Extensions.WriteTo(buf)

	return buf.Bytes()
}

func (e *CertificateRequest) length() types.Uint24 {
	l := uint32(1 + len(e.CertRequestContext))
	l += 2 + uint32(e.Extensions.Length())
	return types.NewUint24(l)
}

func (e *CertificateRequest) fillFrom(b []byte) (err error) {
	e.CertRequestContext, b, err = util.FromVectorOpaque(1, b, true)
	if err != nil {
		return errors.Wrap(err, "reading certRequestContext")
	}

	e.Extensions, err = extension.ExtensionsFromRaw(b)
	if err != nil {
		return errors.Wrap(err, "reading extensions")
	}

	return nil
}

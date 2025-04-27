package handshake

import (
	"bytes"
	"network-stack/lib/types"
	"network-stack/session/tls/common"
	"network-stack/session/tls/handshake/extension"

	"github.com/pkg/errors"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.1
type encryptedExtensions struct {
	extensions extension.Extensions
}

var _ handshake = (*encryptedExtensions)(nil)

func (*encryptedExtensions) messageType() handshakeType {
	return typeEncryptedExtensions
}

func (e *encryptedExtensions) data() []byte {
	buf := bytes.NewBuffer(nil)
	e.extensions.WriteTo(buf)
	return buf.Bytes()
}

func (e *encryptedExtensions) length() types.Uint24 {
	l := 2 + uint32(e.extensions.Length())
	return types.NewUint24(l)
}

func (e *encryptedExtensions) fillFrom(b []byte) (err error) {
	e.extensions, err = extension.ExtensionsFromRaw(b)
	if err != nil {
		return errors.Wrap(err, "reading encryptedExtensions")
	}
	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
type certificateRequest struct {
	certRequestContext []byte
	extensions         extension.Extensions
}

var _ handshake = (*certificateRequest)(nil)

func (*certificateRequest) messageType() handshakeType {
	return typeCertificateRequest
}

func (e *certificateRequest) data() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(common.ToVectorOpaque(1, e.certRequestContext))
	e.extensions.WriteTo(buf)

	return buf.Bytes()
}

func (e *certificateRequest) length() types.Uint24 {
	l := uint32(1 + len(e.certRequestContext))
	l += 2 + uint32(e.extensions.Length())
	return types.NewUint24(l)
}

func (e *certificateRequest) fillFrom(b []byte) (err error) {
	e.certRequestContext, b, err = common.FromVectorOpaque(1, b, true)
	if err != nil {
		return errors.Wrap(err, "reading certRequestContext")
	}

	e.extensions, err = extension.ExtensionsFromRaw(b)
	if err != nil {
		return errors.Wrap(err, "reading extensions")
	}

	return nil
}

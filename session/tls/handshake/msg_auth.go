package handshake

import (
	"bytes"
	"encoding/binary"
	"network-stack/lib/types"
	"network-stack/session/tls/common"
	"network-stack/session/tls/handshake/extension"

	"github.com/pkg/errors"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
type certType uint8

const (
	typeX509         certType = 0
	typeRawPublicKey certType = 2
)

type certificateEntry struct {
	// could be ASN1_subjectPublicKeyInfo. See: https://datatracker.ietf.org/doc/html/rfc7250
	certData   []byte
	extensions extension.Extensions
}

var _ (common.VerctorConv) = certificateEntry{}

func (c certificateEntry) Bytes() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(common.ToVectorOpaque(3, c.certData))
	c.extensions.WriteTo(buf)

	return buf.Bytes()
}

func (c certificateEntry) FromBytes(b []byte) (out common.VerctorConv, rest []byte, err error) {
	c.certData, rest, err = common.FromVectorOpaque(3, b, true)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading cert data")
	}

	c.extensions, err = extension.ExtensionsFromRaw(rest)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading extensions")
	}

	rest = rest[2+c.extensions.Length():]
	return c, rest, nil
}

type certificate struct {
	certRequestContext []byte
	certList           []certificateEntry
}

var _ handshake = (*certificate)(nil)

func (*certificate) messageType() handshakeType {
	return typeCertificate
}

func (c *certificate) data() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(common.ToVectorOpaque(1, c.certRequestContext))
	buf.Write(common.ToVector(3, c.certList))

	return buf.Bytes()
}

func (c *certificate) length() types.Uint24 {
	l := uint32(1 + len(c.certRequestContext))

	l += 3
	for _, entry := range c.certList {
		l += uint32(len(entry.Bytes()))
	}

	return types.NewUint24(l)
}

func (c *certificate) fillFrom(b []byte) (err error) {
	c.certRequestContext, b, err = common.FromVectorOpaque(1, b, true)
	if err != nil {
		return errors.Wrap(err, "reading certificate request context")
	}

	c.certList, _, err = common.FromVector[certificateEntry](3, b, false)
	if err != nil {
		return errors.Wrap(err, "reading certificate list")
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3
type certificateVerify struct {
	algorithm extension.SigScheme
	signature []byte
}

var _ handshake = (*certificateVerify)(nil)

func (c *certificateVerify) messageType() handshakeType {
	return typeCertificateVerify
}

func (c *certificateVerify) data() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(c.algorithm.Bytes())
	buf.Write(common.ToVectorOpaque(2, c.signature))

	return buf.Bytes()
}

func (c *certificateVerify) length() types.Uint24 {
	l := uint32(2)
	l += 2 + uint32(len(c.signature))
	return types.NewUint24(l)
}

func (c *certificateVerify) fillFrom(b []byte) (err error) {
	if len(b) < 2 {
		return errors.New("insufficient data to read algorithm")
	}

	c.algorithm = extension.SigScheme(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]

	c.signature, _, err = common.FromVectorOpaque(2, b, false)
	if err != nil {
		return errors.Wrap(err, "reading signature")
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
type finished struct {
	verifyData []byte
}

var _ handshake = (*finished)(nil)

func (*finished) messageType() handshakeType {
	return typeFinished
}

func (f *finished) data() []byte {
	return f.verifyData
}

func (f *finished) length() types.Uint24 {
	return types.NewUint24(uint32(len(f.verifyData)))
}

func (f *finished) fillFrom(b []byte) error {
	if len(b) == 0 {
		return errors.New("insufficient data to read verifyData")
	}

	f.verifyData = make([]byte, len(b))
	copy(f.verifyData, b)

	return nil
}

type endOfEarlyData struct{}

var _ handshake = (*endOfEarlyData)(nil)

func (*endOfEarlyData) messageType() handshakeType { return typeEndOfEarlyData }
func (*endOfEarlyData) data() []byte               { return []byte{} }
func (*endOfEarlyData) length() types.Uint24       { return types.NewUint24(0) }
func (c *endOfEarlyData) fillFrom(b []byte) error {
	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.1
type newSessionTicket struct {
	ticketLifetime uint32
	ticketAgeAdd   uint32
	ticketNonce    []byte
	ticket         []byte
	extensions     extension.Extensions
}

var _ handshake = (*newSessionTicket)(nil)

func (n *newSessionTicket) messageType() handshakeType {
	return typeNewSessionTicket
}

func (n *newSessionTicket) data() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(common.ToBigEndianBytes(uint(n.ticketLifetime), 4))
	buf.Write(common.ToBigEndianBytes(uint(n.ticketAgeAdd), 4))
	buf.Write(common.ToVectorOpaque(1, n.ticketNonce))
	buf.Write(common.ToVectorOpaque(2, n.ticket))
	n.extensions.WriteTo(buf)

	return buf.Bytes()
}

func (n *newSessionTicket) length() types.Uint24 {
	l := uint32(4 + 4) // ticket_lifetime, ticket_age_add
	l += 1 + uint32(len(n.ticketNonce))
	l += 2 + uint32(len(n.ticket))
	l += 2 + uint32(n.extensions.Length())
	return types.NewUint24(l)
}

func (n *newSessionTicket) fillFrom(b []byte) (err error) {
	if len(b) < 8 {
		return errors.New("insufficient data to read ticketLifetime and ticketAgeAdd")
	}

	n.ticketLifetime = binary.BigEndian.Uint32(b[:4])
	b = b[4:]

	n.ticketAgeAdd = binary.BigEndian.Uint32(b[:4])
	b = b[4:]

	n.ticketNonce, b, err = common.FromVectorOpaque(1, b, true)
	if err != nil {
		return errors.Wrap(err, "reading ticketNonce")
	}

	n.ticket, b, err = common.FromVectorOpaque(2, b, true)
	if err != nil {
		return errors.Wrap(err, "reading ticket")
	}

	n.extensions, err = extension.ExtensionsFromRaw(b)
	if err != nil {
		return errors.Wrap(err, "reading extensions")
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.3
type keyUpdateRequest uint8

const (
	UpdateNotRequested keyUpdateRequest = 0
	UpdateRequested    keyUpdateRequest = 1
)

type keyUpdate struct {
	requestUpdate keyUpdateRequest
}

var _ handshake = (*keyUpdate)(nil)

func (*keyUpdate) messageType() handshakeType {
	return typeKeyUpdate
}

func (k *keyUpdate) data() []byte {
	return common.ToBigEndianBytes(uint(k.requestUpdate), 1)
}

func (k *keyUpdate) length() types.Uint24 {
	return types.NewUint24(1)
}

func (k *keyUpdate) fillFrom(b []byte) error {
	if len(b) != 1 {
		return errors.New("invalid length for keyUpdate message")
	}

	k.requestUpdate = keyUpdateRequest(b[0])
	return nil
}

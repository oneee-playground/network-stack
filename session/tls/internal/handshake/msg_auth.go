package handshake

import (
	"bytes"
	"encoding/binary"
	"network-stack/lib/types"
	"network-stack/session/tls/common/signature"
	"network-stack/session/tls/internal/handshake/extension"
	"network-stack/session/tls/internal/util"

	"github.com/pkg/errors"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
type CertType uint8

const (
	CertTypeX509         CertType = 0
	CertTypeRawPublicKey CertType = 2
)

type CertificateEntry struct {
	// could be ASN1_subjectPublicKeyInfo. See: https://datatracker.ietf.org/doc/html/rfc7250
	CertData   []byte
	Extensions extension.Extensions
}

var _ (util.VerctorConv) = CertificateEntry{}

func (c CertificateEntry) Bytes() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(util.ToVectorOpaque(3, c.CertData))
	c.Extensions.WriteTo(buf)

	return buf.Bytes()
}

func (c CertificateEntry) FromBytes(b []byte) (out util.VerctorConv, rest []byte, err error) {
	c.CertData, rest, err = util.FromVectorOpaque(3, b, true)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading cert data")
	}

	c.Extensions, err = extension.ExtensionsFromRaw(rest)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading extensions")
	}

	rest = rest[2+c.Extensions.Length():]
	return c, rest, nil
}

type Certificate struct {
	CertRequestContext []byte
	CertList           []CertificateEntry
}

var _ Handshake = (*Certificate)(nil)

func (*Certificate) messageType() handshakeType {
	return typeCertificate
}

func (c *Certificate) data() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(util.ToVectorOpaque(1, c.CertRequestContext))
	buf.Write(util.ToVector(3, c.CertList))

	return buf.Bytes()
}

func (c *Certificate) length() types.Uint24 {
	l := uint32(1 + len(c.CertRequestContext))

	l += 3
	for _, entry := range c.CertList {
		l += uint32(len(entry.Bytes()))
	}

	return types.NewUint24(l)
}

func (c *Certificate) fillFrom(b []byte) (err error) {
	c.CertRequestContext, b, err = util.FromVectorOpaque(1, b, true)
	if err != nil {
		return errors.Wrap(err, "reading certificate request context")
	}

	c.CertList, _, err = util.FromVector[CertificateEntry](3, b, false)
	if err != nil {
		return errors.Wrap(err, "reading certificate list")
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3
type CertificateVerify struct {
	Algorithm signature.Scheme
	Signature []byte
}

var _ Handshake = (*CertificateVerify)(nil)

func (c *CertificateVerify) messageType() handshakeType {
	return typeCertificateVerify
}

func (c *CertificateVerify) data() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(c.Algorithm.Bytes())
	buf.Write(util.ToVectorOpaque(2, c.Signature))

	return buf.Bytes()
}

func (c *CertificateVerify) length() types.Uint24 {
	l := uint32(2)
	l += 2 + uint32(len(c.Signature))
	return types.NewUint24(l)
}

func (c *CertificateVerify) fillFrom(b []byte) (err error) {
	if len(b) < 2 {
		return errors.New("insufficient data to read algorithm")
	}

	c.Algorithm = signature.Scheme(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]

	c.Signature, _, err = util.FromVectorOpaque(2, b, false)
	if err != nil {
		return errors.Wrap(err, "reading signature")
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
type Finished struct {
	VerifyData []byte
}

var _ Handshake = (*Finished)(nil)

func (*Finished) messageType() handshakeType {
	return typeFinished
}

func (f *Finished) data() []byte {
	return f.VerifyData
}

func (f *Finished) length() types.Uint24 {
	return types.NewUint24(uint32(len(f.VerifyData)))
}

func (f *Finished) fillFrom(b []byte) error {
	if len(b) == 0 {
		return errors.New("insufficient data to read verifyData")
	}

	f.VerifyData = make([]byte, len(b))
	copy(f.VerifyData, b)

	return nil
}

type EndOfEarlyData struct{}

var _ Handshake = (*EndOfEarlyData)(nil)

func (*EndOfEarlyData) messageType() handshakeType { return typeEndOfEarlyData }
func (*EndOfEarlyData) data() []byte               { return []byte{} }
func (*EndOfEarlyData) length() types.Uint24       { return types.NewUint24(0) }
func (c *EndOfEarlyData) fillFrom(b []byte) error {
	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.1
type NewSessionTicket struct {
	TicketLifetime uint32
	TicketAgeAdd   uint32
	TicketNonce    []byte
	Ticket         []byte
	Extensions     extension.Extensions
}

var _ Handshake = (*NewSessionTicket)(nil)

func (n *NewSessionTicket) messageType() handshakeType {
	return typeNewSessionTicket
}

func (n *NewSessionTicket) data() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(util.ToBigEndianBytes(uint(n.TicketLifetime), 4))
	buf.Write(util.ToBigEndianBytes(uint(n.TicketAgeAdd), 4))
	buf.Write(util.ToVectorOpaque(1, n.TicketNonce))
	buf.Write(util.ToVectorOpaque(2, n.Ticket))
	n.Extensions.WriteTo(buf)

	return buf.Bytes()
}

func (n *NewSessionTicket) length() types.Uint24 {
	l := uint32(4 + 4) // ticket_lifetime, ticket_age_add
	l += 1 + uint32(len(n.TicketNonce))
	l += 2 + uint32(len(n.Ticket))
	l += 2 + uint32(n.Extensions.Length())
	return types.NewUint24(l)
}

func (n *NewSessionTicket) fillFrom(b []byte) (err error) {
	if len(b) < 8 {
		return errors.New("insufficient data to read ticketLifetime and ticketAgeAdd")
	}

	n.TicketLifetime = binary.BigEndian.Uint32(b[:4])
	b = b[4:]

	n.TicketAgeAdd = binary.BigEndian.Uint32(b[:4])
	b = b[4:]

	n.TicketNonce, b, err = util.FromVectorOpaque(1, b, true)
	if err != nil {
		return errors.Wrap(err, "reading ticketNonce")
	}

	n.Ticket, b, err = util.FromVectorOpaque(2, b, true)
	if err != nil {
		return errors.Wrap(err, "reading ticket")
	}

	n.Extensions, err = extension.ExtensionsFromRaw(b)
	if err != nil {
		return errors.Wrap(err, "reading extensions")
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.3
type KeyUpdateRequest uint8

const (
	UpdateNotRequested KeyUpdateRequest = 0
	UpdateRequested    KeyUpdateRequest = 1
)

type KeyUpdate struct {
	RequestUpdate KeyUpdateRequest
}

var _ Handshake = (*KeyUpdate)(nil)

func (*KeyUpdate) messageType() handshakeType {
	return typeKeyUpdate
}

func (k *KeyUpdate) data() []byte {
	return util.ToBigEndianBytes(uint(k.RequestUpdate), 1)
}

func (k *KeyUpdate) length() types.Uint24 {
	return types.NewUint24(1)
}

func (k *KeyUpdate) fillFrom(b []byte) error {
	if len(b) != 1 {
		return errors.New("invalid length for keyUpdate message")
	}

	k.RequestUpdate = KeyUpdateRequest(b[0])
	return nil
}

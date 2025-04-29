package extension

import (
	"bytes"
	"network-stack/session/tls/internal/util"

	"github.com/pkg/errors"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.4
type CertAuthorities struct {
	Authorities []DistinguishedName
}

type DistinguishedName []byte

func (d DistinguishedName) Bytes() []byte { return util.ToVectorOpaque(2, d) }
func (DistinguishedName) FromBytes(b []byte) (out util.VerctorConv, rest []byte, err error) {
	opaque, rest, err := util.FromVectorOpaque(2, b, true)
	if err != nil {
		return nil, nil, err
	}

	return DistinguishedName(opaque), rest, nil
}

var _ util.VerctorConv = (DistinguishedName)(nil)

var _ Extension = (*CertAuthorities)(nil)

func (c *CertAuthorities) ExtensionType() ExtensionType {
	return TypeCertAuthorities
}

func (c *CertAuthorities) Data() []byte {
	return util.ToVector(2, c.Authorities)
}

func (c *CertAuthorities) Length() uint16 {
	dLen := uint16(2)
	for _, authority := range c.Authorities {
		dLen += 2
		dLen += uint16(len(authority))
	}

	return dLen
}

func (c *CertAuthorities) fillFrom(raw rawExtension) error {
	out, _, err := util.FromVector[DistinguishedName](2, raw.data, false)
	if err != nil {
		return errors.Wrap(err, "reading authorities")
	}

	c.Authorities = out
	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.5
type OIDFilters struct {
	Filters []OIDFilter
}

type OIDFilter struct {
	CertExtensionOID    []byte
	CertExtensionValues []byte
}

func (o *OIDFilter) data() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(util.ToVectorOpaque(1, o.CertExtensionOID))
	buf.Write(util.ToVectorOpaque(2, o.CertExtensionValues))

	return buf.Bytes()
}

func (o *OIDFilter) length() uint16 {
	dLen := uint16(1)
	dLen += uint16(len(o.CertExtensionOID))
	dLen += uint16(2)
	dLen += uint16(len(o.CertExtensionValues))
	return dLen
}

func (o OIDFilter) Bytes() []byte { return o.data() }

func (o OIDFilter) FromBytes(b []byte) (out util.VerctorConv, rest []byte, err error) {
	opaqueOID, rest, err := util.FromVectorOpaque(1, b, true)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading oid")
	}

	opaqueValues, rest, err := util.FromVectorOpaque(2, rest, true)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading values")
	}

	o.CertExtensionOID = opaqueOID
	o.CertExtensionValues = opaqueValues

	return o, rest, nil
}

var _ util.VerctorConv = (*OIDFilter)(nil)

var _ Extension = (*OIDFilters)(nil)

func (o *OIDFilters) ExtensionType() ExtensionType {
	return TypeOidFilters
}

func (o *OIDFilters) Data() []byte {
	return util.ToVector(2, o.Filters)
}

func (o *OIDFilters) Length() uint16 {
	dLen := uint16(2)
	for _, filter := range o.Filters {
		dLen += filter.length()
	}

	return dLen
}

func (o *OIDFilters) fillFrom(raw rawExtension) error {
	out, _, err := util.FromVector[OIDFilter](2, raw.data, false)
	if err != nil {
		return errors.Wrap(err, "reading filters")
	}

	o.Filters = out
	return nil
}

package extension

import (
	"bytes"
	"encoding/binary"
	"network-stack/session/tls/internal/util"

	"github.com/pkg/errors"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
type NamedGroup uint16

func (n NamedGroup) Bytes() []byte {
	b := make([]byte, 2)
	b[0] = uint8(n >> 8)
	b[1] = uint8(n)
	return b
}

func (NamedGroup) FromBytes(b []byte) (out util.VectorConv, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, util.ErrVectorShort
	}

	out = NamedGroup(binary.BigEndian.Uint16(b))

	return out, b[2:], nil
}

var _ util.VectorConv = NamedGroup(0)

const (
	// Elliptic Curve Groups (ECDHE)
	NamedGroup_Secp256r1 NamedGroup = 0x0017
	NamedGroup_Secp384r1 NamedGroup = 0x0018
	NamedGroup_Secp521r1 NamedGroup = 0x0019
	NamedGroup_X25519    NamedGroup = 0x001D
	NamedGroup_X448      NamedGroup = 0x001E

	// Finite Field Groups (DHE)
	NamedGroup_FFDHE2048 NamedGroup = 0x0100
	NamedGroup_FFDHE3072 NamedGroup = 0x0101
	NamedGroup_FFDHE4096 NamedGroup = 0x0102
	NamedGroup_FFDHE6144 NamedGroup = 0x0103
	NamedGroup_FFDHE8192 NamedGroup = 0x0104

	// Reserved Code Points
	// FFDHE private use 0x01FC ~ 0x01FF
	// ECDHE private use 0xFE00 ~ 0xFEFF
)

type SupportedGroups struct {
	NamedGroupList []NamedGroup
}

var _ Extension = (*SupportedGroups)(nil)

func (s *SupportedGroups) ExtensionType() ExtensionType {
	return TypeSupportedGroups
}

func (s *SupportedGroups) Data() []byte {
	return util.ToVector(2, s.NamedGroupList)
}

func (s *SupportedGroups) Length() uint16 {
	return 2 + uint16(len(s.NamedGroupList))*2 // length + num named group * named group size
}

func (s *SupportedGroups) fillFrom(raw rawExtension) error {
	namedGroups, _, err := util.FromVector[NamedGroup](2, raw.data, false)
	if err != nil {
		return errors.Wrap(err, "reading named group list")
	}

	s.NamedGroupList = namedGroups
	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
type KeyShareEntry struct {
	Group       NamedGroup
	KeyExchange []byte
}

var _ util.VectorConv = KeyShareEntry{}

func (k KeyShareEntry) Bytes() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(k.Group.Bytes())
	buf.Write(util.ToVectorOpaque(2, k.KeyExchange))

	return buf.Bytes()
}

func (k KeyShareEntry) FromBytes(b []byte) (out util.VectorConv, rest []byte, err error) {
	group, rest, err := k.Group.FromBytes(b)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading group")
	}

	keyExchange, rest, err := util.FromVectorOpaque(2, rest, true)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading key exchange")
	}
	return KeyShareEntry{group.(NamedGroup), keyExchange}, rest, nil
}

type KeyShareCH struct{ KeyShares []KeyShareEntry }

var _ Extension = (*KeyShareCH)(nil)

func (k *KeyShareCH) ExtensionType() ExtensionType {
	return TypeKeyShare
}

func (k *KeyShareCH) Data() []byte {
	return util.ToVector(2, k.KeyShares)
}

func (k *KeyShareCH) Length() uint16 {
	dLen := uint16(2)
	for _, entry := range k.KeyShares {
		dLen += uint16(len(entry.Bytes()))
	}

	return dLen
}

func (k *KeyShareCH) fillFrom(raw rawExtension) error {
	entries, _, err := util.FromVector[KeyShareEntry](2, raw.data, false)
	if err != nil {
		return errors.Wrap(err, "reading key shares")
	}

	k.KeyShares = entries
	return nil
}

type KeyShareHRR struct{ SelectedGroup NamedGroup }

var _ Extension = (*KeyShareHRR)(nil)

func (k *KeyShareHRR) ExtensionType() ExtensionType {
	return TypeKeyShare
}

func (k *KeyShareHRR) Data() []byte {
	return k.SelectedGroup.Bytes()
}

func (k *KeyShareHRR) Length() uint16 {
	return 2
}

func (k *KeyShareHRR) fillFrom(raw rawExtension) error {
	group, rest, err := k.SelectedGroup.FromBytes(raw.data)
	if err != nil {
		return errors.Wrap(err, "reading group")
	}

	if len(rest) != 0 {
		return errors.New("invalid lnegth")
	}

	k.SelectedGroup = group.(NamedGroup)
	return nil
}

type KeyShareSH struct{ KeyShare KeyShareEntry }

var _ Extension = (*KeyShareSH)(nil)

func (k *KeyShareSH) ExtensionType() ExtensionType {
	return TypeKeyShare
}

func (k *KeyShareSH) Data() []byte {
	return k.KeyShare.Bytes()
}

func (k *KeyShareSH) Length() uint16 {
	return uint16(len(k.KeyShare.Bytes()))
}

func (k *KeyShareSH) fillFrom(raw rawExtension) error {
	share, rest, err := k.KeyShare.FromBytes(raw.data)
	if err != nil {
		return errors.Wrap(err, "reading key share")
	}

	if len(rest) != 0 {
		return errors.New("invalid lnegth")
	}

	k.KeyShare = share.(KeyShareEntry)
	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.9
type PskKeyExchangeMode uint8

var _ util.VectorConv = PskKeyExchangeMode(0)

func (p PskKeyExchangeMode) Bytes() []byte {
	return []byte{byte(p)}
}

func (p PskKeyExchangeMode) FromBytes(b []byte) (out util.VectorConv, rest []byte, err error) {
	if len(b) < 1 {
		return nil, nil, util.ErrVectorShort
	}

	out = PskKeyExchangeMode(b[0])
	return out, b[1:], nil
}

const (
	ExchangeMode_PSKKE    PskKeyExchangeMode = 0
	ExchangeMode_PSKDHEKE PskKeyExchangeMode = 1
)

type PskKeyExchangeModes struct {
	KeModes []PskKeyExchangeMode
}

var _ Extension = (*PskKeyExchangeModes)(nil)

func (k *PskKeyExchangeModes) ExtensionType() ExtensionType {
	return TypePskKeyExchangeModes
}

func (k *PskKeyExchangeModes) Data() []byte {
	return util.ToVector(1, k.KeModes)
}

func (k *PskKeyExchangeModes) Length() uint16 {
	return 1 + uint16(len(k.KeModes))
}

func (k *PskKeyExchangeModes) fillFrom(raw rawExtension) error {
	modes, _, err := util.FromVector[PskKeyExchangeMode](1, raw.data, false)
	if err != nil {
		return errors.Wrap(err, "reading modes")
	}

	k.KeModes = modes
	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
type PreSharedKeySH struct {
	SelectedIdentity uint16
}

var _ Extension = (*PreSharedKeySH)(nil)

func (p *PreSharedKeySH) ExtensionType() ExtensionType { return TypePreSharedKey }
func (p *PreSharedKeySH) Data() []byte                 { return util.ToBigEndianBytes(uint(p.SelectedIdentity), 2) }
func (p *PreSharedKeySH) Length() uint16               { return 2 }
func (p *PreSharedKeySH) fillFrom(raw rawExtension) error {
	if len(raw.data) != 2 {
		return errors.New("invalid length")
	}

	p.SelectedIdentity = binary.BigEndian.Uint16(raw.data)
	return nil
}

type PreSharedKeyCH struct {
	Identities []PSKIdentity
	Binders    []PSKBinderEntry
}

type PSKIdentity struct {
	Identity            []byte
	ObfuscatedTicketAge uint32
}

var _ util.VectorConv = PSKIdentity{}

func (p PSKIdentity) Bytes() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(util.ToVectorOpaque(2, p.Identity))
	buf.Write(util.ToBigEndianBytes(uint(p.ObfuscatedTicketAge), 4))

	return buf.Bytes()
}

func (p PSKIdentity) FromBytes(b []byte) (out util.VectorConv, rest []byte, err error) {
	opaqueIDentity, rest, err := util.FromVectorOpaque(2, b, true)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading identity")
	}

	if len(rest) < 4 {
		return nil, nil, errors.Wrap(util.ErrVectorShort, "reading ticket age")
	}

	p.Identity = opaqueIDentity
	p.ObfuscatedTicketAge = binary.BigEndian.Uint32(rest[:4])

	return p, rest[4:], nil
}

type PSKBinderEntry []byte

var _ util.VectorConv = PSKBinderEntry{}

func (p PSKBinderEntry) Bytes() []byte { return util.ToVectorOpaque(1, p) }

func (PSKBinderEntry) FromBytes(b []byte) (out util.VectorConv, rest []byte, err error) {
	opaque, rest, err := util.FromVectorOpaque(1, b, true)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading binder entry")
	}

	return PSKBinderEntry(opaque), rest, nil
}

var _ Extension = (*PreSharedKeyCH)(nil)

func (p *PreSharedKeyCH) ExtensionType() ExtensionType { return TypePreSharedKey }

func (p *PreSharedKeyCH) Data() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(util.ToVector(2, p.Identities))
	buf.Write(util.ToVector(2, p.Binders))

	return buf.Bytes()
}

func (p *PreSharedKeyCH) Length() uint16 {
	dLen := uint16(2)
	for _, identity := range p.Identities {
		dLen += uint16(len(identity.Bytes()))
	}
	dLen += uint16(2)
	for _, binder := range p.Binders {
		dLen += uint16(len(binder.Bytes()))
	}
	return dLen
}

func (p *PreSharedKeyCH) fillFrom(raw rawExtension) error {
	identities, rest, err := util.FromVector[PSKIdentity](2, raw.data, true)
	if err != nil {
		return errors.Wrap(err, "reading identities")
	}

	binders, _, err := util.FromVector[PSKBinderEntry](2, rest, false)
	if err != nil {
		return errors.Wrap(err, "reading binders")
	}

	p.Identities = identities
	p.Binders = binders
	return nil
}

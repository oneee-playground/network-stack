package extension

import (
	"bytes"
	"encoding/binary"
	"network-stack/session/tls/common"
	"network-stack/session/tls/common/keyexchange"

	"network-stack/session/tls/internal/util"

	"github.com/pkg/errors"
)

type SupportedGroups struct {
	NamedGroupList []keyexchange.GroupID
}

var _ Extension = (*SupportedGroups)(nil)

func (s *SupportedGroups) ExtensionType() ExtensionType { return TypeSupportedGroups }
func (s *SupportedGroups) exists() bool                 { return s != nil }

func (s *SupportedGroups) Data() []byte {
	return util.ToVector(2, s.NamedGroupList)
}

func (s *SupportedGroups) Length() uint16 {
	return 2 + uint16(len(s.NamedGroupList))*2 // length + num named group * named group size
}

func (*SupportedGroups) newFrom(raw Raw) (Extension, error) {
	var s SupportedGroups
	namedGroups, _, err := util.FromVector[keyexchange.GroupID](2, raw.data, false)
	if err != nil {
		return nil, errors.Wrap(err, "reading named group list")
	}

	s.NamedGroupList = namedGroups
	return &s, nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8
type KeyShareEntry struct {
	Group       keyexchange.GroupID
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
	return KeyShareEntry{group.(keyexchange.GroupID), keyExchange}, rest, nil
}

type KeyShareCH struct{ KeyShares []KeyShareEntry }

var _ Extension = (*KeyShareCH)(nil)

func (k *KeyShareCH) ExtensionType() ExtensionType { return TypeKeyShare }
func (k *KeyShareCH) exists() bool                 { return k != nil }

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

func (*KeyShareCH) newFrom(raw Raw) (Extension, error) {
	var k KeyShareCH
	entries, _, err := util.FromVector[KeyShareEntry](2, raw.data, false)
	if err != nil {
		return nil, errors.Wrap(err, "reading key shares")
	}

	k.KeyShares = entries
	return &k, nil
}

type KeyShareHRR struct{ SelectedGroup keyexchange.GroupID }

var _ Extension = (*KeyShareHRR)(nil)

func (k *KeyShareHRR) ExtensionType() ExtensionType { return TypeKeyShare }
func (k *KeyShareHRR) exists() bool                 { return k != nil }

func (k *KeyShareHRR) Data() []byte {
	return k.SelectedGroup.Bytes()
}

func (k *KeyShareHRR) Length() uint16 {
	return 2
}

func (*KeyShareHRR) newFrom(raw Raw) (Extension, error) {
	var k KeyShareHRR
	group, rest, err := k.SelectedGroup.FromBytes(raw.data)
	if err != nil {
		return nil, errors.Wrap(err, "reading group")
	}

	if len(rest) != 0 {
		return nil, errors.New("invalid lnegth")
	}

	k.SelectedGroup = group.(keyexchange.GroupID)
	return &k, nil
}

type KeyShareSH struct{ KeyShare KeyShareEntry }

var _ Extension = (*KeyShareSH)(nil)

func (k *KeyShareSH) ExtensionType() ExtensionType { return TypeKeyShare }
func (k *KeyShareSH) exists() bool                 { return k != nil }

func (k *KeyShareSH) Data() []byte {
	return k.KeyShare.Bytes()
}

func (k *KeyShareSH) Length() uint16 {
	return uint16(len(k.KeyShare.Bytes()))
}

func (*KeyShareSH) newFrom(raw Raw) (Extension, error) {
	var k KeyShareSH
	share, rest, err := k.KeyShare.FromBytes(raw.data)
	if err != nil {
		return nil, errors.Wrap(err, "reading key share")
	}

	if len(rest) != 0 {
		return nil, errors.New("invalid lnegth")
	}

	k.KeyShare = share.(KeyShareEntry)
	return &k, nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.9
type PSKMode uint8

var _ util.VectorConv = PSKMode(0)

func (p PSKMode) Bytes() []byte {
	return []byte{byte(p)}
}

func (p PSKMode) FromBytes(b []byte) (out util.VectorConv, rest []byte, err error) {
	if len(b) < 1 {
		return nil, nil, common.ErrNeedMoreBytes
	}

	out = PSKMode(b[0])
	return out, b[1:], nil
}

const (
	PSKModePSK_KE     PSKMode = 0
	PSKModePSK_DHE_KE PSKMode = 1
)

type PskKeyExchangeModes struct {
	KeModes []PSKMode
}

var _ Extension = (*PskKeyExchangeModes)(nil)

func (k *PskKeyExchangeModes) ExtensionType() ExtensionType { return TypePskKeyExchangeModes }
func (k *PskKeyExchangeModes) exists() bool                 { return k != nil }

func (k *PskKeyExchangeModes) Data() []byte {
	return util.ToVector(1, k.KeModes)
}

func (k *PskKeyExchangeModes) Length() uint16 {
	return 1 + uint16(len(k.KeModes))
}

func (*PskKeyExchangeModes) newFrom(raw Raw) (Extension, error) {
	var k PskKeyExchangeModes
	modes, _, err := util.FromVector[PSKMode](1, raw.data, false)
	if err != nil {
		return nil, errors.Wrap(err, "reading modes")
	}

	k.KeModes = modes
	return &k, nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
type PreSharedKeySH struct {
	SelectedIdentity uint16
}

var _ Extension = (*PreSharedKeySH)(nil)

func (p *PreSharedKeySH) ExtensionType() ExtensionType { return TypePreSharedKey }
func (p *PreSharedKeySH) exists() bool                 { return p != nil }
func (p *PreSharedKeySH) Data() []byte                 { return util.ToBigEndianBytes(uint(p.SelectedIdentity), 2) }
func (p *PreSharedKeySH) Length() uint16               { return 2 }
func (*PreSharedKeySH) newFrom(raw Raw) (Extension, error) {
	var p PreSharedKeySH
	if len(raw.data) != 2 {
		return nil, errors.New("invalid length")
	}

	p.SelectedIdentity = binary.BigEndian.Uint16(raw.data)
	return &p, nil
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
		return nil, nil, common.ErrNeedMoreBytes
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
func (p *PreSharedKeyCH) exists() bool                 { return p != nil }

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

func (*PreSharedKeyCH) newFrom(raw Raw) (Extension, error) {
	var p PreSharedKeyCH
	identities, rest, err := util.FromVector[PSKIdentity](2, raw.data, true)
	if err != nil {
		return nil, errors.Wrap(err, "reading identities")
	}

	binders, _, err := util.FromVector[PSKBinderEntry](2, rest, false)
	if err != nil {
		return nil, errors.Wrap(err, "reading binders")
	}

	p.Identities = identities
	p.Binders = binders
	return &p, nil
}

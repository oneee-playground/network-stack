package keyexchange

import (
	"crypto/ecdh"
	"encoding/binary"
	"network-stack/session/tls/common"
	"network-stack/session/tls/internal/util"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
type GroupID uint16

func (id GroupID) Bytes() []byte {
	b := make([]byte, 2)
	b[0] = uint8(id >> 8)
	b[1] = uint8(id)
	return b
}

func (GroupID) FromBytes(b []byte) (out util.VectorConv, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, common.ErrNeedMoreBytes
	}

	out = GroupID(binary.BigEndian.Uint16(b))

	return out, b[2:], nil
}

var _ util.VectorConv = GroupID(0)

type Group struct {
	id       GroupID
	exchange KeyExchange
}

func NewGroup(id GroupID, exchange KeyExchange) Group {
	return Group{id: id, exchange: exchange}
}

func (g Group) ID() GroupID              { return g.id }
func (g Group) KeyExchange() KeyExchange { return g.exchange }

var groups = make(map[GroupID]Group)

func register(g Group) GroupID { groups[g.ID()] = g; return g.ID() }

func Get(id GroupID) (Group, bool) {
	g, ok := groups[id]
	return g, ok
}

var (
	// Elliptic Curve Groups (ECDHE)
	Group_Secp256r1         = register(Group{0x0017, ecdheKeyExchange{ecdh.P256()}})
	Group_Secp384r1         = register(Group{0x0018, ecdheKeyExchange{ecdh.P384()}})
	Group_Secp521r1         = register(Group{0x0019, ecdheKeyExchange{ecdh.P521()}})
	Group_X25519            = register(Group{0x001D, ecdheKeyExchange{ecdh.X25519()}})
	Group_X448      GroupID = 0x001E // Unimplemented in stdlib.

	// Finite Field Groups (DHE)
	// Unimplemented in stdlib.
	Group_FFDHE2048 GroupID = 0x0100
	Group_FFDHE3072 GroupID = 0x0101
	Group_FFDHE4096 GroupID = 0x0102
	Group_FFDHE6144 GroupID = 0x0103
	Group_FFDHE8192 GroupID = 0x0104

	// Reserved Code Points
	// FFDHE private use 0x01FC ~ 0x01FF
	// ECDHE private use 0xFE00 ~ 0xFEFF
)

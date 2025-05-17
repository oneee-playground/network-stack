package ciphersuite

import (
	"crypto"
	sliceutil "network-stack/lib/slice"
	"network-stack/session/tls/common"
	"network-stack/session/tls/internal/util"
)

type ID [2]uint8

func (ID) FromBytes(b []byte) (out util.VectorConv, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, common.ErrNeedMoreBytes
	}

	out = ID([2]uint8(b))

	return out, b[2:], nil
}

func (id ID) Bytes() []byte {
	return id[:]
}

type Suite struct {
	id   ID
	aead AEAD
	hash crypto.Hash
}

func (s Suite) ID() ID            { return s.id }
func (s Suite) AEAD() AEAD        { return s.aead }
func (s Suite) Hash() crypto.Hash { return s.hash }

func NewSuite(id ID, aead AEAD, hash crypto.Hash) Suite {
	return Suite{
		id:   id,
		aead: aead,
		hash: hash,
	}
}

var suites = make(map[ID]Suite)

func register(s Suite) ID { suites[s.ID()] = s; return s.ID() }

func Get(id ID) (Suite, bool) {
	s, ok := suites[id]
	return s, ok
}

func AsIDs(suites []Suite) []ID {
	return sliceutil.Map(suites, func(suite Suite) ID {
		return suite.ID()
	})
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4
var (
	TLS_AES_128_GCM_SHA256 = register(Suite{ID([2]uint8{0x13, 0x01}), AEAD{16, aeadAES_128_GCM}, crypto.SHA256})
	TLS_AES_256_GCM_SHA384 = register(Suite{ID([2]uint8{0x13, 0x02}), AEAD{32, aeadAES_256_GCM}, crypto.SHA384})

	TLS_CHACHA20_POLY1305_SHA256 = [2]uint8{0x13, 0x03} // NOTE: Unimplemented in stdlib.

	TLS_AES_128_CCM_SHA256   = [2]uint8{0x13, 0x04} // NOTE: Unimplemented in stdlib.
	TLS_AES_128_CCM_8_SHA256 = [2]uint8{0x13, 0x05} // NOTE: Unimplemented in stdlib.
)

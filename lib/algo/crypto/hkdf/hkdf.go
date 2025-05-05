// Package hkdf implements HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
//
// Reference: https://datatracker.ietf.org/doc/html/rfc5869
package hkdf

import (
	"crypto"
	"crypto/hmac"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc5869#section-2.2
func Extract(hash crypto.Hash, salt, ikm []byte) (prk []byte) {
	if len(salt) == 0 {
		salt = make([]byte, hash.Size())
	}

	h := hmac.New(hash.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

// Reference: https://datatracker.ietf.org/doc/html/rfc5869#section-2.3
func Expand(hash crypto.Hash, prk, info []byte, l uint) (okm []byte) {
	hashLen := uint(hash.Size())
	n := uint8((l + hashLen - 1) / hashLen) // ceil(l / hashLen)

	okm = make([]byte, 0, l)
	var t []byte

	for i := uint8(1); i <= n; i++ {
		h := hmac.New(hash.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})

		t = h.Sum(nil)
		okm = append(okm, t...)
	}

	return okm[:l]
}

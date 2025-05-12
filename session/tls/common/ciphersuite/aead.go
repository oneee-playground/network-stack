package ciphersuite

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

var ErrKeyLen = errors.New("invalid key length")

type AEAD struct {
	keyLen int
	f      aeadFunc
}

func (a AEAD) New(key []byte) (cipher.AEAD, error) {
	if len(key) != a.keyLen {
		return nil, ErrKeyLen
	}

	return a.f(key)
}

func (a AEAD) KeyLen() int {
	return a.keyLen
}

type aeadFunc func(key []byte) (cipher.AEAD, error)

func aeadAES_128_GCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func aeadAES_256_GCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

package ciphersuite

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

var ErrKeyLen = errors.New("invalid key length")

type AEADFunc func(key []byte) (cipher.AEAD, error)

func aeadAES_128_GCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 16 {
		return nil, ErrKeyLen
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func aeadAES_256_GCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrKeyLen
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

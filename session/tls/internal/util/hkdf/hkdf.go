// Package hkdf is tls-specific "crypto/hkdf" wrapper.
package hkdf

import (
	"crypto/hkdf"
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/internal/util"

	"github.com/pkg/errors"
)

func Extract(suite ciphersuite.Suite, secret []byte, salt []byte) ([]byte, error) {
	if len(secret) == 0 || len(salt) == 0 {
		zeros := make([]byte, suite.Hash().Size())
		if len(secret) == 0 {
			secret = zeros
		}
		if len(salt) == 0 {
			salt = zeros
		}
	}

	prk, err := hkdf.Extract(suite.Hash().New, secret, salt)
	if err != nil {
		return nil, errors.Wrap(err, "extracting via hkdf")
	}

	return prk, nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
type hkdfLabel struct {
	length  uint16
	label   []byte
	context []byte
}

func (l hkdfLabel) marshal() string {
	b := util.ToBigEndianBytes(uint(l.length), 2)
	b = append(b, util.ToVectorOpaque(1, l.label)...)
	b = append(b, util.ToVectorOpaque(1, l.context)...)
	return string(b)
}

func ExpandLabel(
	suite ciphersuite.Suite,
	secret []byte,
	label, context string,
	length int,
) ([]byte, error) {
	hkdfLabel := hkdfLabel{
		length:  uint16(suite.Hash().Size()),
		label:   []byte("tls13 " + label),
		context: []byte(context),
	}

	b, err := hkdf.Expand(suite.Hash().New, secret, hkdfLabel.marshal(), length)
	return b, err
}

func DeriveSecret(
	suite ciphersuite.Suite,
	secret []byte,
	label string,
	transcriptHash []byte,
) ([]byte, error) {
	return ExpandLabel(
		suite, secret, label, string(transcriptHash), suite.Hash().Size(),
	)
}

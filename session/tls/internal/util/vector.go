package util

import (
	"bytes"
	"math/big"

	"github.com/pkg/errors"
)

var ErrVectorShort = errors.New("vector is short")

type VectorConv interface {
	// FromBytes returns the object itself that is filled from bytes.
	FromBytes(b []byte) (out VectorConv, rest []byte, err error)
	// ToBytes returns raw bytes containing its data.
	Bytes() []byte
}

func FromVector[T VectorConv](lenSize uint, b []byte, allowRemain bool) (_ []T, rest []byte, err error) {
	length, rest, err := getLength(lenSize, b)
	if err != nil {
		return nil, nil, err
	}

	b = rest
	rest = rest[:length]

	dst := make([]T, 0)
	for len(rest) > 0 {
		var tmp T
		out, tmpRest, err := tmp.FromBytes(rest)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "reading #%d element", len(dst))
		}

		dst = append(dst, out.(T))
		rest = tmpRest
	}

	if !allowRemain && len(b[length:]) != 0 {
		return nil, nil, errors.New("unexpected remaining bytes")
	}

	return dst, b[length:], nil
}

func FromVectorOpaque(lenSize uint, b []byte, allowRemain bool) (opaque []byte, rest []byte, err error) {
	length, rest, err := getLength(lenSize, b)
	if err != nil {
		return nil, nil, err
	}

	b = rest

	if !allowRemain && len(b[length:]) != 0 {
		return nil, nil, errors.New("unexpected remaining bytes")
	}

	return b[:length], b[length:], nil
}

func getLength(size uint, b []byte) (length uint, rest []byte, err error) {
	if uint(len(b)) < size {
		return 0, nil, errors.Wrap(ErrVectorShort, "getting length")
	}

	// big.Int is convinient when we can't convert it into specific uint.
	length = uint(big.NewInt(0).SetBytes(b[:size]).Uint64())
	rest = b[size:]

	if uint(len(rest)) < length {
		return 0, nil, errors.Wrap(ErrVectorShort, "getting data")
	}

	return length, rest, nil
}

func ToVector[T VectorConv](lenSize uint, data []T) []byte {
	buf := bytes.NewBuffer(nil)

	l := uint(0)
	raws := make([][]byte, len(data))
	for idx, d := range data {
		b := d.Bytes()

		l += uint(len(b))
		raws[idx] = b
	}

	buf.Write(ToBigEndianBytes(l, uint8(lenSize)))
	for _, raw := range raws {
		buf.Write(raw)
	}

	return buf.Bytes()
}

func ToVectorOpaque(lenSize uint, data []byte) []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(ToBigEndianBytes(uint(len(data)), uint8(lenSize)))
	buf.Write(data)

	return buf.Bytes()
}

package common

func ToBigEndianBytes(n uint, byteLen uint8) []byte {
	if byteLen > 8 {
		panic("cannot make more than 8 bytes")
	}

	b := make([]byte, byteLen)
	for i := range b {
		shift := uint(8 * (len(b) - 1 - i))
		b[i] = uint8(n >> shift)
	}

	return b
}

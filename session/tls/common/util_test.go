package common

import (
    "testing"

    "github.com/stretchr/testify/assert"
)

func TestToBigEndianBytes(t *testing.T) {
    testcases := []struct {
        desc     string
        n        uint
        byteLen  uint8
        expected []byte
        wantPanic bool
    }{
        {
            desc:     "convert 0x123456 to 3 bytes",
            n:        0x123456,
            byteLen:  3,
            expected: []byte{0x12, 0x34, 0x56},
        },
        {
            desc:     "convert 0x123456 to 4 bytes (padded)",
            n:        0x123456,
            byteLen:  4,
            expected: []byte{0x00, 0x12, 0x34, 0x56},
        },
        {
            desc:     "convert 0x123456 to 2 bytes (truncated)",
            n:        0x123456,
            byteLen:  2,
            expected: []byte{0x34, 0x56},
        },
        {
            desc:     "convert 0 to 1 byte",
            n:        0,
            byteLen:  1,
            expected: []byte{0x00},
        },
        {
            desc:     "convert 0xFF to 1 byte",
            n:        0xFF,
            byteLen:  1,
            expected: []byte{0xFF},
        },
        {
            desc:     "Panic when byteLen > 8",
            n:        0x123456,
            byteLen:  9,
            wantPanic: true,
        },
    }

    for _, tc := range testcases {
        t.Run(tc.desc, func(t *testing.T) {
            if tc.wantPanic {
                assert.Panics(t, func() {
                    ToBigEndianBytes(tc.n, tc.byteLen)
                })
                return
            }

            result := ToBigEndianBytes(tc.n, tc.byteLen)
            assert.Equal(t, tc.expected, result)
        })
    }
}


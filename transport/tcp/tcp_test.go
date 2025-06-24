package tcp

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSegmentComputeOffset(t *testing.T) {
	s := segment{}
	offset := s.computeOffset()

	minOffset := minSegmentLength / offsetMultiplier
	require.Equal(t, minOffset, int(offset))

	o := option{}
	s.options = append(s.options, o)

	offset = s.computeOffset()

	assert.Equal(t, minOffset+1, int(offset))
}

func TestSegmentComputeChecksum(t *testing.T) {
	s := segment{data: []byte("hello")}
	s.checksum = ^s.computeChecksum(nil)

	checksum := s.computeChecksum(nil)
	assert.Equal(t, uint16(0xFFFF), checksum, fmt.Sprintf("%b %b", s.checksum, checksum))
}

func TestSegmentCodec(t *testing.T) {
	original := segment{
		srcPort:   1,
		dstPort:   2,
		seqNum:    3,
		ackNum:    4,
		offset:    5,
		control:   ctl{},
		window:    6,
		checksum:  7,
		urgentPtr: 8,
		data:      []byte{9},
	}
	original.offset = original.computeOffset()

	b := original.bytes()

	got, err := parseSegment(b)
	require.NoError(t, err, fmt.Sprintf("%v : %#+v", b, original))

	assert.Equal(t, original, got)
}

func TestCTLCodec(t *testing.T) {
	ctl := ctl{
		urg: true,
		rst: true,
	}

	b := ctl.byte()
	restored := ctlFromByte(b)

	assert.Equal(t, ctl, restored, fmt.Sprintf("%b", b))
}

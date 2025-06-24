// Package tcp implements Transmission Control Protocol (TCP)
//
// Reference: https://datatracker.ietf.org/doc/html/rfc9293
package tcp

import (
	"encoding/binary"
	"errors"
	"network-stack/network"
	"network-stack/network/ip"
	"network-stack/transport"
	"strconv"
)

type Addr struct {
	ipAddr ip.Addr
	port   uint16
}

var _ transport.Addr = Addr{}

func NewAddr(ipAddr ip.Addr, port uint16) Addr {
	return Addr{ipAddr, port}
}

func (a Addr) Port() uint16              { return a.port }
func (a Addr) NetworkAddr() network.Addr { return a.ipAddr }

func (a Addr) String() string {
	net := a.ipAddr.String()
	if a.ipAddr.Version() == 6 {
		net = "[" + net + "]"
	}

	return net + ":" + strconv.FormatUint(uint64(a.port), 10)
}

// Reference: https://datatracker.ietf.org/doc/html/rfc9293#section-3.1-3
type segment struct {
	srcPort, dstPort uint16

	seqNum, ackNum uint32

	offset  uint8 // 4bits. other 4 bits are reserved.
	control ctl
	window  uint16

	checksum  uint16
	urgentPtr uint16

	options []option

	data []byte
}

const minSegmentLength = 20
const offsetMultiplier = 4

func (s segment) computeOffset() uint8 {
	offset := minSegmentLength
	for _, option := range s.options {
		offset += len(option.bytes())
	}

	return uint8((offset + offsetMultiplier - 1) / offsetMultiplier)
}

// computeChecksum computes checksum.
// On sender's side, it must ensure that checksum is 0.
// On receiver's side, if return value isn't 0xFFFF, the segment isn't valid.
// Reference: https://datatracker.ietf.org/doc/html/rfc9293#section-3.1-6.18.1
func (s segment) computeChecksum(ipPseudoHeader []byte) uint16 {
	input := append(ipPseudoHeader, s.bytes()...)
	if len(input)%2 == 1 {
		// Add padding.
		input = append(input, byte(0))
	}

	sum := uint16(0)
	for idx := 0; idx < len(input); idx += 2 {
		v := uint16(input[idx])<<8 + uint16(input[idx+1])
		v += sum

		if sum > v {
			// Previous sum is greater than current sum.
			// This means the addition resulted in overflow.
			// In one's complement addition, we add carry for this case.
			v++
		}

		sum = v
	}

	return sum
}

// bytes assumes offset and checksum are properly set.
func (s segment) bytes() []byte {
	b := []byte{}
	b = binary.BigEndian.AppendUint16(b, s.srcPort)
	b = binary.BigEndian.AppendUint16(b, s.dstPort)

	b = binary.BigEndian.AppendUint32(b, s.seqNum)
	b = binary.BigEndian.AppendUint32(b, s.ackNum)

	b = append(b, s.offset)
	b = append(b, s.control.byte())
	b = binary.BigEndian.AppendUint16(b, s.window)

	b = binary.BigEndian.AppendUint16(b, s.checksum)
	b = binary.BigEndian.AppendUint16(b, s.urgentPtr)

	if len(s.options) > 0 {
		for _, option := range s.options {
			b = append(b, option.bytes()...)
		}

		if remainder := len(b) % offsetMultiplier; remainder > 0 {
			// Pad the options with zeros.
			// First byte should be treated as EOL option.
			b = append(b, make([]byte, remainder)...)
		}
	}

	b = append(b, s.data...)

	return b
}

func parseSegment(raw []byte) (segment, error) {
	if len(raw) < minSegmentLength {
		return segment{}, errors.New("segment too short")
	}

	s := segment{
		srcPort: binary.BigEndian.Uint16(raw[0:2]),
		dstPort: binary.BigEndian.Uint16(raw[2:4]),

		seqNum: binary.BigEndian.Uint32(raw[4:8]),
		ackNum: binary.BigEndian.Uint32(raw[8:12]),

		offset:  raw[12],
		control: ctlFromByte(raw[13]),
		window:  binary.BigEndian.Uint16(raw[14:16]),

		checksum:  binary.BigEndian.Uint16(raw[16:18]),
		urgentPtr: binary.BigEndian.Uint16(raw[18:20]),
	}

	dataAt := int(s.offset) * offsetMultiplier

	if dataAt > len(raw) {
		return segment{}, errors.New("advertised data offset too long")
	}

	if s.offset > (minSegmentLength / offsetMultiplier) {
		// Option presents only when data offset > 5.
		optIdx := minSegmentLength

		for optIdx < dataAt {
			// TODO: make option more flexible.
			kind := optionKind(raw[optIdx])
			if kind == optionKindEOL {
				// The rest bytes are just paddings.
				break
			}

			opt := option{kind: kind}
			switch kind {
			case optionKindNoOp:
				optIdx++
			case optionKindMSS:
				opt.length = raw[optIdx+1]
				opt.data = append([]byte{}, raw[optIdx+2:optIdx+2+int(opt.length)]...)
				optIdx += 6 // 1(kind) + 1(length) + 4(data)
			}

			s.options = append(s.options, opt)
		}
	}

	s.data = raw[dataAt:]

	return s, nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc9293#section-3.1-6.14.1
type ctl struct {
	cwr, ece, urg, ack, psh, rst, syn, fin bool
}

func (c ctl) byte() byte {
	b := byte(0)

	flags := []bool{c.cwr, c.ece, c.urg, c.ack, c.psh, c.rst, c.syn, c.fin}
	for idx, flag := range flags {
		if flag {
			b |= byte(1 << (7 - idx))
		}
	}

	return b
}

func ctlFromByte(b byte) ctl {
	c := ctl{}
	flags := []*bool{&c.cwr, &c.ece, &c.urg, &c.ack, &c.psh, &c.rst, &c.syn, &c.fin}

	for idx, flag := range flags {
		if (b & byte(1<<(7-idx))) != 0 {
			*flag = true
		}
	}

	return c
}

type option struct {
	kind   optionKind
	length uint8
	data   []byte
}

func (o option) bytes() []byte {
	// TODO: flexibility
	if o.kind == optionKindMSS {
		return append([]byte{byte(o.kind), o.length}, o.data...)
	}
	return []byte{byte(o.kind)}
}

type optionKind uint8

// Reference: https://datatracker.ietf.org/doc/html/rfc9293#section-3.1-6.22.9
const (
	optionKindEOL  = 0
	optionKindNoOp = 1
	optionKindMSS  = 2
)

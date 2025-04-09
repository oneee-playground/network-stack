package ipv4

import (
	"network-stack/network/ip"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type Addr [4]byte

var _ ip.Addr = Addr{}

func (a Addr) Raw() []byte   { return a[:] }
func (a Addr) Version() uint { return 4 }

func (a Addr) ToUint32() (n uint32) {
	n |= uint32(a[0]) << 24
	n |= uint32(a[1]) << 16
	n |= uint32(a[2]) << 8
	n |= uint32(a[3])
	return
}

func (a Addr) String() string {
	var nums = make([]string, 4)
	for idx, digit := range a {
		nums[idx] = strconv.FormatUint(uint64(digit), 10)
	}

	return strings.Join(nums, ".")
}

func ParseAddr(s string) (Addr, error) {
	digits := strings.Split(s, ".")
	if len(digits) != 4 {
		return Addr{}, errors.New("digits are not properly seperated")
	}

	var addr Addr
	for idx, digit := range digits {
		n, err := strconv.ParseUint(digit, 10, 8)
		if err != nil {
			return Addr{}, errors.Wrap(err, "failed to parse a part into digit")
		}

		if digit[0] == '0' && !(n == 0 && len(digit) == 1) {
			// '00', '01'
			return Addr{}, errors.New("leading zero is not allowed in digit")
		}
		addr[idx] = byte(n)
	}

	return addr, nil
}

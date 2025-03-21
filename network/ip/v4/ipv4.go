package ipv4

import (
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type Addr [4]byte

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

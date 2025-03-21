package ipv6

import (
	ipv4 "network-stack/network/ip/v4"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type Addr [16]byte

func ParseAddr(s string) (Addr, error) {
	before, after, found := strings.Cut(s, "::")
	var addr Addr

	if !found {
		// Two colons not found. parse the whole string.
		addrBytes, err := parseAddrFrag(before, true)
		if err != nil {
			return Addr{}, err
		}
		if len(addrBytes) != 16 {
			return Addr{}, errors.New("length of address is not 128bit")
		}

		copy(addr[:], addrBytes)

		return addr, nil
	}

	// Two colons found. parse each of them and combine them.
	frag1, err1 := parseAddrFrag(before, false)
	frag2, err2 := parseAddrFrag(after, true)
	if err1 != nil || err2 != nil {
		if err1 != nil {
			return Addr{}, errors.Wrap(err1, "parsing fragment before ::")
		} else {
			return Addr{}, errors.Wrap(err2, "parsing fragment after ::")
		}
	}

	if len(frag1)+len(frag2) >= 14 {
		// At least 2 bytes should be ommited.
		return Addr{}, errors.New("ipv6 address too long")
	}

	// copy first len(frag1) bytes.
	copy(addr[:len(frag1)], frag1)
	// copy last len(frag2) bytes.
	copy(addr[len(addr)-len(frag2):], frag2)

	return addr, nil
}

func parseAddrFrag(s string, isLast bool) ([]byte, error) {
	if s == "" {
		return []byte{}, nil
	}

	h16s := strings.Split(s, ":")

	addr := make([]byte, len(h16s)*2)
	for idx, h16 := range h16s {
		if h16 == "" {
			// 0:::, 0::0::
			return nil, errors.New("invalid use of colon seperator")
		}

		n, err := strconv.ParseUint(h16, 16, 16)
		if err != nil {
			if !isLast || idx != len(h16s)-1 {
				// If it is not the last element of the whole address
				return nil, errors.Wrap(err, "failed to parse hex")
			}
			// It might be IPv4 address
			addrV4, err := ipv4.ParseAddr(h16)
			if err != nil {
				return nil, errors.Wrap(err,
					"non-hex item found on the last index, but wasn't ipv4 address",
				)
			}
			n = uint64(addrV4.ToUint32())
		}

		nIdx := idx * 2
		addr[nIdx] = byte(n >> 8)
		addr[nIdx+1] = byte(n & 0xFF)
	}

	return addr, nil
}

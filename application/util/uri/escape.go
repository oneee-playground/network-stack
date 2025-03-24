package uri

import (
	"strings"

	"github.com/pkg/errors"
)

type encodeMode uint

const (
	encodePath encodeMode = 1 + iota
	encodeHost
	encodeUserInfo
	encodeQuery
	encodeFragment
)

func hex(c byte) (h [2]byte) {
	const hexSet = "0123456789ABCDEF"
	h[0] = hexSet[c>>4]
	h[1] = hexSet[c&0xF]
	return
}

func unhex(h [2]byte) (c byte) {
	return (_hex_to_num(h[0]) << 4) | _hex_to_num(h[1])
}

func _hex_to_num(h byte) byte {
	switch {
	case '0' <= h && h <= '9':
		return h - '0'
	case 'a' <= h && h <= 'f':
		return h - 'a' + 10
	case 'A' <= h && h <= 'F':
		return h - 'A' + 10
	}
	return 0
}

func escape(s string, mode encodeMode) string {
	b := new(strings.Builder)
	b.Grow(len(s))

	for idx := 0; idx < len(s); idx++ {
		c := s[idx]
		if shouldEscape(c, mode) {
			hex := hex(c)
			b.Write([]byte{'%', hex[0], hex[1]})
		} else {
			b.WriteByte(c)
		}
	}

	return b.String()
}

func unescape(s string) (string, error) {
	b := new(strings.Builder)
	b.Grow(len(s))

	for idx := 0; idx < len(s); idx++ {
		c := s[idx]
		if c == '%' {
			if idx+2 >= len(s) || !isPercentEncoded(s[idx:idx+3]) {
				bad := s[idx:min(len(s), idx+3)]
				return "", errors.Errorf("percent encoding not properly applied: %q", bad)
			}
			b.WriteByte(unhex([2]byte{s[idx+1], s[idx+2]}))
			idx += 2
			continue
		}
		b.WriteByte(c)
	}

	return b.String(), nil
}

func shouldEscape(c byte, mode encodeMode) bool {
	if isUnreserved(c) {
		return false
	}

	if isReserved(c) {
		switch mode {
		case encodeUserInfo:
			// Reference: https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.1
			return !(isSubDelim(c) || c == ':')
		case encodeHost:
			// Reference: https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.2
			return !(isSubDelim(c) || c == '[' || c == ']' || c == ':') // For IP Literal and reg-name.
		case encodePath:
			// Reference: https://datatracker.ietf.org/doc/html/rfc3986#section-3.3
			return !(isSubDelim(c) || c == ':' || c == '@' || c == '/')
		case encodeFragment, encodeQuery:
			// Reference:
			// https://datatracker.ietf.org/doc/html/rfc3986#section-3.4
			// https://datatracker.ietf.org/doc/html/rfc3986#section-3.5
			return !(isSubDelim(c) || c == ':' || c == '@' || c == '/' || c == '?')
		}
	}

	return true
}

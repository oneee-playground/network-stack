package uri

import (
	"network-stack/application/util/rule"
	ipv4 "network-stack/network/ip/v4"
	ipv6 "network-stack/network/ip/v6"
	"strings"

	"github.com/pkg/errors"
)

func containsCTL(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < ' ' || b == 0x7f {
			return true
		}
	}
	return false
}

// Reference: https://datatracker.ietf.org/doc/html/rfc3986#section-2.2
func isSubDelim(c byte) bool {
	switch c {
	case '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=':
		return true
	}
	return false
}

// Reference: https://datatracker.ietf.org/doc/html/rfc3986#section-2.3
func isUnreserved(c byte) bool {
	if rule.IsAlpha(rune(c)) || rule.IsDigit(rune(c)) {
		return true
	}
	switch c {
	case '-', '.', '_', '~':
		return true
	}
	return false
}

func isReserved(c byte) bool {
	switch c {
	case ':', '/', '?', '#', '[', ']', '@':
		// gen-delims
		return true
	}
	return isSubDelim(c)
}

// Reference: https://datatracker.ietf.org/doc/html/rfc3986#section-2.1
func isPercentEncoded(s string) bool {
	if len(s) != 3 {
		return false
	}

	return s[0] == '%' &&
		rule.IsHex(rune(s[1])) &&
		rule.IsHex(rune(s[2]))
}

// Reference: https://datatracker.ietf.org/doc/html/rfc3986#section-3.3
func isAllPchar(s string) bool {
	for idx := 0; idx < len(s); idx++ {
		c := s[idx]
		if isUnreserved(c) || isSubDelim(c) || c == ':' || c == '@' {
			continue
		}
		if idx+2 < len(s) && isPercentEncoded(s[idx:idx+3]) {
			idx += 2
			continue
		}
		return false
	}

	return true
}

func assertValidScheme(scheme string) error {
	if len(scheme) == 0 {
		return errors.New("scheme is empty")
	}

	if !rule.IsAlpha(rune(scheme[0])) {
		return errors.New("scheme doesn't start with ALPHA")
	}

	for idx := 1; idx < len(scheme); idx++ {
		c := scheme[idx]
		switch {
		case rule.IsAlpha(rune(c)) || rule.IsDigit(rune(c)):
		case c == '+' || c == '-' || c == '.':
		default:
			return errors.New("scheme contains invalid byte")
		}
	}

	return nil
}

func assertValidHost(host string) error {
	if host == "" {
		// Empty value for reg-name is valid.
		// Reference: https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.2
		return nil
	}
	if len(host) > 255 {
		// Length is limited to 255.
		return errors.Errorf("host length exceeds limit(255): %d", len(host))
	}

	first, last := 0, len(host)-1
	if host[first] == '[' && host[last] == ']' {
		// This is IP Literal.
		host = host[first+1 : last]
		if _, err := ipv6.ParseAddr(host); err == nil {
			return nil
		}
		if ok := isIPvFuture(host); ok {
			return nil
		}

		return errors.New("host is expected to be IP Literal, but was malformed")
	}

	if _, err := ipv4.ParseAddr(host); err == nil {
		return nil
	}
	if ok := isValidRegName(host); ok {
		return nil
	}

	return errors.New("host is neither ipv4 addr nor valid reg-name")
}

func isValidUserInfo(s string) bool {
	for idx := 0; idx < len(s); idx++ {
		c := s[idx]
		if isUnreserved(c) || isSubDelim(c) || c == ':' {
			continue
		}
		if idx+2 < len(s) && isPercentEncoded(s[idx:idx+3]) {
			idx += 2
			continue
		}

		return false
	}

	return true
}

func isValidRegName(s string) bool {
	for idx := 0; idx < len(s); idx++ {
		c := s[idx]
		if isUnreserved(c) || isSubDelim(c) {
			continue
		}
		if idx+2 < len(s) && isPercentEncoded(s[idx:idx+3]) {
			idx += 2
			continue
		}

		return false
	}

	return true
}

func isIPvFuture(s string) bool {
	if len(s) < 4 {
		return false
	}

	// v8. vA. vF.
	if !(s[0] == 'v' && rule.IsHex(rune(s[1])) && s[2] == '.') {
		return false
	}

	for idx := 3; idx < len(s); idx++ {
		c := s[idx]
		if !(isUnreserved(c) || isSubDelim(c) || c == ':') {
			return false
		}
	}

	return true
}

func assertValidPath(path string, hasAuthority bool, hasScheme bool) error {
	if hasAuthority {
		if !(path == "" || path[0] == '/') {
			return errors.New(
				"URI with authority must either be empty or start with '/'",
			)
		}
	} else if strings.HasPrefix(path, "//") {
		return errors.New("URI without authority should not start with '//'")
	}

	segments := strings.Split(path, "/")
	if !hasScheme {
		if segments[0] == "" {
			return errors.New(
				"URI without scheme should start with non-zero segment",
			)
		}
		if strings.ContainsRune(segments[0], ':') {
			return errors.New("URI without scheme should not contain ':'")
		}
	}

	for _, segment := range segments {
		if !isAllPchar(segment) {
			return errors.New("path segment should be pchar")
		}
	}

	return nil
}

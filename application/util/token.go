package util

// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-5.6.2-2
func IsValidToken(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		// ALPHA
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') {
			continue
		}
		// DIGIT
		if '0' <= c && c <= '9' {
			continue
		}

		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+',
			'-', '.', '^', '_', '`', '|', '~':
			continue
		}

		return false
	}

	return true
}

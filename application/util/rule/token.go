package rule

import (
	"bytes"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-5.6.2-2
func IsValidToken(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if IsAlpha(c) || IsDigit(c) {
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

// Unquote unquotes token if it was quoted with double quotes.
// If quoted string includes escaped character, it will be un-escaped.
func Unquote(token []byte) []byte {
	quoted := false
	if len(token) >= 2 {
		// Unquote the token if it's wrapped with quotes.
		first, last := 0, len(token)-1
		if token[first] == '"' && token[last] == '"' {
			token = token[first+1 : last]
			quoted = true
		}
	}

	if !quoted {
		return bytes.Clone(token)
	}

	buf := bytes.NewBuffer(make([]byte, 0, len(token)))
	for idx := 0; idx < len(token); idx++ {
		c := token[idx]
		if c == '\\' {
			// Escaped character inside quote.
			// Unescape it and write it away.
			continue
		}
		buf.WriteByte(c)
	}

	return buf.Bytes()
}

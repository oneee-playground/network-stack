package semantic

import (
	"bytes"
	"network-stack/application/http"
	"network-stack/application/util/rule"
	"strconv"
)

type Headers struct{ underlying map[string][]string }

func NewHeaders(initial map[string][]string) Headers {
	clone := make(map[string][]string, len(initial))
	for k, v := range initial {
		if rule.IsValidToken(k) {
			k = toCanonicalFieldName(k)
		}

		slice := make([]string, len(v))
		copy(slice, v)

		clone[k] = slice
	}

	return Headers{underlying: clone}
}

// HeadersFrom creates semantic header from raw fields.
// If mergeValue is true, It will merge multiplce lines with same key.
// If not, last value of the key will be used.
func HeadersFrom(fields []http.Field, mergeValues bool) Headers {
	clone := make(map[string][]string, len(fields))
	for _, field := range fields {
		key := string(field.Name)
		if rule.IsValidToken(key) {
			key = toCanonicalFieldName(key)
		}

		values := tokenizeFieldValues(field.Value)
		if v, ok := clone[key]; ok && mergeValues {
			// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-5.3-1
			values = append(v, values...)
		}

		clone[key] = values
	}

	return Headers{underlying: clone}
}

// Fields returns all the key-values in the header.
func (h *Headers) Fields() (fields map[string][]string) {
	clone := make(map[string][]string, len(h.underlying))
	for k, v := range h.underlying {
		sliceClone := make([]string, len(v))
		copy(sliceClone, v)

		clone[k] = sliceClone
	}

	return clone
}

func (h *Headers) ToRawFields() (fields []http.Field) {
	fields = make([]http.Field, 0, len(h.underlying))
	for k, v := range h.Fields() {
		key, value := []byte(k), toRawFieldValues(v)
		fields = append(fields, http.Field{Name: key, Value: value})
	}

	return fields
}

// Get assumes the field is a singleton field.
// Even if key has multiple values, it will only return the first element of values.
// For list-based field, use [Headers.Values].
func (h *Headers) Get(key string) (value string, ok bool) {
	v, ok := h.underlying[h.canonical(key)]
	if !ok || len(v) == 0 {
		return "", false
	}
	return v[0], true
}

func (h *Headers) Values(key string) (values []string, ok bool) {
	values, ok = h.underlying[h.canonical(key)]
	return
}

// Set assumes the field is a singleton field.
// It overwrites existing value instead of appending to it.
// For list-based field, use [Headers.Add].
func (h *Headers) Set(key, value string) {
	h.underlying[h.canonical(key)] = []string{value}
}

func (h *Headers) Add(key, value string) {
	key = h.canonical(key)
	h.underlying[key] = append(h.underlying[key], value)
}

func (h *Headers) Del(key string) {
	delete(h.underlying, h.canonical(key))
}

func (h *Headers) canonical(s string) string {
	if rule.IsValidToken(s) {
		s = toCanonicalFieldName(s)
	}
	return s
}

// This only works for valid token.
func toCanonicalFieldName(s string) string {
	const capitalDiff = 'a' - 'A'
	b := []byte(s)
	upper := true
	for i, c := range b {
		if upper && 'a' <= c && c <= 'z' {
			c -= capitalDiff
		} else if !upper && 'A' <= c && c <= 'Z' {
			c += capitalDiff
		}
		b[i] = c
		upper = c == '-'
	}
	return string(b)
}

func shouldQuote(s string) bool {
	for _, r := range s {
		switch r {
		case rune(rule.SP), ',':
			return true
		}
	}

	return false
}

func toRawFieldValues(values []string) []byte {
	clone := make([][]byte, len(values))
	for idx, v := range values {
		if shouldQuote(v) {
			v = strconv.Quote(v)
		}

		clone[idx] = []byte(v)
	}

	return bytes.Join(clone, []byte{',', rule.SP})
}

func tokenizeFieldValues(fieldValue []byte) []string {
	tokens := make([]string, 0)
	buf := bytes.NewBuffer(nil)

	parts := bytes.Split(fieldValue, []byte{','})

	// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-5.6.4-1
	quoted := false

	for _, part := range parts {
		if quoted {
			// Comma inside quote, let's write it again.
			buf.WriteByte(',')
		}

		for idx := 0; idx < len(part); idx++ {
			c := part[idx]
			if c == '"' {
				quoted = !quoted
			}

			buf.WriteByte(c)
		}

		if !quoted {
			tokens = addToken(tokens, buf.Bytes())
			buf.Reset()
		}
	}

	if buf.Len() > 0 {
		// Quote didn't end properly.
		// At least write the raw token.
		tokens = addToken(tokens, buf.Bytes())
	}

	return tokens
}

func addToken(tokens []string, token []byte) []string {
	token = bytes.TrimFunc(token, rule.IsWhitespace)
	token = rule.Unquote(token)
	if len(token) == 0 {
		// Don't append if it's empty.
		return tokens
	}
	return append(tokens, string(token))
}

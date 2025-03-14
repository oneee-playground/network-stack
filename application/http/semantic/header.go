package semantic

import "network-stack/application/util"

type Headers struct{ underlying map[string]string }

func NewHeaders(initial map[string]string) Headers {
	clone := make(map[string]string, len(initial))
	for k, v := range initial {
		if util.IsValidToken(k) {
			k = toCanonicalFieldName(k)
		}
		clone[k] = v
	}

	return Headers{underlying: clone}
}

// fields = [key, value]
func (h *Headers) Fields() (fields [][2]string) {
	fields = make([][2]string, 0, len(h.underlying))
	for k, v := range h.underlying {
		fields = append(fields, [2]string{k, v})
	}

	return fields
}

func (h *Headers) Get(key string) (value string, ok bool) {
	value, ok = h.underlying[toCanonicalFieldName(key)]
	return
}

func (h *Headers) Set(key, value string) {
	if util.IsValidToken(key) {
		key = toCanonicalFieldName(key)
	}
	h.underlying[key] = value
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

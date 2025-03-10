package http

import (
	"bytes"
	"io"
	"strconv"

	"github.com/pkg/errors"
)

const (
	CR   byte = '\r'
	LF   byte = '\n'
	SP   byte = ' '
	HTAB byte = '	'
	VT   byte = 0x0B
	FF   byte = 0x0C
)

var (
	OWS         = []byte{SP, HTAB}
	whitespaces = []byte{SP, HTAB, VT, FF, CR}
)

// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-5.6.2-2
func isValidToken(s string) bool {
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

// [Major, Minor]
type Version [2]uint

// ParseVersion parses http version text(e.g. "HTTP/1.1") into [Version].
func ParseVersion(b []byte) (Version, error) {
	prefix := []byte("HTTP/")
	if !bytes.HasPrefix(b, prefix) {
		return Version{}, errors.Errorf("http version prefix not found: %s", b)
	}

	// Get major and minor version.
	first, second, found := bytes.Cut(b[len(prefix):], []byte{'.'})
	if !found {
		return Version{}, errors.Errorf("dot seperator not found on version: %s", b)
	}

	major, err1 := strconv.ParseUint(string(first), 10, 64)
	minor, err2 := strconv.ParseUint(string(second), 10, 64)
	if err1 != nil || err2 != nil {
		return Version{}, errors.Errorf("http version is not convertable to int: %s", b)
	}

	return Version{uint(major), uint(minor)}, nil
}

func (ver Version) Text() []byte {
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte("HTTP/"))
	buf.Write([]byte(strconv.FormatUint(uint64(ver[0]), 10)))
	buf.Write([]byte{'.'})
	buf.Write([]byte(strconv.FormatUint(uint64(ver[1]), 10)))
	return buf.Bytes()
}

func (ver Version) String() string { return string(ver.Text()) }

type Headers struct{ underlying map[string]string }

func NewHeaders(initial map[string]string) Headers {
	clone := make(map[string]string, len(initial))
	for k, v := range initial {
		if isValidToken(k) {
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
	if isValidToken(key) {
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

type requestLine struct {
	Method  string
	Target  string
	Version Version
}

type Request struct {
	requestLine
	Headers Headers

	Body io.ReadCloser
}

type statusLine struct {
	Version      Version
	StatusCode   int
	ReasonPhrase string
}

type Response struct {
	statusLine
	Headers Headers
	Body    io.ReadCloser
}

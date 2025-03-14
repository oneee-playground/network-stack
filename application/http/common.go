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

type Field struct{ Key, Value string }

type Headers []Field

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

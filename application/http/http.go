package http

import (
	"bytes"
	"io"
	"network-stack/application/util/rule"
	"strconv"

	"github.com/pkg/errors"
)

type requestLine struct {
	Method  string
	Target  string
	Version Version
}

type Request struct {
	requestLine
	Headers []Field

	Body io.ReadCloser
}

type statusLine struct {
	Version      Version
	StatusCode   uint
	ReasonPhrase string
}

type Response struct {
	statusLine
	Headers []Field
	Body    io.ReadCloser
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

type Field struct{ Name, Value []byte }

func ParseField(fieldLine []byte) (Field, error) {
	name, value, found := bytes.Cut(fieldLine, []byte{':'})
	if !found {
		return Field{}, errors.Errorf("colon seperator not found on header: %q", string(fieldLine))
	}

	// No whitespace is allowed between field name and colon.
	// An option for correcting it could be provided, but let's reject it for now.
	// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-5.1-2
	for _, c := range rule.OWS {
		if bytes.HasSuffix(name, []byte{c}) {
			return Field{}, errors.New("field name has trailing whitespace")
		}
	}

	// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-5.1-3
	for _, c := range rule.OWS {
		value = bytes.Trim(value, string([]byte{c}))
	}

	return Field{Name: name, Value: value}, nil
}

func (f *Field) Text() []byte {
	buf := bytes.NewBuffer(nil)
	buf.Write(f.Name)
	buf.Write([]byte(": "))
	buf.Write(f.Value)
	return buf.Bytes()
}

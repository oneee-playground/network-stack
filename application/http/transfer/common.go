package transfer

import "io"

type Coding string

const (
	CodingChunked = "chunked"
)

type CoderFactory interface {
	Coding() Coding
	NewReader(r io.Reader) io.Reader
	NewWriter(w io.WriteCloser) io.WriteCloser
}

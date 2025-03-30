package transfer

import (
	"bytes"
	"io"
)

type stubWriteCloser struct {
	buf    *bytes.Buffer
	closed bool
}

var _ io.WriteCloser = (*stubWriteCloser)(nil)

func (w *stubWriteCloser) Close() error {
	w.closed = true
	return nil
}

func (w *stubWriteCloser) Write(p []byte) (n int, err error) {
	return w.buf.Write(p)
}

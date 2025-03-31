package iolib

import (
	"bytes"
	"io"

	"github.com/pkg/errors"
)

type MiddlewareReader struct {
	src  io.Reader
	buf  *bytes.Buffer
	bufw io.WriteCloser
}

func NewMiddlewareReader(
	src io.Reader, middleware func(io.WriteCloser) io.WriteCloser,
) *MiddlewareReader {
	mr := &MiddlewareReader{
		src: src,
		buf: bytes.NewBuffer(nil),
	}
	mr.bufw = middleware(NopWriteCloser(mr.buf))
	return mr
}

func (mr *MiddlewareReader) Read(p []byte) (n int, err error) {
	if mr.buf.Len() == 0 {
		n, err := mr.src.Read(p)
		if err != nil && err != io.EOF {
			return 0, errors.Wrap(err, "reading from source")
		}

		for written := 0; written < n; {
			nn, err := mr.bufw.Write(p[written:n])
			if err != nil {
				return 0, errors.Wrap(err, "failed to write")
			}
			written += nn
		}

		if err == io.EOF {
			if err := mr.bufw.Close(); err != nil {
				return 0, errors.Wrap(err, "failed to close middleware")
			}
		}
	}

	return mr.buf.Read(p)
}

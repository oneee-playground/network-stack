package iolib

import "io"

type nopWriteCloser struct{ w io.Writer }

func NopWriteCloser(w io.Writer) io.WriteCloser {
	return &nopWriteCloser{w: w}
}

func (nc *nopWriteCloser) Close() error {
	return nil
}

func (nc *nopWriteCloser) Write(p []byte) (n int, err error) {
	return nc.w.Write(p)
}

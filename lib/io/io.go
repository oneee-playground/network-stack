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

func WriteFull(w io.Writer, buf []byte) (uint, error) {
	total := uint(0)
	for total < uint(len(buf)) {
		n, err := w.Write(buf[total:])
		total += uint(n)
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

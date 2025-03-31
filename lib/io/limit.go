package iolib

import "io"

// LimitReader creates new [LimitedReader]
func LimitReader(r io.Reader, n uint) io.Reader { return &LimitedReader{r, n} }

// LimitedReader is uint port of [io.LimitedReader]
type LimitedReader struct {
	R io.Reader // underlying reader
	N uint      // max bytes remaining
}

func (l *LimitedReader) Read(p []byte) (n int, err error) {
	if l.N == 0 {
		return 0, io.EOF
	}
	if uint(len(p)) > l.N {
		p = p[:l.N]
	}
	n, err = l.R.Read(p)
	l.N -= uint(n)
	return
}

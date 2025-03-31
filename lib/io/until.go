package iolib

import (
	"bytes"
	"errors"
	"io"
)

type UntilReader struct {
	r io.Reader

	buf *bytes.Buffer
}

func NewUntilReader(r io.Reader) *UntilReader {
	return &UntilReader{r: r, buf: bytes.NewBuffer(nil)}
}

func (ur *UntilReader) Read(p []byte) (n int, err error) {
	if ur.buf.Len() > 0 {
		n, err = ur.buf.Read(p)
		if err == io.EOF {
			err = nil
		}
		return n, err
	}

	return ur.r.Read(p)
}

var ErrZeroLenDelim = errors.New("delim has zero length")

func (ur *UntilReader) ReadUntil(delim []byte) ([]byte, error) {
	if len(delim) == 0 {
		return nil, ErrZeroLenDelim
	}

	sum := 0
	temp := make([]byte, 1024)
	lastByte := delim[len(delim)-1]

	r := ur.r
	if ur.buf.Len() > 0 {
		// If buffer has remaining bytes,
		// append it to reader and reset the buffer.
		r = io.MultiReader(
			bytes.NewReader(bytes.Clone(ur.buf.Bytes())),
			ur.r,
		)
		ur.buf.Reset()
	}

	for {
		n, err := r.Read(temp)
		ur.buf.Write(temp[:n])

		// Seek for the last byte of delim on the temp.
		// If the last byte is found, check buf has suffix of delim.
		for seek := temp[:n]; ; {
			idx := bytes.IndexByte(seek, lastByte)
			if idx < 0 {
				break
			}

			// Original buf length + where lastByte was on temp.
			foundIdx := sum + n - len(seek) + idx

			buffered := ur.buf.Bytes()[:foundIdx+1]
			if bytes.HasSuffix(buffered, delim) {
				// Found the delim.
				// Truncate the buffer to only leave bytes after delim.
				buffered = bytes.Clone(buffered)
				ur.buf.Reset()
				ur.buf.Write(seek[idx+1:])
				return buffered, nil
			}

			seek = seek[idx+1:]
		}

		sum += n

		if err != nil {
			// Underlying reader returned error before delim.
			b := bytes.Clone(ur.buf.Bytes())
			ur.buf.Reset()
			return b, err
		}
	}
}

func (ur *UntilReader) ReadUntilLimit(delim []byte, limit uint) ([]byte, error) {
	if limit > 0 {
		r := ur.r
		ur.r = LimitReader(r, limit)
		defer func() { ur.r = r }() // restore underlying reader.
	}

	return ur.ReadUntil(delim)
}

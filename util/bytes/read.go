package bytesutil

import (
	"bufio"
	"bytes"
	"io"
)

// ReadUntil reads from r until delim. The output will include delim.
func ReadUntil(r *bufio.Reader, delim []byte) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	for {
		b, err := r.ReadBytes((delim[len(delim)-1]))
		if err != nil {
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}

		buf.Write(b)

		if bytes.HasSuffix(b, delim) {
			return buf.Bytes(), nil
		}
	}

}

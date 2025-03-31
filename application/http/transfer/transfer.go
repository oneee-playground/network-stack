package transfer

import (
	"io"
	"network-stack/application/http"

	"github.com/pkg/errors"
)

type Coding string

const (
	CodingChunked = "chunked"
)

type Coder interface {
	Coding() Coding
	NewReader(r io.Reader) io.Reader
	NewWriter(w io.WriteCloser) io.WriteCloser
}

type CodingPipeliner struct{ coders map[Coding]Coder }

func NewCodingPipeliner(customs []Coder) *CodingPipeliner {
	cp := &CodingPipeliner{}
	cp.coders = map[Coding]Coder{
		CodingChunked: NewChunkedCoder(),
	}

	for _, coder := range customs {
		cp.coders[coder.Coding()] = coder
	}

	return cp
}

var ErrUnsupportedCoding = errors.New("coding is unsupported")

func (cp *CodingPipeliner) Decode(r io.Reader, codings []Coding, onTrailer func(f []http.Field)) (io.Reader, error) {
	for idx := len(codings) - 1; idx >= 0; idx-- {
		coding := codings[idx]
		coder, ok := cp.coders[coding]
		if !ok {
			return nil, ErrUnsupportedCoding
		}

		r = coder.NewReader(r)
		if coding == CodingChunked && onTrailer != nil {
			chunkedCoder := r.(*ChunkedReader)

			chunkedCoder.SetOnTrailerReceived(func(f []http.Field) {
				if len(f) == 0 {
					return
				}
				onTrailer(f)
			})
		}
	}

	return r, nil
}

func (cp *CodingPipeliner) Encode(w io.WriteCloser, codings []Coding, sendTrailers func() []http.Field) (io.WriteCloser, error) {
	for idx := len(codings) - 1; idx >= 0; idx-- {
		coding := codings[idx]
		coder, ok := cp.coders[coding]
		if !ok {
			return nil, ErrUnsupportedCoding
		}

		w = coder.NewWriter(w)
		if coding == CodingChunked && sendTrailers != nil {
			chunkedCoder := w.(*ChunkedWriter)

			chunkedCoder.SetSendTrailers(sendTrailers)
		}
	}

	return w, nil
}

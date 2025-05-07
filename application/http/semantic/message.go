package semantic

import (
	"io"
	"network-stack/application/http"
	"network-stack/application/http/transfer"
	iolib "network-stack/lib/io"
	"network-stack/lib/types/pointer"
	"slices"
	"strconv"

	"github.com/pkg/errors"
)

type Message struct {
	Version http.Version

	Headers Headers

	ContentLength    *uint
	TransferEncoding []transfer.Coding

	Body io.Reader

	Trailers *Headers
}

type ParseMessageOptions struct {
	CombineFieldValues bool
	RequiredFields     []string
	MaxContentLen      uint
}

var ErrContentTooBig = errors.New("content is too big")

func createMessage(
	ver http.Version,
	headers []http.Field,
	body io.Reader,
	opts ParseMessageOptions,
) (msg Message, err error) {
	msg.Version = ver

	msg.Headers = HeadersFrom(headers, opts.CombineFieldValues)
	if err := assertHeaderContains(msg.Headers, opts.RequiredFields); err != nil {
		return Message{}, errors.Wrap(err, "header has missing fields")
	}

	msg.ContentLength, err = extractContentLength(msg.Headers)
	if err != nil {
		return Message{}, errors.Wrap(err, "extracting content length")
	}

	msg.Body = body

	// Validations below.
	if v, ok := msg.Headers.Values("Transfer-Encoding"); ok {
		// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-6.1
		for _, coding := range v {
			msg.TransferEncoding = append(msg.TransferEncoding, transfer.Coding(coding))
		}
	}
	if msg.ContentLength != nil {
		length := *msg.ContentLength
		if opts.MaxContentLen > 0 && length > opts.MaxContentLen {
			return Message{}, ErrContentTooBig
		}
	}

	return msg, nil
}

func (m *Message) IsChunked() bool {
	if len(m.TransferEncoding) == 0 {
		return false
	}

	last := m.TransferEncoding[len(m.TransferEncoding)-1]

	return last == transfer.CodingChunked
}

func (m *Message) EncodeTransfer(t *transfer.CodingApplier) error {
	var err error
	body := iolib.NewMiddlewareReader(m.Body,
		func(wc io.WriteCloser) io.WriteCloser {
			w, e := t.Encode(wc, m.TransferEncoding,
				func() []http.Field {
					// On chukned transfer's trailer is to be sent,
					// If trailer exists, send it.
					var trailers []http.Field
					if m.Trailers != nil {
						trailers = m.Trailers.ToRawFields()
					}
					return trailers
				},
			)

			if e != nil {
				// Give the error to the outside-func.
				err = e
				return nil
			}

			return w
		},
	)

	if err != nil {
		// Could be [transfer.ErrUnsupportedCoding]
		// In this case, the user is stupid.
		return errors.Wrap(err, "applying transfer coding to body")
	}

	m.Body = body
	return nil
}

func (m *Message) DecodeTransfer(t *transfer.CodingApplier, combineTrailerFields bool) error {
	body, err := t.Decode(m.Body, m.TransferEncoding,
		func(f []http.Field) {
			// On chukned transfer's trailer is received,
			// parse it and assign it to trailers.
			trailers := HeadersFrom(f, combineTrailerFields)
			m.Trailers = &trailers
		},
	)
	if err != nil {
		// Could be [transfer.ErrUnsupportedCoding]
		return errors.Wrap(err, "applying transfer coding to body")
	}

	m.Body = body
	return nil
}

func (m *Message) EnsureHeadersSet() {
	if m.Headers.underlying == nil {
		m.Headers = NewHeaders(nil)
	}

	if m.ContentLength != nil {
		m.Headers.Set("Content-Length", strconv.FormatUint(uint64(*m.ContentLength), 10))
	}
	if len(m.TransferEncoding) > 0 {
		m.Headers.Del("Transfer-Encoding")
		for _, enc := range m.TransferEncoding {
			m.Headers.Add("Transfer-Encoding", string(enc))
		}
	}
}

// Doesn't clone the body.
func (m Message) Clone() Message {
	msg := Message{
		Version:          m.Version,
		Headers:          HeadersFrom(m.Headers.ToRawFields(), true),
		TransferEncoding: slices.Clone(m.TransferEncoding),
		Body:             m.Body,
	}

	if m.Trailers != nil {
		msg.Trailers = pointer.To(HeadersFrom(m.Trailers.ToRawFields(), true))
	}
	if m.ContentLength != nil {
		msg.ContentLength = pointer.To(*m.ContentLength)
	}
	return msg
}

func assertHeaderContains(h Headers, keys []string) error {
	missing := make([]string, 0)
	for _, key := range keys {
		_, ok := h.Get(key)
		if !ok {
			missing = append(missing, key)
		}
	}

	if len(missing) > 0 {
		return errors.Errorf("missing key(s): %s", missing)
	}

	return nil
}

// extractContentLength extracts content length from headers.
func extractContentLength(h Headers) (*uint, error) {
	v, ok := h.Get("Content-Length")
	if !ok {
		return nil, nil
	}

	// Any value greater than or equal to 0 is valid.
	// But let's restrict it to 64bit uint.
	// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-8.6-10
	len64, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse Content-Length")
	}

	l := uint(len64)
	return &l, nil
}

package semantic

import (
	"io"
	"network-stack/application/http"
	"network-stack/application/http/transfer"
	iolib "network-stack/lib/io"
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
}

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
	} else {
		if msg.ContentLength != nil {
			// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-8.6
			msg.Body = iolib.LimitReader(msg.Body, *msg.ContentLength)
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

func (m *Message) EnsureHeadersSet() {
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

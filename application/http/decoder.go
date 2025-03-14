package http

import (
	"bufio"
	"bytes"
	"io"
	"strconv"

	"network-stack/application/util"
	bytesutil "network-stack/util/bytes"

	"github.com/pkg/errors"
)

type DecodeOptions struct {
	// AllowSoleLF specifies wheter a single LF character should be recognized as a valid line terminator.
	//
	// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-2.2-3
	AllowSoleLF bool

	// LenientWhitespace replaces all [whitespaces] into [SP].
	// And also trims preceding and trailinig whitespace.
	//
	// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-3-3
	LenientWhitespace bool

	// MaxFieldLineLength sets the limit of field line length on headers.
	// It's not on the RFC but I think it's better to have it.
	MaxFieldLineLength uint

	// MaxRequestLineLength sets the limit of request line length.
	// Recommended: >= 8000
	//
	// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-3-5
	MaxRequestLineLength uint

	// MaxStatusLineLength sets the limit of status line length.
	// It's not on the RFC but I think it's better to have it.
	MaxStatusLineLength uint
}

var DefaultDecodeOptions = DecodeOptions{
	AllowSoleLF:          false,
	LenientWhitespace:    false,
	MaxFieldLineLength:   0,
	MaxRequestLineLength: 0,
	MaxStatusLineLength:  0,
}

type MessageDecoder struct {
	br   *bufio.Reader
	opts DecodeOptions
}

var errLineTooLong = errors.New("line length exceeeds limit")

func (md *MessageDecoder) readLine(limit uint) ([]byte, error) {
	b, err := bytesutil.ReadUntil(md.br, []byte{LF})
	if err != nil {
		return nil, err
	}

	if limit > 0 && uint(len(b)) > limit {
		// TODO: This does not prevent reading huge bytes.
		return nil, errLineTooLong
	}

	b = b[:len(b)-1] // Remove LF.

	if !md.opts.AllowSoleLF {
		if len(b) == 0 || b[len(b)-1] != CR {
			return nil, errors.New("missing CR before LF")
		}
		b = b[:len(b)-1] // Remove CR.
	}

	if md.opts.LenientWhitespace {
		for _, c := range whitespaces {
			b = bytes.ReplaceAll(b, []byte{c}, []byte{SP})
		}
		b = bytes.Trim(b, string([]byte{SP}))

		return b, nil
	}

	// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-2.2-4
	b = bytes.ReplaceAll(b, []byte{CR}, []byte{SP})

	return b, nil
}

var ErrFieldLineTooLong = errors.New("field line length exceeds limit")

func (md *MessageDecoder) decodeHeaders(headers *Headers) error {
	tmpHeaders := make(Headers, 0)
	for {
		fieldLine, err := md.readLine(md.opts.MaxFieldLineLength)
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				return ErrFieldLineTooLong
			}
			return errors.Wrap(err, "reading line")
		}

		if len(fieldLine) == 0 {
			// An empty line. This means that there are no more headers.
			break
		}

		name, value, found := bytes.Cut(fieldLine, []byte{':'})
		if !found {
			return errors.Errorf("colon seperator not found on header: %q", string(fieldLine))
		}

		// No whitespace is allowed between field name and colon.
		// An option for correcting it could be provided, but let's reject it for now.
		// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-5.1-2
		for _, c := range OWS {
			if bytes.HasSuffix(name, []byte{c}) {
				return errors.New("field name has trailing whitespace")
			}
		}

		// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-5.1-3
		for _, c := range OWS {
			value = bytes.Trim(value, string([]byte{c}))
		}

		tmpHeaders = append(tmpHeaders, Field{string(name), string(value)})
	}

	*headers = tmpHeaders

	return nil
}

var (
	ErrRequestLineTooLong = errors.New("request line length exceeds limit")
)

type RequestDecoder struct{ MessageDecoder }

func NewRequestDecoder(r io.Reader, opts DecodeOptions) *RequestDecoder {
	return &RequestDecoder{
		MessageDecoder{br: bufio.NewReader(r), opts: opts},
	}
}

// r MUST be a non-nil pointer
func (rd *RequestDecoder) Decode(r *Request) error {
	if err := rd.decodeRequestLine(&r.requestLine); err != nil {
		return errors.Wrap(err, "parsing request line")
	}

	if err := rd.decodeHeaders(&r.Headers); err != nil {
		return errors.Wrap(err, "parsing headers")
	}

	r.Body = io.NopCloser(rd.br)

	return nil
}

func (rd *RequestDecoder) decodeRequestLine(reqLine *requestLine) error {
	var line []byte
	for {
		b, err := rd.readLine(rd.opts.MaxRequestLineLength)
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				return ErrRequestLineTooLong
			}
			return errors.Wrap(err, "reading line")
		}

		// An empty line can be received before message.
		// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-2.2-6
		if len(b) > 0 {
			line = b
			break
		}
	}

	parsed, err := parseRequestLine(line)
	if err != nil {
		return errors.Wrapf(err, "failed to parse the line: %q", string(line))
	}

	*reqLine = parsed

	return nil
}

func parseRequestLine(line []byte) (requestLine, error) {
	parts := bytes.Split(line, []byte{SP})
	if len(parts) != 3 {
		return requestLine{}, errors.New("request line is malformed")
	}

	method := string(parts[0])
	if !util.IsValidToken(method) {
		return requestLine{}, errors.New("method is not a valid token")
	}

	target := string(parts[1])
	if len(target) == 0 {
		return requestLine{}, errors.New("request target should not be empty")
	}

	ver, err := ParseVersion(parts[2])
	if err != nil {
		return requestLine{}, errors.Wrap(err, "parsing version")
	}

	return requestLine{Method: method, Target: target, Version: ver}, nil
}

var (
	ErrStatusLineTooLong = errors.New("status line length exceeds limit")
)

type ResponseDecoder struct{ MessageDecoder }

func NewResponseDecoder(r io.Reader, opts DecodeOptions) *ResponseDecoder {
	return &ResponseDecoder{
		MessageDecoder{br: bufio.NewReader(r), opts: opts},
	}
}

// r MUST be a non-nil pointer
func (rd *ResponseDecoder) Decode(r *Response) error {
	if err := rd.decodeStatusLine(&r.statusLine); err != nil {
		return errors.Wrap(err, "parsing request line")
	}

	if err := rd.decodeHeaders(&r.Headers); err != nil {
		return errors.Wrap(err, "parsing headers")
	}

	r.Body = io.NopCloser(rd.br)

	return nil
}

func (rd *ResponseDecoder) decodeStatusLine(statLine *statusLine) error {
	var line []byte
	for {
		b, err := rd.readLine(rd.opts.MaxStatusLineLength)
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				return ErrStatusLineTooLong
			}
			return errors.Wrap(err, "reading line")
		}

		// An empty line can be received before message.
		// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-2.2-6
		if len(b) > 0 {
			line = b
			break
		}
	}

	parsed, err := parseStatusLine(line)
	if err != nil {
		return errors.Wrapf(err, "failed to parse the line: %q", string(line))
	}

	*statLine = parsed

	return nil
}

func parseStatusLine(line []byte) (statusLine, error) {
	parts := bytes.SplitN(line, []byte{SP}, 3)
	if len(parts) < 3 {
		return statusLine{}, errors.New("status line is malformed")
	}

	ver, err := ParseVersion(parts[0])
	if err != nil {
		return statusLine{}, errors.Wrap(err, "parsing version")
	}

	statusCodeStr := string(parts[1])
	statusCode, err := strconv.Atoi(statusCodeStr)
	if err != nil || len(statusCodeStr) != 3 {
		return statusLine{}, errors.Errorf("status code is malformed: %q", statusCodeStr)
	}

	// reason-phrase is optional.
	reasonPhrase := string(parts[2])

	return statusLine{Version: ver, StatusCode: statusCode, ReasonPhrase: reasonPhrase}, nil
}

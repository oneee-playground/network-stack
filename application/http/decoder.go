package http

import (
	"bytes"
	"io"
	"strconv"

	"network-stack/application/util/rule"
	iolib "network-stack/lib/io"

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
	r    *iolib.UntilReader
	opts DecodeOptions
}

var (
	errLineTooLong       = errors.New("line length exceeeds limit")
	ErrMissingCRBeforeLF = errors.New("missing CR before LF")
)

func (md *MessageDecoder) readLine(limit uint) ([]byte, error) {
	b, err := md.r.ReadUntilLimit([]byte{rule.LF}, limit)
	if err != nil {
		if limit > 0 && err == io.EOF {
			return nil, errLineTooLong
		}
		return nil, err
	}

	b = b[:len(b)-1] // Remove LF.

	if !md.opts.AllowSoleLF {
		if len(b) == 0 || b[len(b)-1] != rule.CR {
			return nil, ErrMissingCRBeforeLF
		}
		b = b[:len(b)-1] // Remove CR.
	}

	if md.opts.LenientWhitespace {
		for _, c := range rule.Whitespaces {
			b = bytes.ReplaceAll(b, []byte{c}, []byte{rule.SP})
		}
		b = bytes.Trim(b, string([]byte{rule.SP}))

		return b, nil
	}

	// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-2.2-4
	b = bytes.ReplaceAll(b, []byte{rule.CR}, []byte{rule.SP})

	return b, nil
}

var (
	ErrFieldLineTooLong   = errors.New("field line length exceeds limit")
	ErrMalformedFieldLine = errors.New("field line is malformed")
)

func (md *MessageDecoder) decodeHeaders(headers *[]Field) error {
	tmpHeaders := make([]Field, 0)
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

		field, err := ParseField(fieldLine)
		if err != nil {
			return ErrMalformedFieldLine
		}

		tmpHeaders = append(tmpHeaders, field)
	}

	*headers = tmpHeaders

	return nil
}

var (
	ErrRequestLineTooLong   = errors.New("request line length exceeds limit")
	ErrMalformedRequestLine = errors.New("request line is malformed")
)

type RequestDecoder struct{ MessageDecoder }

func NewRequestDecoder(r *iolib.UntilReader, opts DecodeOptions) *RequestDecoder {
	return &RequestDecoder{MessageDecoder{
		opts: opts,
		r:    r,
	}}
}

// r MUST be a non-nil pointer
func (rd *RequestDecoder) Decode(r *Request) error {
	if err := rd.decodeRequestLine(&r.RequestLine); err != nil {
		return errors.Wrap(err, "parsing request line")
	}

	if err := rd.decodeHeaders(&r.Headers); err != nil {
		return errors.Wrap(err, "parsing headers")
	}

	r.Body = rd.r

	return nil
}

func (rd *RequestDecoder) decodeRequestLine(reqLine *RequestLine) error {
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
		return ErrMalformedRequestLine
	}

	*reqLine = parsed

	return nil
}

func parseRequestLine(line []byte) (RequestLine, error) {
	parts := bytes.Split(line, []byte{rule.SP})
	if len(parts) != 3 {
		return RequestLine{}, errors.New("request line is malformed")
	}

	method := string(parts[0])
	if !rule.IsValidToken(method) {
		return RequestLine{}, errors.New("method is not a valid token")
	}

	target := string(parts[1])
	if len(target) == 0 {
		return RequestLine{}, errors.New("request target should not be empty")
	}

	ver, err := ParseVersion(parts[2])
	if err != nil {
		return RequestLine{}, errors.Wrap(err, "parsing version")
	}

	return RequestLine{Method: method, Target: target, Version: ver}, nil
}

var (
	ErrStatusLineTooLong   = errors.New("status line length exceeds limit")
	ErrMalformedStatusLine = errors.New("status line is malformed")
)

type ResponseDecoder struct{ MessageDecoder }

func NewResponseDecoder(r *iolib.UntilReader, opts DecodeOptions) *ResponseDecoder {
	return &ResponseDecoder{
		MessageDecoder{
			r:    r,
			opts: opts,
		},
	}
}

// r MUST be a non-nil pointer
func (rd *ResponseDecoder) Decode(r *Response) error {
	if err := rd.decodeStatusLine(&r.StatusLine); err != nil {
		return errors.Wrap(err, "parsing request line")
	}

	if err := rd.decodeHeaders(&r.Headers); err != nil {
		return errors.Wrap(err, "parsing headers")
	}

	r.Body = rd.r

	return nil
}

func (rd *ResponseDecoder) decodeStatusLine(statLine *StatusLine) error {
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
		return ErrMalformedStatusLine
	}

	*statLine = parsed

	return nil
}

func parseStatusLine(line []byte) (StatusLine, error) {
	parts := bytes.SplitN(line, []byte{rule.SP}, 3)
	if len(parts) < 3 {
		return StatusLine{}, errors.New("status line is malformed")
	}

	ver, err := ParseVersion(parts[0])
	if err != nil {
		return StatusLine{}, errors.Wrap(err, "parsing version")
	}

	statusCodeStr := string(parts[1])
	statusCode, err := strconv.ParseUint(statusCodeStr, 10, 64)
	if err != nil || len(statusCodeStr) != 3 {
		return StatusLine{}, errors.Errorf("status code is malformed: %q", statusCodeStr)
	}

	// reason-phrase is optional.
	reasonPhrase := string(parts[2])

	return StatusLine{Version: ver, StatusCode: uint(statusCode), ReasonPhrase: reasonPhrase}, nil
}

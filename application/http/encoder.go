package http

import (
	"bufio"
	"bytes"
	"io"
	"strconv"

	"network-stack/application/util/rule"

	"github.com/pkg/errors"
)

type EncodeOptions struct {
	// UseSoleLF specifies wheter a single LF character should be used as a line terminator.
	//
	// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-2.2-3
	UseSoleLF bool
}

var DefaultEncodeOptions = EncodeOptions{
	UseSoleLF: false,
}

type MessageEncoder struct {
	bw   *bufio.Writer
	opts EncodeOptions
}

func (me *MessageEncoder) writeLine(line []byte) error {
	if _, err := me.bw.Write(line); err != nil {
		return errors.Wrap(err, "writing line")
	}

	term := rule.CRLF
	if me.opts.UseSoleLF {
		term = term[1:]
	}

	if _, err := me.bw.Write(term); err != nil {
		return errors.Wrap(err, "writing line terminator")
	}

	return nil
}

func (me *MessageEncoder) encodeHeaders(headers []Field) error {
	for _, field := range headers {
		if err := me.writeLine(field.Text()); err != nil {
			return errors.Wrap(err, "writing field")
		}
	}

	// Write a empty line as all the headers are written.
	if err := me.writeLine(nil); err != nil {
		return errors.Wrap(err, "writing line terminator")
	}

	return nil
}

type RequestEncoder struct{ MessageEncoder }

func NewRequestEncoder(w io.Writer, opts EncodeOptions) *RequestEncoder {
	return &RequestEncoder{
		MessageEncoder{
			bw:   bufio.NewWriter(w),
			opts: opts,
		},
	}
}

func (re *RequestEncoder) Encode(request Request) error {
	if err := re.encodeRequestLine(request.requestLine); err != nil {
		return errors.Wrap(err, "encoding request line")
	}

	if err := re.encodeHeaders(request.Headers); err != nil {
		return errors.Wrap(err, "encoding headers")
	}

	// I think it's better to flush it before body.
	if err := re.bw.Flush(); err != nil {
		return errors.Wrap(err, "flushing requst line & header")
	}

	if _, err := re.bw.ReadFrom(request.Body); err != nil {
		return errors.Wrap(err, "writing request body")
	}

	if err := re.bw.Flush(); err != nil {
		return errors.Wrap(err, "flushing request body")
	}

	return nil
}

func (re *RequestEncoder) encodeRequestLine(reqLine requestLine) error {
	buf := bytes.NewBuffer(nil)

	buf.Write([]byte(reqLine.Method))
	buf.WriteByte(rule.SP)
	buf.Write([]byte(reqLine.Target))
	buf.WriteByte(rule.SP)
	buf.Write(reqLine.Version.Text())

	if err := re.writeLine(buf.Bytes()); err != nil {
		return errors.Wrap(err, "writing line")
	}

	return nil
}

type ResponseEncoder struct{ MessageEncoder }

func NewResponseEncoder(w io.Writer, opts EncodeOptions) *ResponseEncoder {
	return &ResponseEncoder{
		MessageEncoder{
			bw:   bufio.NewWriter(w),
			opts: opts,
		},
	}
}

func (re *ResponseEncoder) Encode(response Response) error {
	if err := re.encodeStatusLine(response.statusLine); err != nil {
		return errors.Wrap(err, "encoding status line")
	}

	if err := re.encodeHeaders(response.Headers); err != nil {
		return errors.Wrap(err, "encoding headers")
	}

	// I think it's better to flush it before body.
	if err := re.bw.Flush(); err != nil {
		return errors.Wrap(err, "flushing response line & header")
	}

	defer response.Body.Close()
	if _, err := re.bw.ReadFrom(response.Body); err != nil {
		return errors.Wrap(err, "writing response body")
	}

	if err := re.bw.Flush(); err != nil {
		return errors.Wrap(err, "flushing response body")
	}

	return nil
}

func (re *ResponseEncoder) encodeStatusLine(statLine statusLine) error {
	buf := bytes.NewBuffer(nil)

	buf.Write(statLine.Version.Text())
	buf.WriteByte(rule.SP)
	buf.Write([]byte(strconv.Itoa(statLine.StatusCode)))
	buf.WriteByte(rule.SP)
	buf.Write([]byte(statLine.ReasonPhrase))

	if err := re.writeLine(buf.Bytes()); err != nil {
		return errors.Wrap(err, "writing line")
	}

	return nil
}

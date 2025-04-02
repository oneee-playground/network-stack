package semantic

import (
	"network-stack/application/http"
	"network-stack/application/http/semantic/status"
	"time"

	"github.com/pkg/errors"
)

type Response struct {
	Message
	raw *http.Response

	Status status.Status
	Date   time.Time
}

type ParseResponseOptions struct {
	ParseMessageOptions
}

func ResponseFrom(raw *http.Response, opts ParseResponseOptions) (*Response, error) {
	response := Response{
		raw:    raw,
		Status: status.Status{Code: raw.StatusCode, ReasonPhrase: raw.ReasonPhrase},
	}

	var err error
	response.Message, err = createMessage(raw.Version, raw.Headers, raw.Body, opts.ParseMessageOptions)
	if err != nil {
		return nil, err
	}

	response.Date, err = extractDate(response.Headers)
	if err != nil {
		return nil, errors.Wrap(err, "extracting date")
	}

	return &response, nil
}

func (r *Response) EnsureHeadersSet() {
	r.Message.EnsureHeadersSet()

	r.Headers.Set("Date", r.Date.Format(imfFixDateFormat))
}

func (r *Response) RawResponse() http.Response {
	if r.raw != nil {
		return *r.raw
	}

	res := http.Response{
		StatusLine: http.StatusLine{
			Version:      r.Version,
			StatusCode:   r.Status.Code,
			ReasonPhrase: r.Status.ReasonPhrase,
		},
		Headers: r.Headers.ToRawFields(),
		Body:    r.Body,
	}

	return res
}

func extractDate(h Headers) (time.Time, error) {
	v, ok := h.Get("Date")
	if !ok {
		return time.Time{}, nil
	}

	return ParseDate(v)
}

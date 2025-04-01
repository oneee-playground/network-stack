package semantic

import (
	"network-stack/application/http"
	"network-stack/application/http/semantic/status"

	"github.com/pkg/errors"
)

type Response struct {
	Message
	raw *http.Response

	Status status.Status
}

type ParseResponseOptions struct {
	ParseMessageOptions
}

func ResponseFrom(raw *http.Response, opts ParseResponseOptions) (*Response, error) {
	response := Response{
		raw:    raw,
		Status: status.Status{Code: raw.StatusCode, ReasonPhrase: raw.ReasonPhrase},
	}

	response.Headers = HeadersFrom(raw.Headers, opts.CombineFieldValues)
	if err := assertHeaderContains(response.Headers, opts.RequiredFields); err != nil {
		return nil, errors.Wrap(err, "header has missing fields")
	}

	response.Body = raw.Body

	var err error
	response.Message, err = createMessage(raw.Version, raw.Headers, raw.Body, opts.ParseMessageOptions)
	if err != nil {
		return nil, err
	}

	return &response, nil
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

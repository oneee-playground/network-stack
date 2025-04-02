package semantic

import (
	"network-stack/application/http"
	"network-stack/application/util/uri"
	"strings"

	"github.com/pkg/errors"
)

type Request struct {
	Message
	raw *http.Request

	Method Method
	URI    uri.URI

	Host string
}

type ParseRequestOptions struct {
	ParseMessageOptions

	IsForwardProxy bool
	MaxURILen      uint
}

func RequestFrom(raw *http.Request, opts ParseRequestOptions) (*Request, error) {
	request := Request{
		raw:    raw,
		Method: Method(raw.Method),
	}

	var err error
	request.Message, err = createMessage(
		raw.Version, raw.Headers, raw.Body, opts.ParseMessageOptions,
	)
	if err != nil {
		return nil, err
	}

	request.Host, err = extractHost(request.Headers)
	if err != nil {
		return nil, errors.Wrap(err, "extracting host")
	}

	request.URI, err = parseAndValidateURI(
		raw.Target, request.Method, opts.IsForwardProxy, opts.MaxURILen,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse URI")
	}

	if !(request.Method == MethodOptions || request.Method == MethodConnect) {

		request.URI = normalizeURI(request.URI)
	}

	if request.URI.IsAbsoluteURI() {
		// Reference:
		// - https://datatracker.ietf.org/doc/html/rfc9112#section-3.2.2-7
		// - https://datatracker.ietf.org/doc/html/rfc9112#section-3.2.2-8
		host := ""
		if request.URI.Authority != nil {
			host = request.URI.Authority.Host
		}
		request.Headers.Set("Host", host)
		request.Host = host
	}

	return &request, nil
}

func (r *Request) EnsureHeadersSet() {
	r.Message.EnsureHeadersSet()

	r.Headers.Set("Host", r.Host)
}

func (r *Request) RawRequest() http.Request {
	if r.raw != nil {
		return *r.raw
	}

	req := http.Request{
		RequestLine: http.RequestLine{
			Method:  string(r.Method),
			Target:  r.URI.String(),
			Version: r.Version,
		},
		Headers: r.Headers.ToRawFields(),
		Body:    r.Body,
	}

	return req
}

func extractHost(h Headers) (string, error) {
	v, ok := h.Get("Host")
	if !ok {
		return "", nil
	}

	if err := uri.AssertValidHost(v); err != nil {
		return "", errors.Wrap(err, "host value is not valid")
	}

	return v, nil
}

var ErrURITooLong = errors.New("uri too long")

// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-3.2
func parseAndValidateURI(
	raw string, method Method, isForwardProxy bool, maxLen uint,
) (uri.URI, error) {
	if maxLen > 0 && uint(len(raw)) > maxLen {
		return uri.URI{}, ErrURITooLong
	}

	u, err := uri.Parse(raw)
	if err != nil {
		return uri.URI{}, err
	}

	switch method {
	case MethodConnect:
		// authority-form.
		// It doesn't follow uri rule, so it won't be parsed properly.
		// Let's create a temporary uri here.
		// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-3.2.3
		u, err = parseAuthorityForm(raw)
		if err != nil {
			return uri.URI{}, errors.Wrap(err, "failed to parse authority-form")
		}
	case MethodOptions:
		// asterisk-form
		// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-3.2.4
		if u.String() != "*" {
			return uri.URI{}, errors.New("OPTIONS request's target should be asterisk-form")
		}
	default:
		if u.IsAbsoluteURI() {
			// absolute-form
			// These assertions below aren't explicitly described in the RFC.
			// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-3.2.2
			if !(u.Scheme == "http" || u.Scheme == "https") {
				return uri.URI{}, errors.New("scheme is invalid. allowed schemes are: http, https")
			}
			if u.Authority == nil {
				return uri.URI{}, errors.New("absoulte-form needs authority")
			}
		} else {
			if isForwardProxy {
				return uri.URI{}, errors.New("forward-proxy only allows absoulte-uri")
			}
			// origin-form
			// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-3.2.1
			if !strings.HasPrefix(u.Path, "/") {
				return uri.URI{}, errors.New("origin-form uri's path should start with /")
			}
		}
	}

	return u, nil
}

func parseAuthorityForm(raw string) (uri.URI, error) {
	idx := strings.Index(raw, ":")
	if idx < 0 {
		return uri.URI{}, errors.New("authority-form doesn't contain ':'")
	}

	host := raw[:idx]
	if err := uri.AssertValidHost(host); err != nil {
		return uri.URI{}, errors.Wrap(err, "host isn't valid")
	}

	port, hasPort, err := uri.ParsePort(raw[idx:])
	if err != nil {
		return uri.URI{}, errors.Wrap(err, "failed to parse port")
	}
	if !hasPort {
		return uri.URI{}, errors.New("port in authority form is required")
	}

	return uri.URI{
		Authority: &uri.Authority{
			Host: host,
			Port: &port,
		},
	}, nil
}

// normalizeURI normalizes given URI based on scheme-based normalization.
// It assumes that URI is produced by [uri.Parse]. So it only performs http-specific normalization.
// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-4.2.3
func normalizeURI(u uri.URI) uri.URI {
	if u.Authority != nil && u.Authority.Port != nil {
		// If the port is equal to the default port for a scheme,
		// the normal form is to omit the port subcomponent.
		p := *u.Authority.Port
		if false ||
			(u.Scheme == "http" && p == defaultPort("http")) ||
			(u.Scheme == "https" && p == defaultPort("https")) {
			u.Authority.Port = nil
		}
	}

	if u.Path == "" {
		// When not being used as the target of an OPTIONS request,
		// an empty path component is equivalent to an absolute path of "/",
		// so the normal form is to provide a path of "/" instead
		u.Path = "/"
	}

	// - The scheme and host are case-insensitive and normally provided in lowercase;
	//   all other components are compared in a case-sensitive manner.
	// - Characters other than those in the "reserved" set are equivalent to their percent-encoded octets:
	// 	 the normal form is to not encode them (see Sections 2.1 and 2.2 of [URI]).
	//
	// Already done in [uri.Parse].

	return u
}

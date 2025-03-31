package semantic

import (
	"time"

	"github.com/pkg/errors"
)

func defaultPort(scheme string) uint16 {
	switch scheme {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}

type Method string

const (
	MethodGet     Method = "GET"
	MethodHead    Method = "HEAD"
	MethodPost    Method = "POST"
	MethodPut     Method = "PUT"
	MethodDelete  Method = "DELETE"
	MethodConnect Method = "CONNECT"
	MethodOptions Method = "OPTIONS"
	MethodTrace   Method = "TRACE"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-9.2.1-3
func DefaultSafeMethods() []Method {
	return []Method{
		MethodGet, MethodHead, MethodOptions, MethodTrace,
	}
}

const (
	// Preferred format: IMF-fixdate
	imfFixDateFormat = "Mon, 02 Jan 2006 15:04:05 GMT"
	// Obsolete RFC 850 format
	rfc850DateFormat = "Monday, 02-Jan-06 15:04:05 GMT"
	// Obsolete asctime format
	asctimeDateFormat = "Mon Jan _2 15:04:05 2006"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-5.6.7
func ParseDate(raw string) (time.Time, error) {
	layouts := []string{imfFixDateFormat, rfc850DateFormat, asctimeDateFormat}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, nil
		}
	}

	return time.Time{}, errors.Errorf("invalid time format: %q", raw)
}

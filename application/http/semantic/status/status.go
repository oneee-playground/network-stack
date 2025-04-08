package status

type Status struct {
	Code         uint
	ReasonPhrase string
}

// Informational 1XX
// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-15.2
var (
	Continue           = add(Status{100, "Continue"})
	SwitchingProtocols = add(Status{101, "Switching Protocols"})
)

// Successful 2XX
// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-15.3
var (
	OK                   = add(Status{200, "OK"})
	Created              = add(Status{201, "Created"})
	Accepted             = add(Status{202, "Accepted"})
	NonAuthoritativeInfo = add(Status{203, "Non-Authoritative Information"})
	NoContent            = add(Status{204, "No Content"})
	ResetContent         = add(Status{205, "Reset Content"})
	PartialContent       = add(Status{206, "Partial Content"})
)

// Redirection 3xx
// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-15.4
var (
	MultipleChoices   = add(Status{300, "Multiple Choices"})
	MovedPermanently  = add(Status{301, "Moved Permanently"})
	Found             = add(Status{302, "Found"})
	SeeOther          = add(Status{303, "See Other"})
	NotModified       = add(Status{304, "Not Modified"})
	UseProxy          = add(Status{305, "Use Proxy"})
	_                 = add(Status{306, ""}) // Unused
	TemporaryRedirect = add(Status{307, "Temporary Redirect"})
	PermanentRedirect = add(Status{308, "Permanent Redirect"})
)

// Client Error 4xx
// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-15.5
var (
	BadRequest           = add(Status{400, "Bad Request"})
	Unauthorized         = add(Status{401, "Unauthorized"})
	PaymentRequired      = add(Status{402, "Payment Required"})
	Forbidden            = add(Status{403, "Forbidden"})
	NotFound             = add(Status{404, "Not Found"})
	MethodNotAllowed     = add(Status{405, "Method Not Allowed"})
	NotAcceptable        = add(Status{406, "Not Acceptable"})
	ProxyAuthRequired    = add(Status{407, "Proxy Authentication Required"})
	RequestTimeout       = add(Status{408, "Request Timeout"})
	Conflict             = add(Status{409, "Conflict"})
	Gone                 = add(Status{410, "Gone"})
	LengthRequired       = add(Status{411, "Length Required"})
	PreconditionFailed   = add(Status{412, "Precondition Failed"})
	ContentTooLarge      = add(Status{413, "Content Too Large"})
	RequestURITooLong    = add(Status{414, "Request URI TooLong"})
	UnsupportedMediaType = add(Status{415, "Unsupported Media Type"})
	RangeNotSatisfiable  = add(Status{416, "Range Not Satisfiable"})
	ExpectationFailed    = add(Status{417, "Expectation Failed"})
	ImATeapot            = add(Status{418, "I'm a teapot"}) // Unused. But I like the joke.
	MisdirectedRequest   = add(Status{421, "Misdirected Request"})
	UnprocessableContent = add(Status{422, "Unprocessable Content"})
	UpgradeRequired      = add(Status{426, "Upgrade Required"})
)

// Server Error 5xx
// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-15.6
var (
	InternalServerError     = add(Status{500, "Internal Server Error"})
	NotImplemented          = add(Status{501, "Not Implemented"})
	BadGateway              = add(Status{502, "Bad Gateway"})
	ServiceUnavailable      = add(Status{503, "Service Unavailable"})
	GatewayTimeout          = add(Status{504, "Gateway Timeout"})
	HTTPVersionNotSupported = add(Status{505, "HTTP Version Not Supported"})
)

var sm = make(map[uint]*Status)

func add(status Status) Status {
	sm[status.Code] = &status
	return status
}

func FromCode(code uint) (status Status, ok bool) {
	s, ok := sm[code]
	if !ok {
		return Status{Code: code, ReasonPhrase: ""}, false
	}

	return *s, true
}

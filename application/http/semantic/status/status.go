package status

type Status struct {
	Code         uint
	ReasonPhrase string
}

// Informational 1XX
// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-15.2
var (
	Continue           = Status{100, "Continue"}
	SwitchingProtocols = Status{101, "Switching Protocols"}
)

// Successful 2XX
// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-15.3
var (
	OK                   = Status{200, "OK"}
	Created              = Status{201, "Created"}
	Accepted             = Status{202, "Accepted"}
	NonAuthoritativeInfo = Status{203, "Non-Authoritative Information"}
	NoContent            = Status{204, "No Content"}
	ResetContent         = Status{205, "Reset Content"}
	PartialContent       = Status{206, "Partial Content"}
)

// Redirection 3xx
// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-15.4
var (
	MultipleChoices   = Status{300, "Multiple Choices"}
	MovedPermanently  = Status{301, "Moved Permanently"}
	Found             = Status{302, "Found"}
	SeeOther          = Status{303, "See Other"}
	NotModified       = Status{304, "Not Modified"}
	UseProxy          = Status{305, "Use Proxy"}
	_                 = Status{306, ""} // Unused
	TemporaryRedirect = Status{307, "Temporary Redirect"}
	PermanentRedirect = Status{308, "Permanent Redirect"}
)

// Client Error 4xx
// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-15.5
var (
	BadRequest           = Status{400, "Bad Request"}
	Unauthorized         = Status{401, "Unauthorized"}
	PaymentRequired      = Status{402, "Payment Required"}
	Forbidden            = Status{403, "Forbidden"}
	NotFound             = Status{404, "Not Found"}
	MethodNotAllowed     = Status{405, "Method Not Allowed"}
	NotAcceptable        = Status{406, "Not Acceptable"}
	ProxyAuthRequired    = Status{407, "Proxy Authentication Required"}
	RequestTimeout       = Status{408, "Request Timeout"}
	Conflict             = Status{409, "Conflict"}
	Gone                 = Status{410, "Gone"}
	LengthRequired       = Status{411, "Length Required"}
	PreconditionFailed   = Status{412, "Precondition Failed"}
	ContentTooLarge      = Status{413, "Content Too Large"}
	RequestURITooLong    = Status{414, "Request URI TooLong"}
	UnsupportedMediaType = Status{415, "Unsupported Media Type"}
	RangeNotSatisfiable  = Status{416, "Range Not Satisfiable"}
	ExpectationFailed    = Status{417, "Expectation Failed"}
	ImATeapot            = Status{418, "I'm a teapot"} // Unused. But I like the joke.
	MisdirectedRequest   = Status{421, "Misdirected Request"}
	UnprocessableContent = Status{422, "Unprocessable Content"}
	UpgradeRequired      = Status{426, "Upgrade Required"}
)

// Server Error 5xx
// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-15.6
var (
	InternalServerError     = Status{500, "Internal Server Error"}
	NotImplemented          = Status{501, "Not Implemented"}
	BadGateway              = Status{502, "Bad Gateway"}
	ServiceUnavailable      = Status{503, "Service Unavailable"}
	GatewayTimeout          = Status{504, "Gateway Timeout"}
	HTTPVersionNotSupported = Status{505, "HTTP Version Not Supported"}
)

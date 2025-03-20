package semantic

type Status struct {
	Code         uint
	ReasonPhrase string
}

// Informational 1XX
// Reference: https://datatracker.ietf.org/doc/html/rfc9110#name-informational-1xx
var (
	StatusContinue           = Status{100, "Continue"}
	StatusSwitchingProtocols = Status{101, "Switching Protocols"}
)

// Successful 2XX
// Reference: https://datatracker.ietf.org/doc/html/rfc9110#name-successful-2xx
var (
	StatusOK                   = Status{200, "OK"}
	StatusCreated              = Status{201, "Created"}
	StatusAccepted             = Status{202, "Accepted"}
	StatusNonAuthoritativeInfo = Status{203, "Non-Authoritative Information"}
	StatusNoContent            = Status{204, "No Content"}
	StatusResetContent         = Status{205, "Reset Content"}
	StatusPartialContent       = Status{206, "Partial Content"}
)

// Redirection 3xx
// Reference: https://datatracker.ietf.org/doc/html/rfc9110#name-redirection-3xx
var (
	StatusMultipleChoices   = Status{300, "Multiple Choices"}
	StatusMovedPermanently  = Status{301, "Moved Permanently"}
	StatusFound             = Status{302, "Found"}
	StatusSeeOther          = Status{303, "See Other"}
	StatusNotModified       = Status{304, "Not Modified"}
	StatusUseProxy          = Status{305, "Use Proxy"}
	_                       = Status{306, ""} // Unused
	StatusTemporaryRedirect = Status{307, "Temporary Redirect"}
	StatusPermanentRedirect = Status{308, "Permanent Redirect"}
)

// Client Error 4xx
// Reference: https://datatracker.ietf.org/doc/html/rfc9110#name-client-error-4xx
var (
	StatusBadRequest           = Status{400, "Bad Request"}
	StatusUnauthorized         = Status{401, "Unauthorized"}
	StatusPaymentRequired      = Status{402, "Payment Required"}
	StatusForbidden            = Status{403, "Forbidden"}
	StatusNotFound             = Status{404, "Not Found"}
	StatusMethodNotAllowed     = Status{405, "Method Not Allowed"}
	StatusNotAcceptable        = Status{406, "Not Acceptable"}
	StatusProxyAuthRequired    = Status{407, "Proxy Authentication Required"}
	StatusRequestTimeout       = Status{408, "Request Timeout"}
	StatusConflict             = Status{409, "Conflict"}
	StatusGone                 = Status{410, "Gone"}
	StatusLengthRequired       = Status{411, "Length Required"}
	StatusPreconditionFailed   = Status{412, "Precondition Failed"}
	StatusContentTooLarge      = Status{413, "Content Too Large"}
	StatusRequestURITooLong    = Status{414, "Request URI TooLong"}
	StatusUnsupportedMediaType = Status{415, "Unsupported Media Type"}
	StatusRangeNotSatisfiable  = Status{416, "Range Not Satisfiable"}
	StatusExpectationFailed    = Status{417, "Expectation Failed"}
	StatusTeapot               = Status{418, "Teapot"} // Unused. But I like the joke.
	StatusMisdirectedRequest   = Status{421, "Misdirected Request"}
	StatusUnprocessableContent = Status{422, "Unprocessable Content"}
	StatusUpgradeRequired      = Status{426, "Upgrade Required"}
)

// Server Error 5xx
// Reference: https://datatracker.ietf.org/doc/html/rfc9110#name-server-error-5xx
var (
	StatusInternalServerError     = Status{500, "Internal Server Error"}
	StatusNotImplemented          = Status{501, "Not Implemented"}
	StatusBadGateway              = Status{502, "Bad Gateway"}
	StatusServiceUnavailable      = Status{503, "Service Unavailable"}
	StatusGatewayTimeout          = Status{504, "Gateway Timeout"}
	StatusHTTPVersionNotSupported = Status{505, "HTTP Version Not Supported"}
)

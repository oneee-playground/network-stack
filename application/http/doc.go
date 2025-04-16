// Package http implements Hypertext Transfer Protocol (HTTP)
//
// Reference:
//
// - https://datatracker.ietf.org/doc/html/rfc9110
//
// - TODO: https://datatracker.ietf.org/doc/html/rfc9111
//
// - https://datatracker.ietf.org/doc/html/rfc9112
//
// - TODO: soon, https://datatracker.ietf.org/doc/html/rfc9113
//
// - TODO: https://datatracker.ietf.org/doc/html/rfc9114
package http

// Unimplemented features excluding above:
// - proxy server.
// - Expect header (100-continue).
// - Most of semantic actions. Including redirects.
// - Cookies: https://datatracker.ietf.org/doc/html/rfc6265
// - Version handling. (Backward compatibility for HTTP/1.0)
// - Negotiating transfer codings: https://datatracker.ietf.org/doc/html/rfc9112#section-4-9
// - Read/Write Timeouts in client.

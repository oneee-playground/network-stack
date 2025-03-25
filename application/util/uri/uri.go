package uri

import (
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// NOTE: Manually created URI should not have escaped characters.
type URI struct {
	Scheme    string
	Authority *Authority
	Path      string
	Query     *string
	Fragment  *string
}

// Reference: https://datatracker.ietf.org/doc/html/rfc3986#section-4.2
func (u *URI) IsRelativeRef() bool {
	return u.Scheme == ""
}

// Reference: https://datatracker.ietf.org/doc/html/rfc3986#section-4.3
func (u *URI) IsAbsoluteURI() bool {
	return u.Scheme != "" && u.Fragment == nil
}

func (u *URI) IsValid() error {
	if u.Scheme != "" {
		if err := assertValidScheme(u.Scheme); err != nil {
			return errors.Wrap(err, "scheme is not valid")
		}
	}

	if u.Authority != nil {
		if valid := isValidUserInfo(u.Authority.UserInfo); !valid {
			return errors.New("userinfo is not valid")
		}
		if err := assertValidHost(u.Authority.Host); err != nil {
			return errors.Wrap(err, "host is not valid")
		}
	}

	hasAuthority := u.Authority != nil
	if err := assertValidPath(u.Path, hasAuthority, u.IsRelativeRef()); err != nil {
		return errors.Wrap(err, "path is not valid")
	}

	if u.Query != nil && !isQueryFragValid(*u.Query) {
		return errors.New("query is not valid")
	}
	if u.Fragment != nil && !isQueryFragValid(*u.Fragment) {
		return errors.New("fragment is not valid")
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc3986#section-5.3
func (u *URI) String() string {
	b := new(strings.Builder)
	if u.Scheme != "" {
		b.WriteString(u.Scheme)
		b.WriteByte(':')
	}

	if u.Authority != nil {
		b.WriteString("//")
		if u.Authority.UserInfo != "" {
			b.WriteString(escape(u.Authority.UserInfo, encodeUserInfo))
			b.WriteByte('@')
		}
		b.WriteString(escape(u.Authority.Host, encodeHost))
		if u.Authority.Port != nil {
			rawPort := strconv.FormatUint(uint64(*u.Authority.Port), 10)
			b.WriteRune(':')
			b.WriteString(rawPort)
		}
	}

	b.WriteString(escape(u.Path, encodePath))

	if u.Query != nil {
		b.WriteByte('?')
		b.WriteString(escape(*u.Query, encodeQuery))
	}

	if u.Fragment != nil {
		b.WriteByte('#')
		b.WriteString(escape(*u.Fragment, encodeFragment))
	}

	return b.String()
}

type Authority struct {
	UserInfo string
	Host     string

	// NOTE: Port can be digits of any length. But practically it is in range of 0 ~ 65535.
	// It should be better to store it as string to follow the RFC rule.
	// But since the pacakge uri is library, I'll use uint16 for usability.
	// Reference: datatracker.ietf.org/doc/html/rfc3986#section-3.2.3
	Port *uint16
}

// Normalize performs syntax-based normalization on given URI.
// Reference: https://datatracker.ietf.org/doc/html/rfc3986#section-6.2.2
func Normalize(uri URI) (URI, error) {
	if err := uri.IsValid(); err != nil {
		return URI{}, errors.Wrap(err, "URI is not valid")
	}

	uri.Scheme = strings.ToLower(uri.Scheme)
	if uri.Authority != nil {
		uri.Authority.Host = strings.ToLower(uri.Authority.Host)
	}

	uri.Path = removeDotSegments(uri.Path)

	var err error
	// Unescape components.
	if uri.Path, err = unescape(uri.Path); err != nil {
		return URI{}, errors.Wrap(err, "unescaping path")
	}
	if uri.Authority != nil {
		a := uri.Authority
		if a.UserInfo, err = unescape(a.UserInfo); err != nil {
			return URI{}, errors.Wrap(err, "unescaping userinfo")
		}
		if a.Host, err = unescape(a.Host); err != nil {
			return URI{}, errors.Wrap(err, "unescaping host")
		}
		uri.Authority = a
	}
	if uri.Query != nil {
		if *uri.Query, err = unescape(*uri.Query); err != nil {
			return URI{}, errors.Wrap(err, "unescaping query")
		}
	}
	if uri.Fragment != nil {
		if *uri.Fragment, err = unescape(*uri.Fragment); err != nil {
			return URI{}, errors.Wrap(err, "unescaping fragment")
		}
	}

	return uri, nil
}

func Parse(rawURL string) (URI, error) {
	if containsCTL(rawURL) {
		return URI{}, errors.New("URI should not contain CTL bytes")
	}

	var uri URI

	// Get scheme
	scheme, rest, err := cutScheme(rawURL)
	if err != nil {
		return URI{}, errors.Wrap(err, "getting scheme")
	}
	// Scheme is recommended to be lowercase.
	uri.Scheme = strings.ToLower(scheme)

	if strings.HasPrefix(rest, "//") {
		var authorityRaw string
		authorityRaw, rest = rest[2:], ""
		if i := strings.Index(authorityRaw, "/"); i >= 0 {
			authorityRaw, rest = authorityRaw[:i], authorityRaw[i:]
		}

		authority, err := parseAuthority(authorityRaw)
		if err != nil {
			return URI{}, errors.Wrap(err, "parsing authority")
		}

		uri.Authority = &authority
	}

	path, query, frag := splitPathQueryFrag(rest)

	hasAuthority := uri.Authority != nil
	if err := assertValidPath(path, hasAuthority, uri.IsRelativeRef()); err != nil {
		return URI{}, errors.Wrap(err, "path is not valid")
	}
	uri.Path, err = unescape(path)
	if err != nil {
		return URI{}, errors.Wrap(err, "unescaping path")
	}

	if len(query) > 0 {
		// Strip '?' from query.
		query = query[1:]
		if !isQueryFragValid(query) {
			return URI{}, errors.New("query is not valid")
		}

		if query, err = unescape(query); err != nil {
			return URI{}, errors.Wrap(err, "unescaping query")
		}
		uri.Query = &query
	}

	if len(frag) > 0 {
		// Strip '#' from fragment.
		frag = frag[1:]
		if !isQueryFragValid(frag) {
			return URI{}, errors.New("frag is not valid")
		}

		if frag, err = unescape(frag); err != nil {
			return URI{}, errors.Wrap(err, "unescaping fragment")
		}
		uri.Fragment = &frag
	}

	return uri, nil
}

// cutScheme cuts scheme from rawURL. If scheme is not valid, it returns an error.
func cutScheme(rawURL string) (scheme, rest string, err error) {
	before, after, found := strings.Cut(rawURL, ":")
	if !found {
		// If seperator is not found, scheme doesn't exist.
		return "", before, nil
	}

	scheme, rest = before, after
	if err := assertValidScheme(scheme); err != nil {
		return "", "", err
	}

	return scheme, rest, nil
}

func parseAuthority(raw string) (authority Authority, err error) {
	var userInfo, host string
	if i := strings.Index(raw, "@"); i >= 0 {
		userInfo, host = raw[:i], raw[i+1:]
	} else {
		host = raw
	}

	if userInfo != "" {
		if !isValidUserInfo(userInfo) {
			return Authority{}, errors.New("user information is not valid")
		}
		authority.UserInfo, err = unescape(userInfo)
		if err != nil {
			return Authority{}, errors.Wrap(err, "unescaping user information")
		}
	}

	host, portPart, err := getHostPort(host)
	if err != nil {
		return Authority{}, errors.Wrap(err, "parsing host")
	}

	port, hasPort, err := parsePort(portPart)
	if err != nil {
		return Authority{}, errors.Wrap(err, "parsing host")
	}

	if hasPort {
		authority.Port = &port
	}

	if authority.Host, err = unescape(host); err != nil {
		return Authority{}, errors.Wrap(err, "unescaping host")
	}
	authority.Host = strings.ToLower(authority.Host)

	return authority, nil
}

func getHostPort(raw string) (host string, portPart string, err error) {
	if strings.HasPrefix(raw, "[") {
		// This is IP Literal.
		idx := strings.LastIndex(raw, "]")
		if idx < 0 {
			return "", "", errors.New("missing ']' in IP Literal")
		}

		host = raw[:idx+1]
		portPart = raw[idx+1:]
	} else {
		// ipv4 or reg-name.
		host = raw
		if idx := strings.LastIndex(raw, ":"); idx >= 0 {
			host = raw[:idx]
			portPart = raw[idx:]
		}
	}

	if err := assertValidHost(host); err != nil {
		return "", "", errors.Wrap(err, "host is not valid")
	}

	return host, portPart, nil
}

// This is not the same rule as RFC. See [Authority].
func parsePort(s string) (port uint16, hasPort bool, err error) {
	if s == "" {
		return 0, false, nil
	}

	if s[0] != ':' {
		return 0, false, errors.New("colon delimiter not found on port")
	}

	s = s[1:]

	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, false, errors.Wrap(err, "failed to parse uint")
	}

	if s[0] == '0' && !(n == 0 && len(s) == 1) {
		return 0, false, errors.New("port has leading zero")
	}

	return uint16(n), true, nil
}

func splitPathQueryFrag(raw string) (path, query, frag string) {
	if idx := strings.LastIndexByte(raw, '#'); idx >= 0 {
		frag = raw[idx:]
		raw = raw[:idx]
	}

	if idx := strings.IndexByte(raw, '?'); idx >= 0 {
		query = raw[idx:]
		raw = raw[:idx]
	}

	path = raw
	return
}

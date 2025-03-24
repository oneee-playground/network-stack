package uri

import (
	"errors"
	"network-stack/lib/ds/stack"
	"strings"
)

type RefResolver struct {
	base URI
}

func NewRefResolver(baseURI URI) (*RefResolver, error) {
	if baseURI.IsRelativeRef() {
		return nil, errors.New("baseURI cannot be relative ref")
	}
	return &RefResolver{base: baseURI}, nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc3986#section-5.2.2
func (rr *RefResolver) Resolve(ref URI) (out URI) {
	out = ref

	defer func() { out.Path = removeDotSegments(out.Path) }()

	if out.Scheme != "" {
		return out
	}
	out.Scheme = rr.base.Scheme

	if out.Authority != nil {
		return out
	}
	out.Authority = rr.base.Authority

	if out.Path != "" {
		if !strings.HasPrefix(out.Path, "/") {
			out.Path = mergePath(rr.base, out)
		}
		return out
	}
	out.Path = rr.base.Path

	if out.Query != nil {
		return out
	}
	out.Query = rr.base.Query

	return out
}

// Reference: https://datatracker.ietf.org/doc/html/rfc3986#section-5.2.3
func mergePath(base, ref URI) string {
	if base.Authority != nil && base.Path == "" {
		return "/" + ref.Path
	}

	if idx := strings.LastIndexByte(base.Path, '/'); idx >= 0 {
		return base.Path[:idx+1] + ref.Path
	}

	return ref.Path
}

// Reference: https://datatracker.ietf.org/doc/html/rfc3986#section-5.2.4
func removeDotSegments(path string) string {
	// The input buffer is initialized with the now-appended path
	// components and the output buffer is initialized to the empty
	// string.
	out := stack.New[string](0)

	// While the input buffer is not empty, loop as follows:
	for len(path) > 0 {
		var found bool
		// If the input buffer begins with a prefix of "../" or "./",
		// then remove that prefix from the input buffer; otherwise,
		if path, found = strings.CutPrefix(path, "../"); found {
			continue
		}
		if path, found = strings.CutPrefix(path, "./"); found {
			continue
		}

		// if the input buffer begins with a prefix of "/./" or "/.",
		// where "." is a complete path segment, then replace that
		// prefix with "/" in the input buffer; otherwise,
		if path, found = strings.CutPrefix(path, "/./"); found {
			path = "/" + path
			continue
		} else if path == "/." {
			path = "/"
			continue
		}

		// if the input buffer begins with a prefix of "/../" or "/..",
		// where ".." is a complete path segment, then replace that
		// prefix with "/" in the input buffer and remove the last
		// segment and its preceding "/" (if any) from the output
		// buffer; otherwise,
		if path, found = strings.CutPrefix(path, "/../"); found {
			out.Pop()
			path = "/" + path
			continue
		} else if path == "/.." {
			out.Pop()
			path = "/"
			continue
		}

		// if the input buffer consists only of "." or "..", then remove
		// that from the input buffer; otherwise,
		if path == ".." || path == "." {
			break
		}

		// move the first path segment in the input buffer to the end of
		// the output buffer, including the initial "/" character (if
		// any) and any subsequent characters up to, but not including,
		// the next "/" character or the end of the input buffer.
		idx := strings.IndexByte(path[1:], '/') + 1
		if idx == 0 {
			idx = len(path)
		}
		out.Push(path[:idx])
		path = path[idx:]
	}

	return strings.Join(out.Data(), "")
}

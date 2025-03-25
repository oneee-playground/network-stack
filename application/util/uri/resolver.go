package uri

import (
	"errors"
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

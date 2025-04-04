package server

import (
	"context"
	"network-stack/application/http"
	"network-stack/application/http/semantic"
	"network-stack/application/http/semantic/status"
	"network-stack/transport"

	"github.com/pkg/errors"
)

type HandleFunc func(c *HandleContext, request *semantic.Request) *semantic.Response

type HandleContext struct {
	ctx context.Context

	remoteAddr transport.Addr
	version    http.Version

	request *semantic.Request

	closeConn  bool
	altHandler AltHandler

	// Should only be used inside this struct.
	_fatalError error
}

func (c *HandleContext) doHandle(handle HandleFunc) (res *semantic.Response, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = errors.Errorf("handler panicked: %s", e)
		}
	}()

	response := handle(c, c.request)
	if c._fatalError != nil {
		return nil, c._fatalError
	}

	if response == nil && !c.closeConn {
		return nil, errors.New("nil response is forbidden")
	}

	return response, nil
}

func (c *HandleContext) RemoteAddr() transport.Addr { return c.remoteAddr }

func (c *HandleContext) Error(err error) *semantic.Response {
	if err == nil {
		c._fatalError = errors.New("using Error() with nil error is forbidden")
		return nil
	}

	c.closeConn = true

	if errors.Is(err, transport.ErrConnClosed) {
		return nil
	}

	if statusErr := new(status.Error); errors.As(err, statusErr) {
		return statusErrToResponse(*statusErr, false)
	}

	if errors.Is(err, transport.ErrDeadLineExceeded) {
		return statusErrToResponse(
			status.NewError(nil, status.RequestTimeout),
			true,
		)
	}

	return statusErrToResponse(
		status.NewError(err, status.InternalServerError),
		false,
	)
}

func (c *HandleContext) Context() context.Context  { return c.ctx }
func (c *HandleContext) HTTPVersion() http.Version { return c.version }

func (c *HandleContext) SwitchProtocol(proto string, customRes *semantic.Response, h AltHandler) *semantic.Response {
	if h == nil {
		c._fatalError = errors.New("alt handler should be non-nil")
		return nil
	}

	c.altHandler = h
	if customRes != nil {
		return customRes
	}

	return &semantic.Response{
		Status: status.SwitchingProtocols,
		Message: semantic.Message{
			Version: c.version,
			Headers: semantic.NewHeaders(map[string][]string{
				"Upgrade": {proto},
			}),
		},
	}
}

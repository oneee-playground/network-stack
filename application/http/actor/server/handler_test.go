package server

import (
	"context"
	"errors"
	"io"
	"network-stack/application/http"
	"network-stack/application/http/semantic"
	"network-stack/application/http/semantic/status"
	"network-stack/transport"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

type HandleContextTestSuite struct {
	suite.Suite

	ctx        context.Context
	remoteAddr transport.Addr
	version    http.Version

	request *semantic.Request

	hctx *HandleContext
}

func TestHandleContextTestSuite(t *testing.T) {
	suite.Run(t, new(HandleContextTestSuite))
}

func (s *HandleContextTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.remoteAddr = nil
	s.version = http.Version{1, 1}
	s.request = &semantic.Request{Message: semantic.Message{
		Body: strings.NewReader("Foo is Bar"),
	}}

	s.hctx = &HandleContext{
		ctx:        s.ctx,
		remoteAddr: s.remoteAddr,
		version:    s.version,
		request:    s.request,
	}
}

func (s *HandleContextTestSuite) TestDoHandle() {
	handle := func(c *HandleContext, request *semantic.Request) *semantic.Response {
		s.Equal(s.request, request)
		s.Equal(s.remoteAddr, c.RemoteAddr())
		s.Equal(s.ctx, c.Context())
		return &semantic.Response{}
	}

	res, err := s.hctx.doHandle(handle)
	s.NoError(err)
	s.Equal(&semantic.Response{}, res)

	b, err := io.ReadAll(s.request.Body)
	s.NoError(err)
	s.Empty(b)
}

func (s *HandleContextTestSuite) TestDoHandleFatalErr() {
	handle := func(c *HandleContext, request *semantic.Request) *semantic.Response {
		return &semantic.Response{}
	}

	e := errors.New("hey")
	s.hctx._fatalError = e

	res, err := s.hctx.doHandle(handle)
	s.ErrorIs(err, e)
	s.Nil(res)
}

func (s *HandleContextTestSuite) TestDoHandleNilResposne() {
	handle := func(c *HandleContext, request *semantic.Request) *semantic.Response {
		return nil
	}

	res, err := s.hctx.doHandle(handle)
	s.Error(err)
	s.Nil(res)
}

func (s *HandleContextTestSuite) TestDoHandlePanic() {
	handle := func(c *HandleContext, request *semantic.Request) *semantic.Response {
		panic("missed me?")
	}

	res, err := s.hctx.doHandle(handle)
	s.Error(err)
	s.Nil(res)
}

func (s *HandleContextTestSuite) TestErrorUnknown() {
	e := errors.New("unknown")
	res := s.hctx.Error(e)
	s.True(s.hctx.closeConn)

	r := res.Body
	res.Body = nil

	l := uint(len(e.Error()))
	s.Equal(&semantic.Response{
		Status: status.InternalServerError,
		Message: semantic.Message{
			ContentLength: &l,
		},
	}, res)

	b, err := io.ReadAll(r)
	s.Require().NoError(err)
	s.Equal(e.Error(), string(b))
}

func (s *HandleContextTestSuite) TestErrorStatusError() {
	e := errors.New("im a teapot")
	res := s.hctx.Error(status.NewError(e, status.ImATeapot))
	s.True(s.hctx.closeConn)

	r := res.Body
	res.Body = nil

	l := uint(len(e.Error()))
	s.Equal(&semantic.Response{
		Status: status.ImATeapot,
		Message: semantic.Message{
			ContentLength: &l,
		},
	}, res)

	b, err := io.ReadAll(r)
	s.Require().NoError(err)
	s.Equal(e.Error(), string(b))
}

func (s *HandleContextTestSuite) TestErrorDeadLineExceeded() {
	res := s.hctx.Error(transport.ErrDeadLineExceeded)
	s.True(s.hctx.closeConn)

	s.Equal(&semantic.Response{
		Status: status.RequestTimeout,
	}, res)
}

func (s *HandleContextTestSuite) TestErrorConnClosed() {
	res := s.hctx.Error(transport.ErrConnClosed)
	s.True(s.hctx.closeConn)
	s.Nil(res)
}

func (s *HandleContextTestSuite) TestErrorNil() {
	res := s.hctx.Error(nil)
	s.Nil(res)
	s.Error(s.hctx._fatalError)
}

func (s *HandleContextTestSuite) TestSwitchProtocol() {
	proto := "htcpcp"
	altHander := func(ctx context.Context, conn transport.Conn) error { return nil }

	res := s.hctx.SwitchProtocol(proto, nil, altHander)
	s.NotNil(s.hctx.altHandler)
	s.Equal(&semantic.Response{
		Status: status.SwitchingProtocols,
		Message: semantic.Message{
			Version: s.version,
			Headers: semantic.NewHeaders(map[string][]string{
				"Upgrade": {proto},
			}),
		},
	}, res)
}

func (s *HandleContextTestSuite) TestSwitchProtocolCustomResponse() {
	proto := "htcpcp"
	altHander := func(ctx context.Context, conn transport.Conn) error { return nil }

	expected := &semantic.Response{
		Status:  status.SwitchingProtocols,
		Message: semantic.Message{Version: http.Version{1, 0}},
	}

	res := s.hctx.SwitchProtocol(proto, expected, altHander)
	s.NotNil(s.hctx.altHandler)
	s.Equal(expected, res)
}

func (s *HandleContextTestSuite) TestSwitchProtocolNilHandler() {
	res := s.hctx.SwitchProtocol("", nil, nil)
	s.Nil(res)
	s.Error(s.hctx._fatalError)
}

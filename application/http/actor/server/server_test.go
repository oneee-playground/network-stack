package server

import (
	"bytes"
	"context"
	"log/slog"
	"network-stack/application/http"
	"network-stack/application/http/semantic"
	"network-stack/application/http/semantic/status"
	"network-stack/application/util/uri"
	iolib "network-stack/lib/io"
	"network-stack/lib/types/pointer"
	"network-stack/transport/pipe"
	"testing"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/suite"
)

type ServerTestSuite struct {
	suite.Suite

	transport *pipe.PipeTransport
	logger    *slog.Logger

	transportAddr pipe.Addr

	server *Server

	clock *clock.Mock
}

func TestServerTestSuite(t *testing.T) {
	suite.Run(t, new(ServerTestSuite))
}

func (s *ServerTestSuite) SetupTest() {
	s.clock = clock.NewMock()

	s.transport = pipe.NewPipeTransport(s.clock)
	s.logger = slog.New(slog.DiscardHandler)

	s.transportAddr = pipe.Addr{Name: "addr"}

	lis, err := s.transport.Listen(s.transportAddr)
	s.Require().NoError(err)

	s.server = New(lis, s.logger, s.clock, nil, Options{})
}

func (s *ServerTestSuite) TestStart() {
	request := semantic.Request{
		Method: semantic.MethodGet,
		Host:   "localhost",
		URI: uri.URI{
			Scheme:    "http",
			Authority: &uri.Authority{Host: "localhost"},
			Path:      "/",
		},
		Message: semantic.Message{
			Version: http.Version{1, 1},
			Body:    bytes.NewBuffer(nil),
		},
	}
	request.EnsureHeadersSet()

	response := semantic.Response{
		Status: status.OK,
		Message: semantic.Message{
			Version:       request.Version,
			ContentLength: pointer.To(uint(0)),
		},
	}
	response.EnsureHeadersSet()

	s.server.handle = func(c *HandleContext, got *semantic.Request) *semantic.Response {
		body := got.Body
		got.Body = nil

		expected := request.Clone()
		expected.Body = nil

		s.Require().Equal(&expected, got)

		got.Body = body
		return &response
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := s.transport.Dial(context.Background(), s.transportAddr)
		s.Require().NoError(err)

		enc := http.NewRequestEncoder(conn, http.EncodeOptions{})
		dec := http.NewResponseDecoder(iolib.NewUntilReader(conn), http.DecodeOptions{})

		s.Require().NoError(enc.Encode(request.RawRequest()))

		var raw http.Response
		s.Require().NoError(dec.Decode(&raw))

		res, err := semantic.ResponseFrom(raw, semantic.ParseResponseOptions{})
		s.Require().NoError(err)

		expected := response.Clone()
		expected.Body = nil
		res.Body = nil

		s.Equal(expected, res)
	}()

	s.server.Start()
	<-done

	s.NoError(s.server.Close())
}

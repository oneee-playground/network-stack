package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"network-stack/application/http"
	"network-stack/application/http/actor/common"
	"network-stack/application/http/semantic"
	"network-stack/application/http/semantic/status"
	"network-stack/application/http/transfer"
	iolib "network-stack/lib/io"
	"network-stack/transport"
	"strings"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/pkg/errors"
)

type conn struct {
	con     transport.Conn
	version http.Version

	r *iolib.UntilReader
	w io.WriteCloser

	handle   HandleFunc
	transfer *transfer.CodingApplier
	clock    clock.Clock

	logger *slog.Logger

	opts Options
}

func (c *conn) isV2() bool {
	return c.version[0] == 2
}

func (c *conn) start(ctx context.Context) {
	defer func() {
		c.logger.Debug("closing connection")
		if err := c.con.Close(); err != nil {
			c.logger.Error("error when closing connection", "error", err)
		}
	}()

	var altHandler common.AltHandler
	var err error
	switch {
	case c.isV2():
		// Serve v2
		// TODO: implement it
		return
	case c.opts.Pipeline.BufferLength > 0:
		// I hate pipelining.
		altHandler, err = c.servePipeine(ctx)
	default:
		altHandler, err = c.serve(ctx)
	}

	if altHandler != nil {
		httpConn := common.NewHTTPWrappedConn(c.con, c.r, c.w)
		err = common.HandleAlt(ctx, httpConn, altHandler)
	}

	switch {
	case errors.Is(err, context.Canceled):
		// no-op.
	case errors.Is(err, ErrIdleTimeoutExceeded):
		c.logger.Info("idle timeout exceeded")
	case errors.Is(err, transport.ErrConnClosed):
		c.logger.Error("unexpected connection closure")
	case err != nil:
		c.logger.Error("unknown error occured", "error", err)
	}
}

func (c *conn) serve(ctx context.Context) (common.AltHandler, error) {
	dec := http.NewRequestDecoder(c.r, c.opts.Serve.Decode)
	enc := http.NewResponseEncoder(c.w, c.opts.Serve.Encode)

	loop := true

	var altHandler common.AltHandler
	for loop {
		if err := c.waitForRequest(ctx); err != nil {
			return nil, errors.Wrap(err, "error while waiting for request")
		}

		var response *semantic.Response

		request, err := c.readRequest(dec)
		if err != nil {
			if errors.Is(err, transport.ErrConnClosed) {
				return nil, err
			}
			// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-2.2-9
			response = statusErrToResponse(toStatusError(err), true)
			loop = false
		} else {
			// Actually handle the request.
			hctx := &HandleContext{
				remoteAddr: c.con.RemoteAddr(),
				ctx:        ctx,
				request:    request,
			}
			response, err = hctx.doHandle(c.handle)
			if err != nil {
				return nil, errors.Wrap(err, "unexpected error while handling request")
			}

			if hctx.closeConn {
				if response == nil {
					break
				}

				loop = false
				response.Headers.Set("Connection", "close")
			}
			if hctx.altHandler != nil {
				loop = false
				altHandler = hctx.altHandler
			}
		}

		// Overwrite response version.
		response.Message.Version = c.version

		if err = c.writeResponse(response, enc); err != nil {
			return nil, errors.Wrap(err, "unexpected error while writing response")
		}
	}

	return altHandler, nil
}

var ErrIdleTimeoutExceeded = errors.New("idle timeout exceeded")

func (c *conn) waitForRequest(ctx context.Context) error {
	timeout := c.opts.Serve.Timeout.IdleTimeout

	if timeout > 0 {
		c.con.SetReadDeadLine(c.clock.Now().Add(timeout))
	}

	signal := make(chan error, 1)
	go func() {
		_, err := c.con.Read(nil)
		if errors.Is(err, transport.ErrDeadLineExceeded) {
			err = ErrIdleTimeoutExceeded
		}

		signal <- err
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-signal:
		return err
	}
}

func (c *conn) readRequest(d *http.RequestDecoder) (*semantic.Request, error) {
	timeout := c.opts.Serve.Timeout.ReadTimeout

	if timeout > 0 {
		c.con.SetReadDeadLine(c.clock.Now().Add(timeout))
	}

	var raw http.Request
	if err := d.Decode(&raw); err != nil {
		return nil, err
	}

	request, err := semantic.RequestFrom(raw, c.opts.Serve.Parse)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a semantic request")
	}

	switch {
	case len(request.TransferEncoding) > 0:
		combineFieldValues := c.opts.Serve.Parse.CombineFieldValues

		if err := request.DecodeTransfer(c.transfer, combineFieldValues); err != nil {
			return nil, err
		}

		if request.IsChunked() {
			// Body is delimited by last chunk.
			// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-6.3-2.4.1
			c.con.SetReadDeadLine(time.Time{})
		} else {
			// The message body length cannot be determined reliably.
			// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-6.3-2.4.3
			return nil, errors.New("transfer encoding without chunked. cannot determine body length")
		}
	case request.ContentLength != nil:
		// Body is delimited by Content-Length.
		// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-6.3-2.6
		request.Body = iolib.LimitReader(request.Body, *request.ContentLength)
	default:
		// Neither transfer-encoding nor content-length exists.
		// So it has no body.
		// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-6.3-2.7
		request.Body = bytes.NewReader(nil)
	}

	return &request, nil
}

func (c *conn) writeResponse(response *semantic.Response, e *http.ResponseEncoder) error {
	timeout := c.opts.Serve.Timeout.WriteTimeout

	if timeout > 0 {
		c.con.SetWriteDeadLine(c.clock.Now().Add(timeout))
	}

	// Reference: https://datatracker.ietf.org/doc/html/rfc9110#section-6.6.1-6
	response.Date = c.clock.Now()

	// Ensures values in fields (e.g. content length, transfer encoding) are set in headers.
	response.EnsureHeadersSet()
	// If response has nil body, replace it into non-nil reader.
	if response.Body == nil {
		response.Body = bytes.NewReader(nil)
	}

	switch {
	case len(response.TransferEncoding) > 0:
		if err := response.EncodeTransfer(c.transfer); err != nil {
			return err
		}
	case response.ContentLength != nil:
		response.Body = iolib.LimitReader(response.Body, *response.ContentLength)
	}

	if err := e.Encode(response.RawResponse()); err != nil {
		return err
	}

	return nil
}

// toStatusError converts error into [StatusError].
// It assumes that error is returned when reading request,
// so if it isn't any specific error, it will return error with [semantic.StatusBadRequest].
// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-2.2-9
func toStatusError(err error) status.Error {
	if errors.Is(err, transport.ErrDeadLineExceeded) {
		return status.NewError(nil, status.RequestTimeout)
	}

	if errors.Is(err, semantic.ErrContentTooBig) {
		// Reference: https://datatracker.ietf.org/doc/html/rfc9110#name-413-content-too-large
		return status.NewError(err, status.ContentTooLarge)
	}

	if errors.Is(err, semantic.ErrURITooLong) {
		// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-3-4
		return status.NewError(err, status.RequestURITooLong)
	}

	if errors.Is(err, transfer.ErrUnsupportedCoding) {
		// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-6.1-11
		return status.NewError(err, status.NotImplemented)
	}

	return status.NewError(err, status.BadRequest)
}

func statusErrToResponse(se status.Error, skipBody bool) (res *semantic.Response) {
	res = &semantic.Response{
		Status: se.Status,
	}

	if skipBody {
		return
	}

	if se.Cause() != nil {
		content := se.Cause().Error()
		l := uint(len(content))

		res.ContentLength = &l
		res.Body = strings.NewReader(content)
	}

	return
}

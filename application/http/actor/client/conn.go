package client

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"network-stack/application/http"
	"network-stack/application/http/semantic"
	"network-stack/application/http/semantic/status"
	"network-stack/application/http/transfer"
	"network-stack/lib/ds/queue"
	iolib "network-stack/lib/io"
	"network-stack/transport"
	"sync"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/pkg/errors"
)

type conn struct {
	con transport.Conn

	addr     transport.Addr
	version  http.Version
	pipeline bool
	maxSeats uint

	r *iolib.UntilReader
	w io.WriteCloser

	transfer *transfer.CodingApplier
	logger   *slog.Logger
	clock    clock.Clock

	seats    uint
	closing  bool
	isAlt    bool // is it controlled by AltHandler?
	idleAt   time.Time
	ongoings *queue.CircularQueue[*roundtripSession]
	mu       sync.Mutex // guards the fields above

	writePipe chan *roundtripSession

	opts Options
}

func (c *conn) occupyLocked() {
	if c.seats == 0 {
		panic("why would you occupy busy conn")
	}
	c.seats--
	c.idleAt = time.Time{} // To mark it as non-idle.
}

func (c *conn) unoccupyLocked() {
	if c.seats == c.maxSeats {
		panic("why would you unoccupy?")
	}
	c.seats++
	if c.seats == c.maxSeats {
		c.idleAt = c.clock.Now()
	}
}

type roundtripSession struct {
	req        *semantic.Request
	responseTo chan *semantic.Response
	errTo      chan error

	callerQuit chan struct{}
}

func (c *conn) roundtrip(ctx context.Context, request *semantic.Request) (*semantic.Response, error) {
	session := &roundtripSession{
		req:        request,
		responseTo: make(chan *semantic.Response),
		errTo:      make(chan error, 2), // for read and write error.
		callerQuit: make(chan struct{}),
	}

	defer close(session.callerQuit)

	// Write request first.
	c.writePipe <- session

	// Wait for response.
	c.mu.Lock()
	c.ongoings.Enqueue(session) // ignore success as it will always succeed.
	c.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-session.errTo:
		return nil, err
	case response := <-session.responseTo:
		return response, nil
	}
}

// TODO: Add retry for awaiting roundtrip sessions when error.
func (c *conn) readLoop() {
	dec := http.NewResponseDecoder(c.r, c.opts.Receive.Decode)

	stop := false
	for !stop {
		c.mu.Lock()
		if c.isAlt {
			// Now requests won't be received.
			stop = true
		}
		c.mu.Unlock()
		if _, err := c.con.Read(nil); err != nil {
			c.close(errors.Wrap(err, "waiting for response from server"))
			return
		}

		c.mu.Lock()
		session, err := c.ongoings.Dequeue()
		c.mu.Unlock()

		if err != nil {
			// No outstanding requests.
			c.close(errors.New("invalid behavior: response on no outstanding request"))
			return
		}

		response, err := c.readResponse(dec)
		if err != nil {
			err = errors.Wrap(err, "reading response")
			session.errTo <- err
			c.close(err)
			return
		}

		signal := make(chan error, 1)
		response.Body = &signalOnError{
			signal: signal,
			r:      response.Body,
		}

		select {
		case <-session.callerQuit:
			// caller gone. read all the body for next response.
			if _, err := io.Copy(io.Discard, response.Body); err != nil {
				c.close(errors.Wrap(err, "reading response body"))
				return
			}
		case session.responseTo <- response:
		}

		if err := <-signal; !errors.Is(err, io.EOF) {
			// Error while reading body.
			c.close(errors.Wrap(err, "reading body"))
			return
		}

		c.mu.Lock()
		if c.isAlt {
			// Now requests won't be received.
			c.mu.Unlock()
			break
		}
		c.mu.Unlock()
	}
}

func (c *conn) writeLoop() {
	enc := http.NewRequestEncoder(c.w, c.opts.Send.Encode)

	for session := range c.writePipe {
		err := c.writeRequest(session.req, enc)
		if err != nil {
			err = errors.Wrap(err, "writing request")
			session.errTo <- err
			c.close(err)
			return
		}
	}
}

func (c *conn) close(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked(err)
}

func (c *conn) closeLocked(err error) {
	if c.closing {
		// already cleaned up.
		return
	}
	c.closing = true

	for c.ongoings.Len() > 0 {
		session, _ := c.ongoings.Dequeue()
		session.errTo <- errors.Wrap(err, "connection closed due to error")
	}

	close(c.writePipe)
}

// Assumes it is locked.
func (c *conn) actuallyClose() {
	if !c.closing {
		panic("conn is not soft-closed")
	}

	if err := c.con.Close(); err != nil {
		panic(err)
	}
}

func (c *conn) writeRequest(request *semantic.Request, e *http.RequestEncoder) error {
	// If request has nil body, replace it into non-nil reader.
	if request.Body == nil {
		request.Body = bytes.NewReader(nil)
	}

	switch {
	case len(request.TransferEncoding) > 0:
		if err := request.EncodeTransfer(c.transfer); err != nil {
			return err
		}
	case request.ContentLength != nil:
		request.Body = iolib.LimitReader(
			request.Body, *request.ContentLength,
		)
	}

	if err := e.Encode(request.RawRequest()); err != nil {
		return err
	}

	return nil
}

func (c *conn) readResponse(d *http.ResponseDecoder) (*semantic.Response, error) {
	var raw http.Response
	if err := d.Decode(&raw); err != nil {
		return nil, err
	}

	response, err := semantic.ResponseFrom(raw, c.opts.Receive.Parse)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a semantic response")
	}

	if !c.opts.Receive.UseReceivedReasonPhrase {
		// Overwrite the reason phrase with default one.
		if status, ok := status.FromCode(response.Status.Code); ok {
			response.Status = status
		}
	}

	switch {
	case len(response.TransferEncoding) > 0:
		combineFieldValues := c.opts.Receive.Parse.CombineFieldValues

		if err := response.DecodeTransfer(c.transfer, combineFieldValues); err != nil {
			return nil, err
		}

		if response.IsChunked() {
			// Body is delimited by last chunk.
			// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-6.3-2.4.1
			c.con.SetReadDeadLine(time.Time{})
		} else {
			// The message is finished when server closes connection.
			// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-6.3-2.4.2
			response.Body = &connClosedReader{r: response.Body}
		}
	case response.ContentLength != nil:
		// Body is delimited by Content-Length.
		// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-6.3-2.6
		response.Body = iolib.LimitReader(response.Body, *response.ContentLength)
	default:
		// Neither transfer-encoding nor content-length exists.
		// The message is finished when server closes connection.
		// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-6.3-2.8
		response.Body = &connClosedReader{r: response.Body}
	}

	return &response, err
}

// Assumes it is locked.
func (c *conn) idleTimeoutExceeded(timeout time.Duration) bool {
	if c.idleAt.IsZero() {
		return false
	}

	return c.clock.Since(c.idleAt) >= timeout
}

// connClosedReader overwrites [transport.ErrConnClosed] as [io.EOF].
type connClosedReader struct{ r io.Reader }

func (r *connClosedReader) Read(p []byte) (n int, err error) {
	n, err = r.r.Read(p)
	if errors.Is(err, transport.ErrConnClosed) {
		return n, io.EOF
	}
	return n, err
}

type signalOnError struct {
	signal chan<- error
	r      io.Reader
}

func (r *signalOnError) Read(p []byte) (n int, err error) {
	n, err = r.r.Read(p)
	if err != nil {
		r.signal <- err
	}
	return n, err
}

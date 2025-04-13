package server

import (
	"bytes"
	"context"
	"network-stack/application/http"
	"network-stack/application/http/actor/common"
	"network-stack/application/http/semantic"
	"network-stack/lib/ds/queue"
	"network-stack/transport"
	"slices"
	"sync"

	"github.com/pkg/errors"
)

func (c *conn) servePipeine(ctx context.Context) (common.AltHandler, error) {
	bufLen := c.opts.Pipeline.BufferLength

	var wg sync.WaitGroup
	defer wg.Wait()

	receiver := newPipelineReceiver(c, bufLen)
	sender := newPipelineSender(c)

	extraWorkers := uint(0)
	if c.opts.Pipeline.ServeParallel {
		extraWorkers = bufLen
	}
	worker := newPipelineWorker(c, extraWorkers)

	receiver.start(ctx, &wg)
	worker.start(ctx, &wg)
	sender.start(&wg)

	defer close(sender.stream)
	defer close(worker.inputs)
	defer close(receiver.signal)

	receiver.signal <- struct{}{} // Initial read.

	var (
		loop     = true
		requests = receiver.stream // to drain it.

		errResponse *semantic.Response
		unsafeInput *pipelineInput

		altHandler common.AltHandler
	)

	for loop {
		select {
		case err := <-sender.errchan:
			return nil, errors.Wrap(err, "unexpected error while writing response")
		case err := <-worker.errchan:
			return nil, errors.Wrap(err, "unexpected error while handling request")
		case err := <-receiver.errchan:
			if errors.Is(err, transport.ErrConnClosed) || errors.Is(err, ErrIdleTimeoutExceeded) {
				return nil, err
			}

			// We should send error response and close connection.
			errResponse = statusErrToResponse(toStatusError(err), true)
			if worker.empty() {
				sender.stream <- errResponse
				return nil, nil
			}
			// Start draining.
			requests = nil
		case <-worker.moreSignal:
			receiver.signal <- struct{}{}
		case request := <-requests:
			safe := slices.Contains(c.opts.Serve.SafeMethods, request.Method)

			input := pipelineInput{
				request: request,
				// Chunked body is not buffered. So it should block further requests.
				block: request.IsChunked() || !safe,
			}

			if !safe && !worker.empty() {
				// unsafe method should be handled alone.
				// So start draining.
				requests = nil
				unsafeInput = &input
				break
			}

			worker.inputs <- input

		case output := <-worker.outputs:
			response := output.response

			if output.closeConn {
				if output.response == nil {
					return nil, nil
				}
				loop = false
				response.Headers.Set("Connection", "close")
			}
			if output.altHandler != nil {
				loop = false
				altHandler = output.altHandler
			}

			sender.stream <- output.response

			if requests == nil && worker.empty() {
				// It was in draining state.
				if errResponse != nil {
					// An error occured when reading request.
					sender.stream <- errResponse
					return nil, nil
				}
				if unsafeInput != nil {
					// Unsafe request was received.
					worker.inputs <- *unsafeInput
					unsafeInput = nil
				}
				requests = receiver.stream
			}
		}
	}

	return altHandler, nil
}

type pipelineReceiver struct {
	conn *conn

	signal  chan struct{}
	stream  chan *semantic.Request
	errchan chan error
}

func newPipelineReceiver(conn *conn, bufLen uint) *pipelineReceiver {
	return &pipelineReceiver{
		conn:    conn,
		signal:  make(chan struct{}),
		stream:  make(chan *semantic.Request, bufLen),
		errchan: make(chan error, 1),
	}

}
func (pr *pipelineReceiver) start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		dec := http.NewRequestDecoder(pr.conn.r, pr.conn.opts.Serve.Decode)

		// Wait for read signal.
		for range pr.signal {
			if err := pr.conn.waitForRequest(ctx); err != nil {
				pr.errchan <- err
				return
			}

			request, err := pr.conn.readRequest(dec)
			if err != nil {
				pr.errchan <- err
				return
			}

			if !request.IsChunked() {
				// We should buffer the whole body to read the next request.
				buf := bytes.NewBuffer(nil)
				if _, err := buf.ReadFrom(request.Body); err != nil {
					pr.errchan <- errors.Wrap(err, "buffering entire body")
					return
				}
				request.Body = buf
			}

			pr.stream <- request
		}
	}()
}

type pipelineSender struct {
	conn *conn

	stream  chan *semantic.Response
	errchan chan error
}

func newPipelineSender(conn *conn) *pipelineSender {
	return &pipelineSender{
		conn:    conn,
		stream:  make(chan *semantic.Response),
		errchan: make(chan error, 1),
	}
}
func (ps *pipelineSender) start(wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		enc := http.NewResponseEncoder(ps.conn.w, ps.conn.opts.Serve.Encode)

		for response := range ps.stream {
			response.Version = ps.conn.version

			if err := ps.conn.writeResponse(response, enc); err != nil {
				ps.errchan <- err

				for range ps.stream {
					// Drain inputs.
				}
				return
			}
		}
	}()
}

type pipelineInput struct {
	request *semantic.Request
	block   bool
}

type pipelineOutput struct {
	response   *semantic.Response
	closeConn  bool
	altHandler common.AltHandler
}

type pipelineWorker struct {
	connRemoteAddr transport.Addr

	moreSignal chan struct{}

	inputs  chan pipelineInput
	outputs chan pipelineOutput
	errchan chan error

	handle HandleFunc
	pool   *queue.CircularQueue[*handleOutput]
	poolMu sync.Mutex
}

type handleOutput struct {
	output  chan pipelineOutput
	errchan chan error
}

func newPipelineWorker(conn *conn, extraWorkers uint) *pipelineWorker {
	return &pipelineWorker{
		connRemoteAddr: conn.con.RemoteAddr(),

		moreSignal: make(chan struct{}),
		inputs:     make(chan pipelineInput),
		outputs:    make(chan pipelineOutput, extraWorkers),
		errchan:    make(chan error, 1),

		handle: conn.handle,
		pool:   queue.NewCircular[*handleOutput](1 + extraWorkers),
	}
}

func (pw *pipelineWorker) start(ctx context.Context, wg *sync.WaitGroup) {
	// Buffer to stash input when workerpool is full.
	inputbuf := make(chan pipelineInput, 1)
	// Assign it to other variable so we can modify it.
	inputs := pw.inputs

	blocked := false

	wg.Add(1)
	go func() {
		defer wg.Done()

		defer func() {
			for range pw.inputs {
				// Drain inputs.
			}

			for pw.pool.Len() > 0 {
				out, _ := pw.pool.Dequeue()
				// Drain handles.
				select {
				case <-out.errchan:
				case <-out.output:
				}
			}
		}()

		for {
			var oldestHandle handleOutput
			if out, err := pw.pool.Peek(); err == nil {
				oldestHandle = *out
			}

			select {
			case <-ctx.Done():
				pw.errchan <- ctx.Err()
				return
			case err := <-oldestHandle.errchan:
				pw.errchan <- errors.Wrap(err, "unexpected error while handling request")
				return
			case output := <-oldestHandle.output:
				pw.nextHandle()
				pw.outputs <- output

				if inputs != nil {
					break
				}

				select {
				case input := <-inputbuf:
					// workerpool was full.
					// Use the input that was stashed.
					inputbuf <- input
					inputs = inputbuf
				default:
					if pw.empty() {
						// inputs channel was blocked by caller's request.
						// Only re-assign it when workers are all finished.
						if blocked {
							blocked = false
							inputs = pw.inputs
							pw.moreSignal <- struct{}{} // It didn't send it when it arrived.
							break
						}

						// input is closed and all the outputs are drained.
						return
					}
				}
			case input, ok := <-inputs:
				if !ok {
					if pw.empty() {
						// nothing is currently processing.
						// return immediately.
						return
					}
					// inputs closed. drain handles.
					inputs = nil
					break
				}

				hctx := &HandleContext{
					remoteAddr: pw.connRemoteAddr,
					ctx:        ctx,
					request:    input.request,
				}

				if hasSpace := pw.feed(hctx); !hasSpace {
					// Stash the input until it has space.
					inputbuf <- input
					inputs = nil
					break
				}

				if inputs == inputbuf {
					inputs = pw.inputs
				}

				if input.block {
					// Block read until this finishes.
					blocked = true
					inputs = nil
				} else {
					// We can read more.
					pw.moreSignal <- struct{}{}
				}
			}
		}
	}()
}

func (p *pipelineWorker) feed(hctx *HandleContext) (hasSpace bool) {
	output := handleOutput{
		output:  make(chan pipelineOutput, 1),
		errchan: make(chan error, 1),
	}

	p.poolMu.Lock()
	defer p.poolMu.Unlock()
	if success := p.pool.Enqueue(&output); !success {
		return false
	}

	go func() {
		res, err := hctx.doHandle(p.handle)
		if err != nil {
			output.errchan <- err
			return
		}

		output.output <- pipelineOutput{
			response:   res,
			closeConn:  hctx.closeConn,
			altHandler: hctx.altHandler,
		}
	}()

	return true
}

func (p *pipelineWorker) nextHandle() {
	p.poolMu.Lock()
	p.pool.Dequeue()
	p.poolMu.Unlock()
}

func (p *pipelineWorker) empty() bool {
	p.poolMu.Lock()
	defer p.poolMu.Unlock()
	return p.pool.Len() == 0
}

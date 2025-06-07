package tls

import (
	"bytes"
	"io"
	"network-stack/session/tls/common"
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/internal/alert"
	"network-stack/session/tls/internal/handshake"
	"network-stack/session/tls/internal/util/hkdf"
	"sync"

	"github.com/pkg/errors"
)

type earlyDataWriter struct {
	conn *Conn

	maxEarlyData uint32

	mu       sync.Mutex
	written  uint32
	closed   bool
	rejected bool

	// send
	writeOK   chan struct{}
	writeDone chan struct{}
	// receive
	canSendEOED chan struct{}

	p protector
}

var _ io.WriteCloser = (*earlyDataWriter)(nil)

// NewEarlyDataWriter creates new early data writer.
// Write will be availabe after first client hello is sent.
// Application must create a seperate goroutine to use this.
// Close must be invoked after successful write at most advertised amount of data.
func NewEarlyDataWriter(maxEarlyData uint32) *earlyDataWriter {
	return &earlyDataWriter{
		maxEarlyData: maxEarlyData,
		writeOK:      make(chan struct{}),
		writeDone:    make(chan struct{}),
		canSendEOED:  make(chan struct{}),
		p:            newProtector(),
	}
}

var ErrNoMoreEarlyData = errors.New("no more early data is permitted")
var ErrEarlyDataRejected = errors.New("early data rejected by server")

func (e *earlyDataWriter) Write(p []byte) (n int, err error) {
	<-e.writeOK

	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.checkWritableLocked(); err != nil {
		return 0, err
	}

	canWrite := e.maxEarlyData - e.written
	data := p[:min(len(p), int(canWrite))]

	// Lock conn.out to prevent interleaving writes.
	e.conn.out.Lock()
	defer e.conn.out.Unlock()

	var toWrite, rest []byte = nil, data
	for len(rest) > 0 {
		toWrite, rest = e.conn.makeChunk(rest)

		record := tlsText{
			contentType:   typeApplicationData,
			recordVersion: common.VersionTLS12,
			length:        uint16(len(toWrite)),
			fragment:      toWrite,
		}

		record, err = e.p.encrypt(record)
		if err != nil {
			return 0, errors.Wrap(err, "encrypting early data")
		}

		if err := e.conn.writeRecordLocked(record, false, false); err != nil {
			return 0, errors.Wrap(err, "writing record")
		}
	}

	if len(data) < len(p) {
		return len(data), ErrNoMoreEarlyData
	}

	return len(data), nil
}

func (e *earlyDataWriter) Close() error {
	<-e.canSendEOED

	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.checkWritableLocked(); err != nil {
		return err
	}

	endOfEarlyData := handshake.ToBytes(&handshake.EndOfEarlyData{})

	record := tlsText{
		contentType:   typeHandshake,
		recordVersion: common.VersionTLS12,
		length:        uint16(len(endOfEarlyData)),
		fragment:      endOfEarlyData,
	}

	record, err := e.p.encrypt(record)
	if err != nil {
		return errors.Wrap(err, "encrypting end of early data")
	}

	e.conn.out.Lock()
	defer e.conn.out.Unlock()

	if err := e.conn.writeRecordLocked(record, false, false); err != nil {
		return errors.Wrap(err, "writing record")
	}

	close(e.writeDone)
	e.closed = true

	return nil
}

func (e *earlyDataWriter) start(conn *Conn, suite ciphersuite.Suite, earlySecret, transcript []byte) error {
	e.conn = conn

	if err := setEarlyTrafficSecret(&e.p, suite, earlySecret, transcript); err != nil {
		return errors.Wrap(err, "setting key for early data")
	}

	close(e.writeOK)
	return nil
}

func (e *earlyDataWriter) checkWritableLocked() error {
	if e.rejected {
		return ErrEarlyDataRejected
	}
	if e.closed {
		return ErrNoMoreEarlyData
	}
	return nil
}

func (e *earlyDataWriter) notifyRejected() { e.mu.Lock(); e.rejected = true; e.mu.Unlock() }
func (e *earlyDataWriter) notifyFinished() { close(e.canSendEOED) }

func (e *earlyDataWriter) wait() <-chan struct{} { return e.writeDone }

type earlyDataHandler struct {
	buf bytes.Buffer

	maxEarlyData uint32

	retried  bool
	rejected bool

	cond     sync.Cond
	read     uint32
	finished bool

	p          protector
	handshakeP *protector
}

// feed provides earlyDataHandler a record that might be an early data.
// Record passed should be of type application data.
func (e *earlyDataHandler) feed(record tlsText) (used bool, err error) {
	e.cond.L.Lock()
	defer e.cond.L.Unlock()

	remain := e.maxEarlyData - e.read

	switch {
	case e.rejected:
		// Client wouldn't know if it was rejected or not.
		// Se we try decrypting it using handshake protector
		// to determine if it is early data or not.
		if e.isHandshakeRecord(record) {
			return false, nil
		}
	case e.retried:
		// Client will send another CH after it sends invalid early data.
		// Since the connection is not encrypted yet, we can distinguish
		// record by its content type.
	default:
		// This should be early data.
		decrpyted, err := e.p.decrypt(record)
		if err != nil {
			if e.isHandshakeRecord(record) {
				return false, nil
			}
			return false, alert.NewError(err, alert.BadRecordMAC)
		}

		record = decrpyted

		switch record.contentType {
		case typeApplicationData:
			defer func() {
				if used {
					e.buf.Write(record.fragment)
					e.cond.Broadcast()
				}
			}()
		case typeHandshake:
			if ok := e._handleHandshake(record.fragment); ok {
				return true, nil
			}
			fallthrough
		default:
			err := errors.New("unexpected non-application data on early data")
			return false, alert.NewError(err, alert.UnexpectedMessage)
		}
	}

	if remain == 0 {
		return false, nil
	}

	// Note that in the case we rejected/ignored early data,
	// we use the length of ciphertext.
	if record.length > uint16(remain) {
		err := errors.New("max early data size exceeded")
		return false, alert.NewError(err, alert.UnexpectedMessage)
	}

	e.read += uint32(record.length)
	return true, nil
}

func (e *earlyDataHandler) _handleHandshake(fragment []byte) (ok bool) {
	var eoed handshake.EndOfEarlyData
	if err := handshake.FromBytes(fragment, &eoed); err != nil {
		return false
	}

	e.finished = true
	e.cond.Broadcast()
	return true
}

func (e *earlyDataHandler) isHandshakeRecord(record tlsText) bool {
	if _, err := e.handshakeP.decrypt(record); err == nil {
		// Return to the previous state.
		e.handshakeP.decrNonce()
		return true
	}
	return false
}

func (e *earlyDataHandler) isFinished() bool {
	e.cond.L.Lock()
	defer e.cond.L.Unlock()
	return e.finished
}

// expectNoMoreEarlyData is used for notifying there won't be no more early data
// when the initial hello was rejected and second hello was received.
func (e *earlyDataHandler) expectNoMoreEarlyData() {
	e.cond.L.Lock()
	e.read = e.maxEarlyData
	e.cond.L.Unlock()
}

func (e *earlyDataHandler) Read(p []byte) (n int, err error) {
	e.cond.L.Lock()
	defer e.cond.L.Unlock()

	for {
		if e.buf.Len() > 0 {
			return e.buf.Read(p)
		}

		if e.finished {
			return 0, io.EOF
		}

		e.cond.Wait()
	}
}

func setEarlyTrafficSecret(p *protector, suite ciphersuite.Suite, earlySecret, transcript []byte) error {
	secret, err := hkdf.DeriveSecret(suite, earlySecret, "c e traffic", transcript)
	if err != nil {
		return errors.Wrap(err, "deriving secret")
	}

	if err := p.setKey(secret, suite); err != nil {
		return errors.Wrap(err, "setting key")
	}

	return nil
}

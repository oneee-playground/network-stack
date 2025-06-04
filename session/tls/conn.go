package tls

import (
	"bytes"
	"crypto/cipher"
	stderrors "errors"
	"hash"
	"io"
	"math"
	"math/big"
	"network-stack/session/tls/common"
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/internal/alert"
	"network-stack/session/tls/internal/handshake"
	"network-stack/session/tls/internal/handshake/extension"
	"network-stack/session/tls/internal/util/hkdf"
	"network-stack/transport"
	"sync"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/pkg/errors"
)

var ErrSessionClosed = errors.Wrap(transport.ErrConnClosed, "tls session is closed")

type Conn struct {
	underlying transport.BufferedConn
	clock      clock.Clock

	session *Session

	onNewSessionTicket func(ticket Ticket) error

	maxChunkSize uint
	isServer     bool
	closeTimeout time.Duration

	mu            sync.Mutex
	handshaking   bool
	alertSent     bool
	alertReceived bool

	in, out protector

	inBuf   []byte       // For read of records.
	dataBuf bytes.Reader // For reading decrypted data.

	lastHandshake []byte

	protocol string
}

var _ transport.BufferedConn = (*Conn)(nil)

func (conn *Conn) ReadBufSize() uint            { return 0 }
func (conn *Conn) WriteBufSize() uint           { return 0 }
func (conn *Conn) LocalAddr() transport.Addr    { return conn.underlying.LocalAddr() }
func (conn *Conn) RemoteAddr() transport.Addr   { return conn.underlying.RemoteAddr() }
func (conn *Conn) SetReadDeadLine(t time.Time)  { conn.underlying.SetReadDeadLine(t) }
func (conn *Conn) SetWriteDeadLine(t time.Time) { conn.underlying.SetWriteDeadLine(t) }

// Empty means no negotiated protocol.
func (conn *Conn) Protocol() string {
	return conn.protocol
}

func (conn *Conn) Session() Session { return *conn.session }

// Close closes the connection itself and its underlying transport layer connection.
func (conn *Conn) Close() error {
	err1 := conn.SoftClose(true)
	err2 := conn.underlying.Close()

	return stderrors.Join(err1, err2)
}

// SoftClose closes the write side of the connection.
// If callers want to read from the session after this, set dontDrain to true.
// Note that it doesn't close its underlying transport layer connection.
// On error, callers must close the transport layer connection since tls layer connection is in invalid state.
// The deadlines of read/write will be reset after this.
func (conn *Conn) SoftClose(dontDrain bool) (err error) {
	if conn.writeClosed() {
		return ErrSessionClosed
	}

	if conn.closeTimeout != 0 {
		deadLine := conn.clock.Now().Add(conn.closeTimeout)

		conn.underlying.SetWriteDeadLine(deadLine)
		conn.underlying.SetReadDeadLine(deadLine)
	}
	defer func() {
		conn.underlying.SetWriteDeadLine(time.Time{})
		conn.underlying.SetReadDeadLine(time.Time{})
	}()

	if err := conn.sendAlert(alert.CloseNotify, nil); err != nil {
		return errors.Wrap(err, "sending close notify")
	}

	if dontDrain {
		return nil
	}

	// Read until remote sends close notify.
	conn.in.Lock()
	defer conn.in.Unlock()

	for {
		if _, err := conn.readRecordLocked(typeApplicationData, true); err != nil {
			if errors.Is(err, ErrSessionClosed) {
				return nil
			}
			return errors.Wrap(err, "draining records")
		}
	}
}

// After an error occurs, (except [transport.ErrDeadLineExceeded])
// the connection is broken. So the caller must only close the underlying connection.
func (conn *Conn) Read(p []byte) (n int, err error) {
	conn.in.Lock()
	defer conn.in.Unlock()

	if conn.dataBuf.Len() > 0 {
		return conn.dataBuf.Read(p)
	}

	if conn.readClosed() {
		return 0, ErrSessionClosed
	}

	record, err := conn.readRecordLocked(typeApplicationData, true)
	if err != nil {
		if alertErr := new(alert.Error); errors.As(err, alertErr) {
			err = conn.sendAlert(alertErr.Description, alertErr.Cause())
		} else {
			if !errors.Is(err, transport.ErrConnClosed) || !errors.Is(err, transport.ErrDeadLineExceeded) {
				err = conn.sendAlert(alert.InternalError, err)
			}
		}
		return 0, errors.Wrap(err, "reading record")
	}

	conn.dataBuf = *bytes.NewReader(record.fragment)

	return conn.dataBuf.Read(p)
}

func (conn *Conn) readRecordLocked(wantType contentType, decrypt bool) (record tlsText, err error) {
	return conn.readRecordMaybeKeyUpdate(wantType, decrypt, true)
}

// readRecordMaybeKeyUpdate assumes conn.in is locked.
func (conn *Conn) readRecordMaybeKeyUpdate(wantType contentType, decrypt, keyUpdate bool) (record tlsText, err error) {
	if conn.readClosed() {
		return tlsText{}, ErrSessionClosed
	}

	record, err = conn.actuallyReadRecord()
	if err != nil {
		return tlsText{}, errors.Wrap(err, "actually reading record")
	}

	if decrypt {
		record, err = conn.in.decrypt(record)
		if err != nil {
			return tlsText{}, alert.NewError(err, alert.BadRecordMAC)
		}
	}

	if record.contentType != wantType {
		handled, err := conn.handleUnexpectedContentType(record, keyUpdate)
		if err != nil {
			return tlsText{}, errors.Wrap(err, "handling unexpected content type")
		}

		if !handled {
			return record, errors.Errorf("unexpected content type: %d", record.contentType)
		}

		return conn.readRecordMaybeKeyUpdate(wantType, decrypt, false)
	}

	return record, nil
}

// handleUnexpectedContentType assumes conn.in is locked.
func (conn *Conn) handleUnexpectedContentType(record tlsText, keyUpdate bool) (handled bool, err error) {
	switch record.contentType {
	case typeAlert:
		valid, err := conn.handleAlert(record.fragment)
		if !valid {
			return false, alert.NewError(err, alert.DecodeError)
		}

		// Alert will always result in error.
		return true, err
	case typeHandshake:
		if conn.handshaking {
			break
		}

		if match, err := conn.handleNewSessionTicket(record.fragment); err != nil {
			return false, errors.Wrap(err, "handling new session ticket")
		} else if match {
			return true, nil
		}

		if keyUpdate {
			if match, err := conn.handleKeyUpdate(record.fragment); err != nil {
				return false, errors.Wrap(err, "handling key update")
			} else if match {
				return true, nil
			}
		}
	}

	return false, nil
}

func (conn *Conn) actuallyReadRecord() (record tlsText, err error) {
	// Underlying connection might result in [transport.ErrDeadLineExceeded].
	// But it might be intended and would not result in fatal.
	// So to resume reading record, we put the data into the buffer first.
	r := io.MultiReader(bytes.NewReader(conn.inBuf), conn.underlying)

	if read, err := record.fillFrom(r); err != nil {
		conn.inBuf = read

		if errors.Is(err, errRecordTooLong) {
			err = alert.NewError(err, alert.RecordOverflow)
		}

		err = errors.Wrap(err, "reading record from underlying connection")
		return tlsText{}, err
	}
	conn.inBuf = nil

	return record, nil
}

func (conn *Conn) handleAlert(fragment []byte) (valid bool, err error) {
	if len(fragment) != 2 {
		return false, errors.New("fragment size should be 2")
	}

	a := alert.FromBytes([2]byte(fragment))

	// We close read side of connection on alert.
	conn.mu.Lock()
	conn.alertReceived = true
	conn.mu.Unlock()

	if a.Description != alert.CloseNotify {
		// We received an error alert.
		return true, errors.Wrapf(ErrSessionClosed, "remote sent an error alert: %s", a.Description)
	}

	return true, ErrSessionClosed
}

func (conn *Conn) handleNewSessionTicket(fragment []byte) (match bool, _ error) {
	if conn.onNewSessionTicket == nil {
		return false, nil
	}

	match, ticket, err := decodeNewSessionTicket(fragment)
	if err != nil {
		return false, errors.Wrap(err, "decoding new session ticket")
	}

	if !match {
		return false, nil
	}

	// Inject session information.
	ticket.Version = conn.session.Version
	ticket.CipherSuite = conn.session.CipherSuite
	ticket.ServerName = conn.session.ServerName

	resumption, err := conn.session.ComputeResumpitonSecret()
	if err != nil {
		return true, errors.Wrap(err, "computing resumption secret")
	}

	psk, err := ComputePSK(conn.session.CipherSuite, resumption, ticket.Nonce)
	if err != nil {
		return true, errors.Wrap(err, "computing psk")
	}

	ticket.Key = psk

	if err := conn.onNewSessionTicket(ticket); err != nil {
		return true, errors.Wrap(err, "handling new session ticket on application")
	}

	return true, nil
}

// decodeNewSessionTicket decodes nst to ticket. some fields are not filled up.
func decodeNewSessionTicket(fragment []byte) (ok bool, ticket Ticket, _ error) {
	var nst handshake.NewSessionTicket
	if err := handshake.FromBytes(fragment, &nst); err != nil {
		if errors.Is(err, handshake.ErrNotExpectedHandshakeType) {
			return false, Ticket{}, nil
		}
		err = errors.Wrap(err, "parsing new session ticket")
		return true, Ticket{}, alert.NewError(err, alert.DecodeError)
	}

	ticket = Ticket{
		Type:     PSKTypeResumption,
		Ticket:   nst.Ticket,
		AgeAdd:   time.Duration(nst.TicketAgeAdd) * time.Second,
		LifeTime: time.Duration(nst.TicketLifetime) * time.Second,
		Nonce:    nst.TicketNonce,
	}

	if edi := nst.ExtEarlyData; edi != nil {
		ticket.EarlyDataLimit = edi.MaxEarlyDataSize
	}

	return true, ticket, nil
}

// We might receive KeyUpdate handshake message.
// In this case, we update remote key first and update write key if needed.
func (conn *Conn) handleKeyUpdate(fragment []byte) (match bool, _ error) {
	match, echo, err := decodeKeyUpdate(fragment)
	if err != nil {
		return false, errors.Wrap(err, "decoding key update")
	}

	if !match {
		return false, nil
	}

	if err := conn.in.updateKey(); err != nil {
		return true, errors.Wrap(err, "updating read key")
	}

	if echo {
		if err := conn.updateWriteKey(false, false); err != nil {
			return true, errors.Wrap(err, "updating write key")
		}
	}

	return true, nil
}

func decodeKeyUpdate(fragment []byte) (ok, echo bool, err error) {
	var ku handshake.KeyUpdate
	if err := handshake.FromBytes(fragment, &ku); err != nil {
		if errors.Is(err, handshake.ErrNotExpectedHandshakeType) {
			return false, false, nil
		}
		err = errors.Wrap(err, "parsing key update")
		return true, false, alert.NewError(err, alert.DecodeError)
	}

	switch ku.RequestUpdate {
	case handshake.UpdateNotRequested, handshake.UpdateRequested:
	default:
		return true, false, alert.NewError(errors.New("not an allowed value"), alert.IllegalParameter)
	}

	echo = ku.RequestUpdate == handshake.UpdateNotRequested

	return true, echo, nil
}

// updateWriteKey updates write key and sends keyUpdate message.
// callers need to specify if conn.out is locked or not.
func (conn *Conn) updateWriteKey(wantEcho, locked bool) error {
	if !locked {
		conn.out.Lock()
		defer conn.out.Unlock()
	}

	if err := conn.writeKeyUpdateLocked(wantEcho); err != nil {
		return errors.Wrap(err, "sending key update")
	}

	if err := conn.out.updateKey(); err != nil {
		return errors.Wrap(err, "updating write key")
	}

	return nil
}

func (conn *Conn) writeKeyUpdateLocked(wantEcho bool) error {
	ku := handshake.KeyUpdate{}
	if wantEcho {
		ku.RequestUpdate = handshake.UpdateNotRequested
	} else {
		ku.RequestUpdate = handshake.UpdateRequested
	}

	fragment := handshake.ToBytes(&ku)

	record := tlsText{
		contentType:   typeHandshake,
		recordVersion: common.VersionTLS12,
		length:        uint16(len(fragment)),
		fragment:      fragment,
	}

	if err := conn.writeRecordLocked(record, true, true); err != nil {
		return errors.Wrap(err, "writing key update")
	}

	return nil
}

// After an error occurs, the connection is broken.
// So the caller must only close the underlying connection.
func (conn *Conn) Write(p []byte) (n int, err error) {
	if conn.writeClosed() {
		return 0, ErrSessionClosed
	}

	conn.out.Lock()
	defer conn.out.Unlock()

	data, _ := conn.makeChunk(p)

	record := tlsText{
		contentType:   typeApplicationData,
		recordVersion: common.VersionTLS12,
		length:        uint16(len(data)),
		fragment:      data,
	}

	if err := conn.writeRecordLocked(record, true, false); err != nil {
		if !errors.Is(err, transport.ErrConnClosed) || !errors.Is(err, transport.ErrDeadLineExceeded) {
			err = conn.sendAlertLocked(alert.InternalError, err)
		}
		return 0, errors.Wrap(err, "writing record")
	}

	return len(data), nil
}

func (conn *Conn) makeChunk(data []byte) (chunk, rest []byte) {
	size := min(len(data), int(conn.maxChunkSize))
	return data[:size], data[size:]
}

func (conn *Conn) writeRecordLocked(record tlsText, encrypt, isKeyUpdate bool) (err error) {
	var needKeyUpdate bool
	if encrypt {
		record, err = conn.out.encrypt(record)
		if err != nil {
			if !errors.Is(err, errNeedKeyUpdate) {
				return errors.Wrap(err, "encrypting record")
			}

			needKeyUpdate = true
		}
	}

	if _, err := record.WriteTo(conn.underlying); err != nil {
		return errors.Wrap(err, "writing record to underlying connection")
	}

	if needKeyUpdate && !isKeyUpdate {
		if err := conn.updateWriteKey(true, true); err != nil {
			return errors.Wrap(err, "updating write key")
		}
	}

	return nil
}

// if transcript is provided, readHandshake will write raw bytes it read into the transcirpt.
func (conn *Conn) readHandshake(v handshake.Handshake, transcript hash.Hash) (raw []byte, err error) {
	conn.in.Lock()
	defer conn.in.Unlock()

	raw = conn.lastHandshake
	for {
		if err = handshake.FromBytes(raw, v); err == nil {
			conn.lastHandshake = nil
			if transcript != nil {
				transcript.Write(raw)
			}
			return raw, nil
		}

		if errors.Is(err, common.ErrNeedMoreBytes) {
			// Read more bytes and try again.
			record, err := conn.readRecordLocked(typeHandshake, conn.in.canProtect())
			if err != nil {
				return nil, errors.Wrap(err, "reading handshake record")
			}

			raw = append(raw, record.fragment...)
			continue
		}

		if errors.Is(err, handshake.ErrNotExpectedHandshakeType) {
			// Mismatching type, it might be used by following callers.
			conn.lastHandshake = raw
			return nil, alert.NewError(err, alert.UnexpectedMessage)
		}

		return nil, alert.NewError(err, alert.DecodeError)
	}
}

func (conn *Conn) writeHandshake(v handshake.Handshake, transcript hash.Hash) error {
	conn.out.Lock()
	defer conn.out.Unlock()

	b := handshake.ToBytes(v)

	if transcript != nil {
		transcript.Write(b)
	}

	var data, rest []byte = nil, b
	for len(rest) > 0 {
		data, rest = conn.makeChunk(rest)

		record := tlsText{
			contentType:   typeHandshake,
			recordVersion: common.VersionTLS12,
			length:        uint16(len(data)),
			fragment:      data,
		}

		if err := conn.writeRecordLocked(record, conn.out.canProtect(), false); err != nil {
			return errors.Wrap(err, "writing record")
		}
	}

	return nil
}

// sendAlert locks write mutex. if already locked, use sendAlertLocked.
func (conn *Conn) sendAlert(desc alert.Description, err error) error {
	conn.out.Lock()
	defer conn.out.Unlock()
	return conn.sendAlertLocked(desc, err)

}

// sendAlertLocked assumes conn.mu and conn.out is locked.
func (conn *Conn) sendAlertLocked(desc alert.Description, err error) error {
	level := alert.LevelWarning
	if err != nil {
		level = alert.LevelFatal
	}

	alertRecord := tlsText{
		contentType:   typeAlert,
		recordVersion: common.VersionTLS12,
		length:        2,
		fragment:      alert.Alert{Level: level, Description: desc}.Bytes(),
	}

	if err := conn.writeRecordLocked(alertRecord, conn.out.canProtect(), false); err != nil {
		return errors.Wrap(err, "writing alert")
	}

	conn.mu.Lock()
	conn.alertSent = true
	conn.mu.Unlock()

	if err != nil {
		return errors.Wrapf(err, "tls aborted with alert: %s", desc.String())
	}

	return nil
}

func (conn *Conn) setTrafficKeys(
	oursLabel, theirsLabel string, suite ciphersuite.Suite, secret, transcript []byte,
) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	ours, err := hkdf.DeriveSecret(suite, secret, oursLabel, transcript)
	if err != nil {
		return errors.Wrap(err, "deriving ours")
	}

	theirs, err := hkdf.DeriveSecret(suite, secret, theirsLabel, transcript)
	if err != nil {
		return errors.Wrap(err, "deriving theirs")
	}

	conn.out.Lock()
	defer conn.out.Unlock()
	if err := conn.out.setKey(ours, suite); err != nil {
		return errors.Wrap(err, "setting write_key")
	}

	conn.in.Lock()
	defer conn.in.Unlock()
	if err := conn.in.setKey(theirs, suite); err != nil {
		return errors.Wrap(err, "setting read_key")
	}

	return nil
}

// SendTicket sends resumption ticket. Only server-side connection can call this.
// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.1
func (conn *Conn) SendTicket(ticket Ticket) error {
	if !conn.isServer {
		return errors.New("only server can send ticket")
	}

	nst := handshake.NewSessionTicket{
		TicketLifetime: uint32(ticket.LifeTime.Seconds()),
		TicketAgeAdd:   uint32(ticket.AgeAdd.Seconds()),
		TicketNonce:    ticket.Nonce,
		Ticket:         ticket.Ticket,
	}

	if ticket.EarlyDataLimit > 0 {
		nst.ExtEarlyData = &extension.EarlyDataNST{
			MaxEarlyDataSize: ticket.EarlyDataLimit,
		}
	}

	if err := conn.writeHandshake(&nst, nil); err != nil {
		return errors.Wrap(err, "writing new session ticket")
	}

	return nil
}

func (conn *Conn) writeClosed() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.alertSent
}

func (conn *Conn) readClosed() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.alertReceived
}

type protector struct {
	sync.Mutex

	suite  ciphersuite.Suite
	cipher cipher.AEAD
	secret []byte

	nonce   *big.Int
	writeIV *big.Int
}

func newProtector() protector {
	return protector{cipher: nil, nonce: big.NewInt(0)}
}

func (p *protector) canProtect() bool {
	return p.cipher != nil
}

var errNeedKeyUpdate = errors.New("key update is needed")

func (p *protector) encrypt(record tlsText) (tlsText, error) {
	nonce := p.getNonce()

	innerRecord := tlsInnerPlainText{
		content:     record.fragment,
		contentType: record.contentType,
		zeros:       nil, // We don't do padding for now.
	}
	plaintext := innerRecord.bytes()

	encrypted := record
	encrypted.contentType = typeApplicationData
	// We must provide ciphertext's length to the additional data.
	encrypted.length = uint16(len(plaintext) + p.cipher.Overhead())

	encrypted.fragment = p.cipher.Seal(nil, nonce, plaintext, encrypted.metadata())

	p.incrNonce()

	if p.nonce.Uint64() == math.MaxUint64 {
		// Next record must be key update.
		return encrypted, errNeedKeyUpdate
	}

	return encrypted, nil
}
func (p *protector) decrypt(record tlsText) (tlsText, error) {
	// Nonce wrapped. TLS state is broken.
	if !p.nonce.IsUint64() {
		return tlsText{}, errNeedKeyUpdate
	}

	nonce := p.getNonce()

	opened, err := p.cipher.Open(nil, nonce, record.fragment, record.metadata())
	if err != nil {
		return tlsText{}, errors.Wrap(err, "opening record")
	}

	var innerRecord tlsInnerPlainText
	if err := innerRecord.fillFrom(opened); err != nil {
		return tlsText{}, errors.Wrap(err, "creating inner plain text")
	}

	decrypted := tlsText{
		contentType:   innerRecord.contentType,
		recordVersion: record.recordVersion,
		length:        uint16(len(innerRecord.content)),
		fragment:      innerRecord.content,
	}

	p.incrNonce()

	return decrypted, nil
}

func (p *protector) getNonce() []byte {
	nonceBuf := make([]byte, p.cipher.NonceSize())

	nonce := big.NewInt(0).Xor(p.nonce, p.writeIV)

	return nonce.FillBytes(nonceBuf)
}

func (p *protector) incrNonce() { p.nonce.Add(p.nonce, big.NewInt(1)) }

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-7.3
func (p *protector) setKey(secret []byte, suite ciphersuite.Suite) error {
	p.nonce.SetUint64(0)

	p.suite = suite
	p.secret = secret

	key, err := hkdf.ExpandLabel(suite, secret, "key", "", suite.AEAD().KeyLen())
	if err != nil {
		return errors.Wrap(err, "generating key")
	}

	p.cipher, err = suite.AEAD().New(key)
	if err != nil {
		return errors.Wrap(err, "setting cipher")
	}

	writeIV, err := hkdf.ExpandLabel(suite, secret, "iv", "", p.cipher.NonceSize())
	if err != nil {
		return errors.Wrap(err, "generating iv")
	}

	p.writeIV = big.NewInt(0).SetBytes(writeIV)

	return nil
}

// updateKey updaates its key using existing secret.
// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-7.2
func (p *protector) updateKey() error {
	new, err := hkdf.ExpandLabel(p.suite, p.secret, "traffic upd", "", p.suite.Hash().Size())
	if err != nil {
		return errors.Wrap(err, "expanding new secret")
	}

	return p.setKey(new, p.suite)
}

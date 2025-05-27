package tls

import (
	"errors"
	"math"
	"math/big"
	"network-stack/session/tls/common"
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/internal/alert"
	"network-stack/session/tls/internal/handshake"
	"network-stack/transport"
	"network-stack/transport/pipe"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type ConnTestSuite struct {
	suite.Suite

	clock       clock.Clock
	ciphersuite ciphersuite.Suite

	exampleRawRecord tlsText

	c1, c2 *Conn
}

func TestConnTestSuite(t *testing.T) {
	suite.Run(t, new(ConnTestSuite))
}

func (s *ConnTestSuite) SetupTest() {
	s.clock = clock.NewMock()

	s.ciphersuite, _ = ciphersuite.Get(ciphersuite.TLS_AES_128_GCM_SHA256)

	c1, c2 := pipe.BufferedPipe("a", "b", s.clock, 1<<13)
	timeout := time.Second

	s.c1 = &Conn{
		underlying:   c1,
		clock:        s.clock,
		closeTimeout: timeout,
		isServer:     false,
		handshaking:  false,
		maxChunkSize: maxRecordLen,
		in:           newProtector(),
		out:          newProtector(),
	}
	s.c2 = &Conn{
		underlying:   c2,
		clock:        s.clock,
		closeTimeout: timeout,
		isServer:     true,
		handshaking:  false,
		maxChunkSize: maxRecordLen,
		in:           newProtector(),
		out:          newProtector(),
	}

	s.exampleRawRecord = tlsText{
		contentType:   typeApplicationData,
		recordVersion: common.VersionTLS12,
		length:        1,
		fragment:      []byte("A"),
	}
}

func (s *ConnTestSuite) setTrafficKeys() {
	shared, transcript := []byte("this is shared secret"), []byte("transcript")
	labelServer, labelClient := "server", "client"

	s.Require().NoError(s.c1.setTrafficKeys(labelClient, labelServer, s.ciphersuite, shared, transcript))
	s.Require().NoError(s.c2.setTrafficKeys(labelServer, labelClient, s.ciphersuite, shared, transcript))
}

func (s *ConnTestSuite) TestSetTrafficKeys() {
	s.setTrafficKeys()

	s.Equal(s.c1.out.secret, s.c2.in.secret)
	s.Equal(s.c1.out.writeIV, s.c2.in.writeIV)
	s.Equal(s.c1.out.suite.ID(), s.c2.in.suite.ID())

	s.Equal(s.c1.in.secret, s.c2.out.secret)
	s.Equal(s.c1.in.writeIV, s.c2.out.writeIV)
	s.Equal(s.c1.in.suite.ID(), s.c2.out.suite.ID())
}

func (s *ConnTestSuite) TestMakeChunk() {
	data := make([]byte, s.c1.maxChunkSize+1)

	chunk, rest := s.c1.makeChunk(data)
	s.Equal(int(s.c1.maxChunkSize), len(chunk))
	s.Equal(1, len(rest))

	chunk, rest = s.c1.makeChunk(rest)
	s.Equal(1, len(chunk))
	s.Equal(0, len(rest))
}

func (s *ConnTestSuite) TestWriteRecord() {
	s.Require().NoError(s.c1.writeRecordLocked(s.exampleRawRecord, false, false))

	got := tlsText{}
	_, err := got.fillFrom(s.c2.underlying)
	s.Require().NoError(err)

	s.Equal(s.exampleRawRecord, got)
}

func (s *ConnTestSuite) TestWriteRecordEncrypted() {
	s.setTrafficKeys()

	s.Require().NoError(s.c1.writeRecordLocked(s.exampleRawRecord, true, false))

	got := tlsText{}
	_, err := got.fillFrom(s.c2.underlying)
	s.Require().NoError(err)

	decrypted, err := s.c2.in.decrypt(got)
	s.Require().NoError(err)

	s.Equal(s.exampleRawRecord, decrypted)
}

func (s *ConnTestSuite) TestWriteKeyUpdate() {
	s.setTrafficKeys()

	s.Require().NoError(s.c1.writeKeyUpdateLocked(true))

	got := tlsText{}
	_, err := got.fillFrom(s.c2.underlying)
	s.Require().NoError(err)

	decrypted, err := s.c2.in.decrypt(got)
	s.Require().NoError(err)

	echo, err := decodeKeyUpdate(decrypted.fragment)
	s.NoError(err)
	s.True(echo)
}

func (s *ConnTestSuite) TestHandleKeyUpdate() {
	s.setTrafficKeys()

	// Indicates echo == true
	ku := handshake.KeyUpdate{RequestUpdate: handshake.UpdateNotRequested}

	s.Require().NoError(s.c1.handleKeyUpdate(handshake.ToBytes(&ku)))

	// This should be key update.
	got := tlsText{}
	_, err := got.fillFrom(s.c2.underlying)
	s.Require().NoError(err)

	decrypted, err := s.c2.in.decrypt(got)
	s.Require().NoError(err)

	echo, err := decodeKeyUpdate(decrypted.fragment)
	s.NoError(err)
	s.False(echo)

	// Check keys are updated.
	s.Require().NoError(s.c2.in.updateKey())
	s.Equal(s.c2.in.secret, s.c1.out.secret)
}

func (s *ConnTestSuite) TestWriteRecordAndKeyUpdate() {
	// Write record -> needs key update -> Write key update handshake.
	s.setTrafficKeys()
	s.c1.out.nonce = big.NewInt(0).SetUint64(math.MaxUint64 - 1)
	s.c2.in.nonce = big.NewInt(0).SetUint64(math.MaxUint64 - 1)

	s.Require().NoError(s.c1.writeRecordLocked(s.exampleRawRecord, true, false))

	got := tlsText{}
	// This one should be the record that was sent.
	_, err := got.fillFrom(s.c2.underlying)
	s.Require().NoError(err)
	decrypted, err := s.c2.in.decrypt(got)
	s.Require().NoError(err)
	s.Require().Equal(s.exampleRawRecord, decrypted)

	// This should be key update.
	_, err = got.fillFrom(s.c2.underlying)
	s.Require().NoError(err)

	decrypted, err = s.c2.in.decrypt(got)
	s.Require().NoError(err)

	echo, err := decodeKeyUpdate(decrypted.fragment)
	s.NoError(err)
	s.True(echo)

	// Check keys are updated.
	s.Require().NoError(s.c2.in.updateKey())
	s.Equal(s.c2.in.secret, s.c1.out.secret)
}

func (s *ConnTestSuite) TestSendAlert() {
	s.NoError(s.c1.sendAlert(alert.CloseNotify, nil))
	s.True(s.c1.alertSent)

	got := tlsText{}
	_, err := got.fillFrom(s.c2.underlying)
	s.Require().NoError(err)

	a, ok := maybeAlert(got)
	s.Require().True(ok)
	s.Equal(alert.Alert{Level: alert.LevelWarning, Description: alert.CloseNotify}, a)
}

func (s *ConnTestSuite) TestSendAlertError() {
	s.ErrorContains(s.c1.sendAlert(alert.DecodeError, errors.New("hey")), "tls aborted with alert")
	s.True(s.c1.alertSent)

	got := tlsText{}
	_, err := got.fillFrom(s.c2.underlying)
	s.Require().NoError(err)

	a, ok := maybeAlert(got)
	s.Require().True(ok)
	s.Equal(alert.Alert{Level: alert.LevelFatal, Description: alert.DecodeError}, a)
}

func (s *ConnTestSuite) TestActuallyReadRecord() {
	s.Require().NoError(s.c2.writeRecordLocked(s.exampleRawRecord, false, false))

	got, err := s.c1.actuallyReadRecord()
	s.Require().NoError(err)
	s.Equal(s.exampleRawRecord, got)
}

func (s *ConnTestSuite) TestActuallyReadRecordDeadLine() {
	s.Require().NoError(s.c2.writeRecordLocked(s.exampleRawRecord, false, false))

	s.c1.SetReadDeadLine(s.clock.Now())
	_, err := s.c1.actuallyReadRecord()
	s.Require().ErrorIs(err, transport.ErrDeadLineExceeded)

	s.c1.SetReadDeadLine(time.Time{})
	got, err := s.c1.actuallyReadRecord()
	s.Require().NoError(err)

	s.Equal(s.exampleRawRecord, got)
}

func (s *ConnTestSuite) TestReadRecordMaybeKeyUpdateAlert() {
	s.setTrafficKeys()

	s.Require().Error(s.c2.sendAlert(alert.DecodeError, errors.New("example")))

	_, err := s.c1.readRecordMaybeKeyUpdate(s.exampleRawRecord.contentType, true, false)
	s.Require().True(s.c1.alertReceived)
	s.ErrorIs(err, ErrSessionClosed)
}

func (s *ConnTestSuite) TestReadRecordMaybeKeyUpdate() {
	s.setTrafficKeys()

	s.Require().NoError(s.c2.writeRecordLocked(s.exampleRawRecord, true, false))

	record, err := s.c1.readRecordMaybeKeyUpdate(s.exampleRawRecord.contentType, true, false)
	s.Require().NoError(err)

	s.Equal(s.exampleRawRecord, record)
}

func (s *ConnTestSuite) TestReadRecordMaybeKeyUpdateSessionClosed() {
	s.c1.alertReceived = true

	_, err := s.c1.readRecordMaybeKeyUpdate(s.exampleRawRecord.contentType, true, false)
	s.ErrorIs(err, ErrSessionClosed)
}

func (s *ConnTestSuite) TestReadWrite() {
	s.setTrafficKeys()

	buf := make([]byte, 100)

	n, err := s.c1.Write(buf)
	s.Require().NoError(err)
	s.Require().Equal(len(buf), n)

	buf = make([]byte, 50)

	n, err = s.c2.Read(buf)
	s.Require().NoError(err)
	s.Equal(len(buf), n)
	n, err = s.c2.Read(buf)
	s.Require().NoError(err)
	s.Equal(len(buf), n)
}

func (s *ConnTestSuite) TestReadHandshake() {
	hs := handshake.EncryptedExtensions{}
	rawHS := handshake.ToBytes(&hs)

	record := tlsText{
		contentType:   typeHandshake,
		recordVersion: common.VersionTLS12,
		length:        uint16(len(rawHS)),
		fragment:      rawHS,
	}

	s.Require().NoError(s.c2.writeRecordLocked(record, false, false))

	var got handshake.EncryptedExtensions
	raw, err := s.c1.readHandshake(&got, nil)
	s.Require().NoError(err)

	s.Equal(rawHS, raw)
	s.Equal(hs, got)
}

func (s *ConnTestSuite) TestReadHandshakeFragmented() {
	hs := handshake.EncryptedExtensions{}
	rawHS := handshake.ToBytes(&hs)

	record1 := tlsText{
		contentType:   typeHandshake,
		recordVersion: common.VersionTLS12,
		length:        1,
		fragment:      rawHS[:1],
	}
	record2 := tlsText{
		contentType:   typeHandshake,
		recordVersion: common.VersionTLS12,
		length:        uint16(len(rawHS) - 1),
		fragment:      rawHS[1:],
	}

	s.Require().NoError(s.c2.writeRecordLocked(record1, false, false))
	s.Require().NoError(s.c2.writeRecordLocked(record2, false, false))

	var got handshake.EncryptedExtensions
	raw, err := s.c1.readHandshake(&got, nil)
	s.Require().NoError(err)

	s.Equal(rawHS, raw)
	s.Equal(hs, got)
}

func (s *ConnTestSuite) TestReadWriteHandshake() {
	s.Require().NoError(s.c1.writeHandshake(&handshake.EndOfEarlyData{}, nil))

	raw, err := s.c2.readHandshake(&handshake.EndOfEarlyData{}, nil)
	s.NoError(err)
	s.Equal(handshake.ToBytes(&handshake.EndOfEarlyData{}), raw)
}

func (s *ConnTestSuite) TestSoftClose() {
	s.setTrafficKeys()

	sentBefore := []byte("hello")

	n, err := s.c2.Write(sentBefore)
	s.Require().NoError(err)
	s.Require().Equal(len(sentBefore), n)

	s.Require().NoError(s.c1.SoftClose(true))

	buf := make([]byte, len(sentBefore))

	// Read on remote will result in [ErrSessionClosed].
	n, err = s.c2.Read(buf)
	s.Require().ErrorIs(err, ErrSessionClosed)
	s.Require().Zero(n)

	// Read on local is available.
	n, err = s.c1.Read(buf)
	s.Require().NoError(err)
	s.Require().Equal(len(sentBefore), n)
	s.Require().Equal(sentBefore, buf)

	// Since write is closed, calling softClose will result in error.
	s.ErrorIs(s.c1.SoftClose(true), ErrSessionClosed)
}

func (s *ConnTestSuite) TestSoftCloseDrain() {
	s.setTrafficKeys()

	sentBefore := []byte("hello")

	go func() {
		n, err := s.c2.Write(sentBefore)
		s.Require().NoError(err)
		s.Require().Equal(len(sentBefore), n)

		s.Require().NoError(s.c2.sendAlert(alert.CloseNotify, nil))
	}()

	s.Require().NoError(s.c1.SoftClose(false))

	buf := make([]byte, len(sentBefore))

	// Read on local will result in [ErrSessionClosed] since it is drained.
	n, err := s.c1.Read(buf)
	s.Require().ErrorIs(err, ErrSessionClosed)
	s.Require().Zero(n)
}

type ProtectorTestSuite struct {
	suite.Suite

	suite  ciphersuite.Suite
	secret []byte

	p protector
}

func TestProtectorTestSuite(t *testing.T) {
	suite.Run(t, new(ProtectorTestSuite))
}

func (s *ProtectorTestSuite) SetupTest() {
	s.p = newProtector()
	s.secret = []byte("secret")
	s.suite, _ = ciphersuite.Get(ciphersuite.TLS_AES_128_GCM_SHA256)

	s.Require().NoError(s.p.setKey(s.secret, s.suite))
}

func (s *ProtectorTestSuite) TestEncryptDecrypt() {
	record := tlsText{
		contentType:   typeAlert,
		recordVersion: common.VersionTLS12,
		length:        0,
		fragment:      nil,
	}

	encrypted, err := s.p.encrypt(record)
	s.Require().NoError(err)

	// Reset nonce so we can decrypt in same state.
	s.p.nonce = big.NewInt(0)

	decrypted, err := s.p.decrypt(encrypted)
	s.Require().NoError(err)

	s.Equal(record, decrypted)
}

func (s *ProtectorTestSuite) TestEncryptNeedKeyUpdate() {
	// If nonce after encryption is at limit, it returns err.
	s.p.nonce = big.NewInt(0).SetUint64(math.MaxUint64 - 1)

	record, err := s.p.encrypt(tlsText{fragment: []byte("hey")})
	s.ErrorIs(err, errNeedKeyUpdate)
	s.NotNil(record.fragment)
}

func (s *ProtectorTestSuite) TestDecryptNeedKeyUpdate() {
	// If nonce is over limit, it returns err.
	// This case we must assume tls session is broken.
	s.p.nonce = big.NewInt(0).SetUint64(math.MaxUint64)
	s.p.nonce.Add(s.p.nonce, big.NewInt(1))

	record, err := s.p.decrypt(tlsText{fragment: []byte("hey")})
	s.ErrorIs(err, errNeedKeyUpdate)
	s.Nil(record.fragment)
}

func (s *ProtectorTestSuite) TestGetNonce() {
	b := s.p.getNonce()

	nonceXor := big.NewInt(0).SetBytes(b)

	s.Equal(s.p.writeIV, nonceXor.Xor(nonceXor, s.p.nonce))
}

func (s *ProtectorTestSuite) TestSetKey() {
	s.p = newProtector()

	s.Require().NoError(s.p.setKey(s.secret, s.suite))

	s.Equal(s.suite.ID(), s.p.suite.ID())
	s.Equal(s.secret, s.p.secret)
	s.Equal(0, big.NewInt(0).Cmp(s.p.nonce))
	s.NotNil(s.p.writeIV)
	s.NotNil(s.p.cipher)
}

func (s *ProtectorTestSuite) TestUpdateKey() {
	s.p = newProtector()

	s.Require().NoError(s.p.setKey(s.secret, s.suite))
	s.p.nonce = big.NewInt(1000)

	s.Require().NoError(s.p.updateKey())

	s.NotEqual(s.secret, s.p.secret)
	s.Equal(0, big.NewInt(0).Cmp(s.p.nonce))
	s.NotNil(s.p.cipher)
}

func TestDecodeKeyUpdate(t *testing.T) {
	ku := handshake.KeyUpdate{RequestUpdate: handshake.UpdateNotRequested}
	echo, err := decodeKeyUpdate(handshake.ToBytes(&ku))
	assert.NoError(t, err)
	assert.True(t, echo)

	ku = handshake.KeyUpdate{RequestUpdate: handshake.UpdateRequested}
	echo, err = decodeKeyUpdate(handshake.ToBytes(&ku))
	assert.NoError(t, err)
	assert.False(t, echo)
}

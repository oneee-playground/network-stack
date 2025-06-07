package tls

import (
	"network-stack/session/tls/common"
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/internal/handshake"
	"network-stack/transport/pipe"
	"sync"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/suite"
)

type EarlyDataWriterTestSuite struct {
	suite.Suite

	clock       clock.Clock
	ciphersuite ciphersuite.Suite

	maxEarlyDataSize uint32
	edw              *earlyDataWriter

	c1, c2 *Conn
}

func TestEarlyDataWriterTestSuite(t *testing.T) {
	suite.Run(t, new(EarlyDataWriterTestSuite))
}

func (s *EarlyDataWriterTestSuite) SetupTest() {
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
		session:      &Session{},
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
		session:      &Session{},
	}

	s.maxEarlyDataSize = 100
	s.edw = NewEarlyDataWriter(s.maxEarlyDataSize)
}

func (s *EarlyDataWriterTestSuite) TestWrite() {
	var secret, transcript []byte
	go func() {
		s.Require().NoError(s.edw.start(s.c1, s.ciphersuite, secret, transcript))
	}()

	data := []byte("hello")

	n, err := s.edw.Write(data)
	s.Require().NoError(err)
	s.Require().Equal(5, n)

	s.Require().NoError(setEarlyTrafficSecret(&s.c2.in, s.ciphersuite, secret, transcript))
	record, err := s.c2.readRecordLocked(typeApplicationData, true)
	s.Require().NoError(err)

	s.Equal(data, record.fragment)
}

func (s *EarlyDataWriterTestSuite) TestWriteExceeded() {
	var secret, transcript []byte
	go func() {
		s.Require().NoError(s.edw.start(s.c1, s.ciphersuite, secret, transcript))
	}()

	data := make([]byte, s.maxEarlyDataSize+1)

	n, err := s.edw.Write(data)
	s.Require().ErrorIs(err, ErrNoMoreEarlyData)
	s.Require().Equal(int(s.maxEarlyDataSize), n)

	s.Require().NoError(setEarlyTrafficSecret(&s.c2.in, s.ciphersuite, secret, transcript))
	record, err := s.c2.readRecordLocked(typeApplicationData, true)
	s.Require().NoError(err)

	s.Equal(data[:s.maxEarlyDataSize], record.fragment)
}

func (s *EarlyDataWriterTestSuite) TestWriteNotWritable() {
	var secret, transcript []byte
	go func() {
		s.Require().NoError(s.edw.start(s.c1, s.ciphersuite, secret, transcript))
	}()

	data := []byte("hello")

	s.edw.rejected = true
	n, err := s.edw.Write(data)
	s.Require().ErrorIs(err, ErrEarlyDataRejected)
	s.Require().Equal(0, n)
	s.edw.rejected = false

	s.edw.closed = true
	n, err = s.edw.Write(data)
	s.Require().ErrorIs(err, ErrNoMoreEarlyData)
	s.Require().Equal(0, n)
	s.edw.closed = false
}

func (s *EarlyDataWriterTestSuite) TestClose() {
	var wg sync.WaitGroup
	defer wg.Wait()

	var secret, transcript []byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.Require().NoError(s.edw.start(s.c1, s.ciphersuite, secret, transcript))
		s.edw.notifyFinished()

		<-s.edw.wait()
	}()

	s.Require().NoError(s.edw.Close())
	n, err := s.edw.Write([]byte("abc"))
	s.Require().ErrorIs(err, ErrNoMoreEarlyData)
	s.Require().Equal(0, n)

	s.Require().NoError(setEarlyTrafficSecret(&s.c2.in, s.ciphersuite, secret, transcript))
	record, err := s.c2.readRecordLocked(typeHandshake, true)
	s.Require().NoError(err)
	var eoed handshake.EndOfEarlyData
	s.Require().NoError(handshake.FromBytes(record.fragment, &eoed))
}

type EarlyDataHandlerTestSuite struct {
	suite.Suite

	clock       clock.Clock
	ciphersuite ciphersuite.Suite

	maxEarlyDataSize uint32
	edh              *earlyDataHandler

	c1, c2 *Conn
}

func TestEarlyDataHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(EarlyDataHandlerTestSuite))
}

func (s *EarlyDataHandlerTestSuite) SetupTest() {
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
		session:      &Session{},
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
		session:      &Session{},
	}

	s.maxEarlyDataSize = 100

	s.edh = &earlyDataHandler{
		maxEarlyData: s.maxEarlyDataSize,
		handshakeP:   &s.c1.in,
		p:            newProtector(),
	}
	s.edh.cond.L = &sync.Mutex{}
	s.c1.earlyDataHandler = s.edh
}

func (s *EarlyDataHandlerTestSuite) TestFeed() {
	var secret, transcript []byte

	s.Require().NoError(setEarlyTrafficSecret(&s.edh.p, s.ciphersuite, secret, transcript))

	record := tlsText{
		contentType:   typeApplicationData,
		recordVersion: common.VersionTLS12,
		length:        1,
		fragment:      []byte{'A'},
	}

	ciphertext, err := s.edh.p.encrypt(record)
	s.Require().NoError(err)
	s.edh.p.decrNonce()

	used, err := s.edh.feed(ciphertext)
	s.Require().NoError(err)
	s.True(used)

	buf := make([]byte, 1)
	n, err := s.edh.Read(buf)
	s.Require().NoError(err)
	s.Equal(1, n)
	s.Equal(record.fragment, buf)
}

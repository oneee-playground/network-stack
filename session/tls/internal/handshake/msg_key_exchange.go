package handshake

import (
	"bytes"
	"network-stack/lib/types"
	"network-stack/session/tls/common"
	"network-stack/session/tls/common/ciphersuite"
	"network-stack/session/tls/internal/handshake/extension"
	"network-stack/session/tls/internal/util"

	"github.com/pkg/errors"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
type ClientHello struct {
	Version            common.Version // Legacy. Always TLS 1.2
	Random             [32]byte
	SessionID          []byte // Legacy. Random 32byte value on compatibility modem else zero-length vector.
	CipherSuites       []ciphersuite.ID
	CompressionMethods []byte // Legacy. It should be set to one zero-value byte. Meaning "null" compression method.

	// Extensions for CH.
	ExtSupportedVersions  *extension.SupportedVersionsCH
	ExtSupportedGroups    *extension.SupportedGroups
	ExtSignatureAlgos     *extension.SignatureAlgos
	ExtSignatureAlgosCert *extension.SignatureAlgosCert
	ExtEarlyData          *extension.EarlyDataCH
	ExtCertAuthorities    *extension.CertAuthorities
	ExtServerNameList     *extension.ServerNameList
	ExtKeyShares          *extension.KeyShareCH
	ExtPreSharedKey       *extension.PreSharedKeyCH
	ExtCookie             *extension.Cookie
}

var _ Handshake = (*ClientHello)(nil)

func (c *ClientHello) messageType() handshakeType { return typeClientHello }

func (c *ClientHello) data() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(c.Version.Bytes())

	buf.Write(c.Random[:])

	buf.Write(util.ToVectorOpaque(1, c.SessionID))
	buf.Write(util.ToVector(2, c.CipherSuites))
	buf.Write(util.ToVectorOpaque(1, c.CompressionMethods))

	raws := extension.ToRaw(
		c.ExtSupportedVersions,
		c.ExtSupportedGroups,
		c.ExtSignatureAlgos,
		c.ExtSignatureAlgosCert,
		c.ExtEarlyData,
		c.ExtCertAuthorities,
		c.ExtServerNameList,
		c.ExtKeyShares,
		c.ExtPreSharedKey,
		c.ExtCookie,
	)
	extension.WriteRaws(raws, buf)

	return buf.Bytes()
}

func (c *ClientHello) length() types.Uint24 {
	dLen := uint32(0)

	dLen += uint32(len(c.Version.Bytes()))
	dLen += uint32(len(c.Random))
	dLen += 1 + uint32(len(c.SessionID))
	dLen += 2 + uint32(2*len(c.CipherSuites)) // size of suite * num of suites.
	dLen += 1 + uint32(len(c.CompressionMethods))
	dLen += 2 + uint32(extension.ByteLen(
		c.ExtSupportedVersions,
		c.ExtSupportedGroups,
		c.ExtSignatureAlgos,
		c.ExtSignatureAlgosCert,
		c.ExtEarlyData,
		c.ExtCertAuthorities,
		c.ExtServerNameList,
		c.ExtKeyShares,
		c.ExtPreSharedKey,
		c.ExtCookie,
	))

	return types.NewUint24(dLen)
}

func (c *ClientHello) fillFrom(b []byte) (err error) {
	if len(b) < 34 {
		return common.ErrNeedMoreBytes
	}

	var v util.VectorConv
	v, b, _ = c.Version.FromBytes(b)
	c.Version = v.(common.Version)

	copy(c.Random[:], b[:32])
	b = b[32:]

	c.SessionID, b, err = util.FromVectorOpaque(1, b, true)
	if err != nil {
		return errors.Wrap(err, "reading sessionID")
	}

	c.CipherSuites, b, err = util.FromVector[ciphersuite.ID](2, b, true)
	if err != nil {
		return errors.Wrap(err, "reading cipherSuites")
	}

	c.CompressionMethods, b, err = util.FromVectorOpaque(1, b, true)
	if err != nil {
		return errors.Wrap(err, "reading compressionMethods")
	}

	raws, err := extension.Parse(b, false)
	if err != nil {
		return errors.Wrap(err, "reading extensions")
	}

	if c.ExtSupportedVersions, err = extension.Extract(raws, c.ExtSupportedVersions); err != nil {
		return errors.Wrap(err, "supported versions")
	}
	if c.ExtSupportedGroups, err = extension.Extract(raws, c.ExtSupportedGroups); err != nil {
		return errors.Wrap(err, "supported groups")
	}
	if c.ExtSignatureAlgos, err = extension.Extract(raws, c.ExtSignatureAlgos); err != nil {
		return errors.Wrap(err, "signature algos")
	}
	if c.ExtSignatureAlgosCert, err = extension.Extract(raws, c.ExtSignatureAlgosCert); err != nil {
		return errors.Wrap(err, "signature algos cert")
	}
	if c.ExtEarlyData, err = extension.Extract(raws, c.ExtEarlyData); err != nil {
		return errors.Wrap(err, "early data")
	}
	if c.ExtCertAuthorities, err = extension.Extract(raws, c.ExtCertAuthorities); err != nil {
		return errors.Wrap(err, "cert authorities")
	}
	if c.ExtServerNameList, err = extension.Extract(raws, c.ExtServerNameList); err != nil {
		return errors.Wrap(err, "sni")
	}
	if c.ExtKeyShares, err = extension.Extract(raws, c.ExtKeyShares); err != nil {
		return errors.Wrap(err, "key shares")
	}
	if c.ExtPreSharedKey, err = extension.Extract(raws, c.ExtPreSharedKey); err != nil {
		return errors.Wrap(err, "pre-shared key")
	}
	if c.ExtCookie, err = extension.Extract(raws, c.ExtCookie); err != nil {
		return errors.Wrap(err, "cookie")
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
type ServerHello struct {
	Version           common.Version // Legacy. Always TLS 1.2
	Random            [32]byte
	SessionIDEcho     []byte // Legacy. Random 32byte value on compatibility modem else zero-length vector.
	CipherSuite       ciphersuite.ID
	CompressionMethod uint8 // Legacy. It should be set to one zero-value byte. Meaning "null" compression method.

	// Extensions for common SH.
	ExtSupportedVersions *extension.SupportedVersionsSH

	// Extensions for SH.
	ExtKeyShareSH   *extension.KeyShareSH
	ExtPreSharedKey *extension.PreSharedKeySH

	// Extensions for HRR.
	ExtKeyShareHRR *extension.KeyShareHRR
	ExtCookie      *extension.Cookie
}

var DowngradeTLS12 = [8]byte{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 01}
var DowngradeTLS11 = [8]byte{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 00}

var _ Handshake = (*ServerHello)(nil)

func (s *ServerHello) messageType() handshakeType { return typeServerHello }

func (s *ServerHello) data() []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write(s.Version.Bytes())

	buf.Write(s.Random[:])

	buf.Write(util.ToVectorOpaque(1, s.SessionIDEcho))

	buf.Write(s.CipherSuite[:])

	buf.WriteByte(s.CompressionMethod)

	raws := extension.ToRaw(
		s.ExtSupportedVersions,
		s.ExtKeyShareSH,
		s.ExtPreSharedKey,
		s.ExtKeyShareHRR,
		s.ExtCookie,
	)
	extension.WriteRaws(raws, buf)

	return buf.Bytes()
}

func (s *ServerHello) length() types.Uint24 {
	dLen := uint32(0)

	dLen += uint32(len(s.Version.Bytes()))
	dLen += uint32(len(s.Random))
	dLen += 1 + uint32(len(s.SessionIDEcho))
	dLen += uint32(len(s.CipherSuite))
	dLen += 1 // Compression method.
	dLen += 2 + uint32(extension.ByteLen(
		s.ExtSupportedVersions,
		s.ExtKeyShareSH,
		s.ExtPreSharedKey,
		s.ExtKeyShareHRR,
		s.ExtCookie,
	))

	return types.NewUint24(dLen)
}

func (s *ServerHello) fillFrom(b []byte) (err error) {
	if len(b) < 38 {
		return common.ErrNeedMoreBytes
	}

	var v util.VectorConv
	v, b, err = s.Version.FromBytes(b)
	if err != nil {
		return errors.Wrap(err, "reading version")
	}
	s.Version = v.(common.Version)

	copy(s.Random[:], b[:32])
	b = b[32:]

	s.SessionIDEcho, b, err = util.FromVectorOpaque(1, b, true)
	if err != nil {
		return errors.Wrap(err, "reading sessionIDEcho")
	}

	if len(b) < 2 {
		return common.ErrNeedMoreBytes
	}
	s.CipherSuite = ciphersuite.ID([2]uint8(b[0:2]))
	b = b[2:]

	if len(b) < 1 {
		return common.ErrNeedMoreBytes
	}
	s.CompressionMethod = b[0]
	b = b[1:]

	raws, err := extension.Parse(b, false)
	if err != nil {
		return errors.Wrap(err, "reading extensions")
	}

	if s.ExtSupportedVersions, err = extension.Extract(raws, s.ExtSupportedVersions); err != nil {
		return errors.Wrap(err, "supported versions")
	}

	if !s.IsHelloRetry() {
		if s.ExtKeyShareSH, err = extension.Extract(raws, s.ExtKeyShareSH); err != nil {
			return errors.Wrap(err, "key share")
		}
		if s.ExtPreSharedKey, err = extension.Extract(raws, s.ExtPreSharedKey); err != nil {
			return errors.Wrap(err, "pre-shared key")
		}
	} else {
		if s.ExtKeyShareHRR, err = extension.Extract(raws, s.ExtKeyShareHRR); err != nil {
			return errors.Wrap(err, "key share")
		}
		if s.ExtCookie, err = extension.Extract(raws, s.ExtCookie); err != nil {
			return errors.Wrap(err, "cookie")
		}
	}

	return nil
}

// Reference: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.4
var helloRetryRandom = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

func (s *ServerHello) IsHelloRetry() bool { return s.Random == helloRetryRandom }
func (s *ServerHello) ToHelloRetry()      { s.Random = helloRetryRandom }

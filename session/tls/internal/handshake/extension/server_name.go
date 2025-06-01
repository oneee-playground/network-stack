package extension

import (
	"bytes"
	"network-stack/session/tls/common"
	"network-stack/session/tls/internal/util"

	"github.com/pkg/errors"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc6066#section-3
type ServerNameType uint8

const (
	ServerNameTypeHostName ServerNameType = 0
)

type ServerName struct {
	NameType ServerNameType
	Name     []byte
}

var _ util.VectorConv = ServerName{}

func (s ServerName) Bytes() []byte {
	buf := bytes.NewBuffer(nil)
	buf.WriteByte(byte(s.NameType))
	buf.Write(util.ToVectorOpaque(2, s.Name))
	return buf.Bytes()
}

func (s ServerName) FromBytes(b []byte) (out util.VectorConv, rest []byte, err error) {
	if len(b) < 1 {
		return nil, nil, common.ErrNeedMoreBytes
	}

	s.NameType = ServerNameType(b[0])

	name, _, err := util.FromVectorOpaque(2, b[1:], false)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading name")
	}
	s.Name = name

	return s, nil, nil
}

type ServerNameList struct {
	ServerNameList []ServerName
}

var _ Extension = (*ServerNameList)(nil)

func (s *ServerNameList) ExtensionType() ExtensionType { return TypeServerName }
func (s *ServerNameList) exists() bool                 { return s != nil }

func (s *ServerNameList) Length() uint16 {
	l := uint16(2)
	for _, name := range s.ServerNameList {
		l += uint16(1) // type
		l += 2 + uint16(len(name.Name))
	}
	return l
}

func (s *ServerNameList) Data() []byte {
	return util.ToVector(2, s.ServerNameList)
}

func (*ServerNameList) newFrom(raw Raw) (Extension, error) {
	var s ServerNameList
	names, _, err := util.FromVector[ServerName](2, raw.data, false)
	if err != nil {
		return nil, errors.Wrap(err, "reading names")
	}

	s.ServerNameList = names
	return &s, nil
}

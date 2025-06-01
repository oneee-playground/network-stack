package extension

import (
	"network-stack/session/tls/internal/util"

	"github.com/pkg/errors"
)

// Reference: https://datatracker.ietf.org/doc/html/rfc7301#section-3
type ALPNProtocolName []byte

var _ util.VectorConv = ServerName{}

func (a ALPNProtocolName) Bytes() []byte {
	b := util.ToBigEndianBytes(uint(len(a)), 1)
	return append(b, a...)
}

func (a ALPNProtocolName) FromBytes(b []byte) (out util.VectorConv, rest []byte, err error) {
	opaque, rest, err := util.FromVectorOpaque(1, b, true)
	if err != nil {
		return nil, nil, err
	}

	return ALPNProtocolName(opaque), rest, nil
}

type ALPNProtocols struct {
	ProtocolNameList []ALPNProtocolName
}

var _ Extension = (*ALPNProtocols)(nil)

func (a *ALPNProtocols) ExtensionType() ExtensionType { return TypeALPN }
func (a *ALPNProtocols) exists() bool                 { return a != nil }

func (a *ALPNProtocols) Length() uint16 {
	l := uint16(2)
	for _, name := range a.ProtocolNameList {
		l += 1 + uint16(len(name))
	}
	return l
}

func (a *ALPNProtocols) Data() []byte {
	return util.ToVector(2, a.ProtocolNameList)
}

func (*ALPNProtocols) newFrom(raw Raw) (Extension, error) {
	var a ALPNProtocols
	names, _, err := util.FromVector[ALPNProtocolName](2, raw.data, false)
	if err != nil {
		return nil, errors.Wrap(err, "reading names")
	}

	a.ProtocolNameList = names
	return &a, nil
}

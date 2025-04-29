package alert

import (
	"fmt"
)

type Level uint8

const (
	LevelWarning = 1
	LevelFatal   = 2
)

type Description uint8

const (
	CloseNotify                  Description = 0
	UnexpectedMessage            Description = 10
	BadRecordMAC                 Description = 20
	RecordOverflow               Description = 22
	HandshakeFailure             Description = 40
	BadCertificate               Description = 42
	UnsupportedCertificate       Description = 43
	CertificateRevoked           Description = 44
	CertificateExpired           Description = 45
	CertificateUnknown           Description = 46
	IllegalParameter             Description = 47
	UnknownCA                    Description = 48
	AccessDenied                 Description = 49
	DecodeError                  Description = 50
	DecryptError                 Description = 51
	ProtocolVersion              Description = 70
	InsufficientSecurity         Description = 71
	InternalError                Description = 80
	InappropriateFallback        Description = 86
	UserCanceled                 Description = 90
	MissingExtension             Description = 109
	UnsupportedExtension         Description = 110
	UnrecognizedName             Description = 112
	BadCertificateStatusResponse Description = 113
	UnknownPSKIdentity           Description = 115
	CertificateRequired          Description = 116
	NoApplicationProtocol        Description = 120
)

type Alert struct {
	Level       Level // This can be ignored.
	Description Description
}

func (a Alert) Bytes() []byte {
	return []byte{byte(a.Level), byte(a.Description)}
}

func AlertFromBytes(b [2]byte) Alert {
	return Alert{
		Level:       Level(b[0]),
		Description: Description(b[1]),
	}
}

type Error struct {
	Description Description
	cause       error
}

func NewError(desc Description, cause error) Error {
	return Error{
		Description: desc,
		cause:       cause,
	}
}

func (e Error) Error() string {
	return fmt.Sprintf("alert(%d), %s", e.Description, e.cause.Error())
}

func (e Error) Cause() error {
	return e.cause
}

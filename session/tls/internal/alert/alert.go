package alert

import (
	"errors"
	"fmt"
)

type Level uint8

const (
	LevelWarning Level = 1
	LevelFatal   Level = 2
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

func FromBytes(b [2]byte) Alert {
	return Alert{
		Level:       Level(b[0]),
		Description: Description(b[1]),
	}
}

func (d Description) String() string {
	switch d {
	case CloseNotify:
		return "close_notify"
	case UnexpectedMessage:
		return "unexpected_message"
	case BadRecordMAC:
		return "bad_record_mac"
	case RecordOverflow:
		return "record_overflow"
	case HandshakeFailure:
		return "handshake_failure"
	case BadCertificate:
		return "bad_certificate"
	case UnsupportedCertificate:
		return "unsupported_certificate"
	case CertificateRevoked:
		return "certificate_revoked"
	case CertificateExpired:
		return "certificate_expired"
	case CertificateUnknown:
		return "certificate_unknown"
	case IllegalParameter:
		return "illegal_parameter"
	case UnknownCA:
		return "unknown_ca"
	case AccessDenied:
		return "access_denied"
	case DecodeError:
		return "decode_error"
	case DecryptError:
		return "decrypt_error"
	case ProtocolVersion:
		return "protocol_version"
	case InsufficientSecurity:
		return "insufficient_security"
	case InternalError:
		return "internal_error"
	case InappropriateFallback:
		return "inappropriate_fallback"
	case UserCanceled:
		return "user_canceled"
	case MissingExtension:
		return "missing_extension"
	case UnsupportedExtension:
		return "unsupported_extension"
	case UnrecognizedName:
		return "unrecognized_name"
	case BadCertificateStatusResponse:
		return "bad_certificate_status_response"
	case UnknownPSKIdentity:
		return "unknown_psk_identity"
	case CertificateRequired:
		return "certificate_required"
	case NoApplicationProtocol:
		return "no_application_protocol"
	}

	return fmt.Sprintf("unknown: %d", d)
}

type Error struct {
	Description Description
	cause       error
}

func NewError(cause error, desc Description) Error {
	return Error{
		Description: desc,
		cause:       cause,
	}
}

func (e Error) Error() string {
	msg := ""
	if e.cause != nil {
		msg = e.cause.Error()
	}

	return fmt.Sprintf("alert(%s), %s", e.Description.String(), msg)
}

func (e Error) Cause() error {
	return e.cause
}

func (e Error) Is(err error) bool {
	return errors.Is(e.cause, err)
}

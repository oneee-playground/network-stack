package common

import "errors"

var ErrNeedMoreBytes = errors.New("need more bytes to decode handshake")

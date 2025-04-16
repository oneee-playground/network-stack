package client

import (
	"network-stack/application/http"
	"network-stack/application/http/semantic"
	"network-stack/application/http/transfer"
	"time"
)

type Options struct {
	Send     SendOptions
	Receive  ReceiveOptions
	Conn     ConnOptions
	Pipeline PipelineOptions
	Timeout  TimeoutOptions

	ExtraTransferCoders []transfer.Coder
}

type SendOptions struct {
	Encode http.EncodeOptions
}

type ReceiveOptions struct {
	Decode http.DecodeOptions

	Parse semantic.ParseResponseOptions

	// UseReceivedReasonPhrase uses reason phrase from response.
	// If false, the reason phrase will instead be filled with default value for the status code.
	// Reference: https://datatracker.ietf.org/doc/html/rfc9112#section-4-9
	UseReceivedReasonPhrase bool
}

type PipelineOptions struct {
	UsePipelining        bool
	MaxConcurrentRequest uint
}

type ConnOptions struct {
	MaxOpenConnsPerHost uint
}

type TimeoutOptions struct {
	IdleTimeout time.Duration
}

package server

import (
	"network-stack/application/http"
	"network-stack/application/http/semantic"
	"network-stack/application/http/transfer"
	"time"
)

type Options struct {
	Serve    ServeOptions
	Pipeline PipelineOptions

	ExtraTransferCoders []transfer.Coder
}

type ServeOptions struct {
	Encode http.EncodeOptions
	Decode http.DecodeOptions

	Parse semantic.ParseRequestOptions

	Timeout TimeoutOptions

	SafeMethods   []semantic.Method
	MaxContentLen uint
}

type PipelineOptions struct {
	BufferLength  uint
	ServeParallel bool
}

type TimeoutOptions struct {
	IdleTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

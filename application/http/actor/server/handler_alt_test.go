package server

import (
	"context"
	"network-stack/transport"
	"network-stack/transport/pipe"
	"testing"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/assert"
)

func TestServeAltHandlerPanic(t *testing.T) {
	testAltHandler := func(ctx context.Context, conn transport.Conn) error {
		panic("haha I always panic")
	}

	conn, _ := pipe.NewPair("a", "b", clock.New())

	c := httpWrappedConn{
		conn: conn,
		r:    conn,
		w:    conn,
	}

	assert.Error(t, serveAltHandler(context.Background(), &c, testAltHandler))
}

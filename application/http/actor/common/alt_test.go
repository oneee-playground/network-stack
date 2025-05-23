package common

import (
	"context"
	"network-stack/transport"
	"network-stack/transport/pipe"
	"testing"

	"github.com/benbjohnson/clock"
	"github.com/stretchr/testify/assert"
)

func TestHandleAltPanic(t *testing.T) {
	testAltHandler := func(ctx context.Context, conn transport.Conn) error {
		panic("haha I always panic")
	}

	conn, _ := pipe.Pipe("a", "b", clock.New())

	c := NewHTTPWrappedConn(conn, conn, conn)

	assert.Error(t, HandleAlt(context.Background(), c, testAltHandler))
}

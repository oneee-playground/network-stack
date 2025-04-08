package semantic

import (
	"io"
	"network-stack/application/http"
	"network-stack/application/http/transfer"
	iolib "network-stack/lib/io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateMessage(t *testing.T) {
	ver := http.Version{1, 1}
	noBody := strings.NewReader("")

	t.Run("example (transfer encoding)", func(t *testing.T) {
		h := []http.Field{
			{Name: []byte("Transfer-Encoding"), Value: []byte("chunked")},
		}
		msg, err := createMessage(ver, h, noBody, ParseMessageOptions{})
		require.NoError(t, err)

		assert.Equal(t, HeadersFrom(h, false), msg.Headers)
		assert.Nil(t, msg.ContentLength)
		assert.Equal(t, noBody, msg.Body)
		assert.Equal(t, []transfer.Coding{"chunked"}, msg.TransferEncoding)
	})

	t.Run("example (content length)", func(t *testing.T) {
		body := strings.NewReader("Hello")
		h := []http.Field{
			{Name: []byte("Content-Length"), Value: []byte("5")},
		}
		msg, err := createMessage(ver, h, body, ParseMessageOptions{})
		require.NoError(t, err)

		assert.Equal(t, HeadersFrom(h, false), msg.Headers)
		assert.Empty(t, msg.TransferEncoding)

		require.NotNil(t, msg.ContentLength)
		assert.Equal(t, uint(5), *msg.ContentLength)

		assert.IsType(t, &iolib.LimitedReader{}, msg.Body)
		b, err := io.ReadAll(msg.Body)
		assert.NoError(t, err)
		assert.Equal(t, []byte("Hello"), b)
	})
}

func TestMessageEnsureHeadersSet(t *testing.T) {
	one := uint(1)
	msg := Message{
		ContentLength:    &one,
		TransferEncoding: []transfer.Coding{transfer.CodingChunked},
	}

	msg.EnsureHeadersSet()

	assert.NotNil(t, msg.Headers.underlying)

	v, ok := msg.Headers.Get("Content-Length")
	assert.True(t, ok)
	assert.Equal(t, "1", v)

	v, ok = msg.Headers.Get("Transfer-Encoding")
	assert.True(t, ok)
	assert.Equal(t, "chunked", v)

}

func TestMessageEncodeTransfer(t *testing.T) {
	content := "How's it going?"

	message := Message{
		TransferEncoding: []transfer.Coding{transfer.CodingChunked},
		Body:             strings.NewReader(content),
	}

	expectedTrailers := NewHeaders(map[string][]string{"Foo": {"Bar"}})
	message.Trailers = &expectedTrailers

	// Applies chunked.
	err := message.EncodeTransfer(transfer.NewCodingApplier(nil))
	require.NoError(t, err)

	trailers := []http.Field{}
	r := transfer.NewChunkedCoder().NewReader(message.Body).(*transfer.ChunkedReader)
	r.SetOnTrailerReceived(func(f []http.Field) {
		trailers = f
	})

	b, err := io.ReadAll(r)
	assert.NoError(t, err)
	assert.Equal(t, content, string(b))

	// Compare trailers.
	assert.Equal(t, expectedTrailers, HeadersFrom(trailers, true))
}

func TestMessageDecodeTransfer(t *testing.T) {
	content := "How's it going?"

	message := Message{
		TransferEncoding: []transfer.Coding{transfer.CodingChunked},
		Body:             strings.NewReader(content),
	}

	expectedTrailers := NewHeaders(map[string][]string{"Foo": {"Bar"}})

	// It is now encoded.
	message.Body = iolib.NewMiddlewareReader(
		message.Body,
		func(wc io.WriteCloser) io.WriteCloser {
			wc = transfer.NewChunkedCoder().NewWriter(wc)
			cw := wc.(*transfer.ChunkedWriter)
			cw.SetSendTrailers(func() []http.Field {
				return expectedTrailers.ToRawFields()
			})
			return wc
		},
	)

	err := message.DecodeTransfer(transfer.NewCodingApplier(nil), true)
	require.NoError(t, err)

	b, err := io.ReadAll(message.Body)
	assert.NoError(t, err)
	assert.Equal(t, content, string(b))

	// Compare trailers.
	require.NotNil(t, message.Trailers)
	assert.Equal(t, &expectedTrailers, message.Trailers)
}

func TestAssertHeaderContains(t *testing.T) {
	h := NewHeaders(map[string][]string{
		"foo": {"bar"},
	})

	assert.NoError(t, assertHeaderContains(h, []string{"foo"}))
	assert.Error(t, assertHeaderContains(h, []string{"bar", "baz"}))
}

func TestExtractContentLength(t *testing.T) {
	h := NewHeaders(map[string][]string{
		"Content-Length": {"1"},
	})

	l, err := extractContentLength(h)
	assert.NoError(t, err)
	require.NotNil(t, l)
	assert.Equal(t, uint(1), *l)

	h.Set("Content-Length", "haha")

	l, err = extractContentLength(h)
	require.Error(t, err)
	require.Nil(t, l)

	h.Del("Content-Length")

	l, err = extractContentLength(h)
	assert.NoError(t, err)
	assert.Nil(t, l)
}

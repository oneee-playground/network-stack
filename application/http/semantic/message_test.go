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

package semantic

import (
	"network-stack/application/http"
	"network-stack/application/http/semantic/status"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResponseFrom(t *testing.T) {
	nobody := strings.NewReader("")
	// Assume it is valid.
	raw := http.Response{
		StatusLine: http.StatusLine{
			Version:      http.Version{1, 1},
			StatusCode:   200,
			ReasonPhrase: "OK",
		},
		Headers: []http.Field{
			{Name: []byte("Foo"), Value: []byte("bar")},
		},
		Body: nobody,
	}

	// Also test Host header is overwritten by absolute uri.
	expected := Response{
		Status: status.OK,
		Message: Message{
			Version: raw.Version,
			Headers: NewHeaders(map[string][]string{
				"Foo": {"bar"},
			}),
			ContentLength:    nil,
			TransferEncoding: nil,
			Body:             nobody,
			Trailers:         nil,
		},
	}

	response, err := ResponseFrom(raw, ParseResponseOptions{})
	require.NoError(t, err)

	assert.Equal(t, expected, response)

	// Also test RawResponse.
	assert.Equal(t, raw, response.RawResponse())
}

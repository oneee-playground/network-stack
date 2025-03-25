package uri

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefResolverResolve(t *testing.T) {
	baseURI, err := Parse("http://a/b/c/d;p?q")
	require.NoError(t, err)

	testcases := []struct {
		input  string
		output string
	}{
		{
			input:  "g:h",
			output: "g:h",
		},
		{
			input:  "g",
			output: "http://a/b/c/g",
		},
		{
			input:  "./g",
			output: "http://a/b/c/g",
		},
		{
			input:  "g/",
			output: "http://a/b/c/g/",
		},
		{
			input:  "/g",
			output: "http://a/g",
		},
		{
			input:  "//g",
			output: "http://g",
		},
		{
			input:  "?y",
			output: "http://a/b/c/d;p?y",
		},
		{
			input:  "g?y",
			output: "http://a/b/c/g?y",
		},
		{
			input:  "#s",
			output: "http://a/b/c/d;p?q#s",
		},
		{
			input:  "g#s",
			output: "http://a/b/c/g#s",
		},
		{
			input:  "g?y#s",
			output: "http://a/b/c/g?y#s",
		},
		{
			input:  ";x",
			output: "http://a/b/c/;x",
		},
		{
			input:  "g;x",
			output: "http://a/b/c/g;x",
		},
		{
			input:  "g;x?y#s",
			output: "http://a/b/c/g;x?y#s",
		},
		{
			input:  "",
			output: "http://a/b/c/d;p?q",
		},
		{
			input:  ".",
			output: "http://a/b/c/",
		},
		{
			input:  "./",
			output: "http://a/b/c/",
		},
		{
			input:  "..",
			output: "http://a/b/",
		},
		{
			input:  "../",
			output: "http://a/b/",
		},
		{
			input:  "../g",
			output: "http://a/b/g",
		},
		{
			input:  "../..",
			output: "http://a/",
		},
		{
			input:  "../../",
			output: "http://a/",
		},
		{
			input:  "../../g",
			output: "http://a/g",
		},
		{
			input:  "../../../g",
			output: "http://a/g",
		},
		{
			input:  "../../../../g",
			output: "http://a/g",
		},
	}

	for _, tc := range testcases {
		t.Run(fmt.Sprintf("%s -> %s", tc.input, tc.output), func(t *testing.T) {
			rr, err := NewRefResolver(baseURI)
			require.NoError(t, err)

			in, err := Parse(tc.input)
			require.NoError(t, err)

			out := rr.Resolve(in)
			assert.Equal(t, tc.output, out.String())
		})
	}
}

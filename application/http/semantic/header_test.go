package semantic

import (
	"network-stack/application/http"
	"network-stack/application/util/rule"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHeaders(t *testing.T) {
	initial := map[string][]string{
		"Hello":     {"world!"},
		"some-word": {"A"},
	}

	headers := NewHeaders(initial)

	assert.Empty(t, headers.underlying["some-word"])
	values := headers.underlying["Some-Word"]
	assert.Len(t, values, 1)
	assert.Equal(t, "A", values[0])

	initial["Hello"] = []string{"there"}

	assert.NotEqual(t, initial["Hello"], headers.underlying["Hello"])
}

func TestHeadersFrom(t *testing.T) {
	testcases := []struct {
		desc        string
		input       []http.Field
		mergeValues bool
		expected    map[string][]string
	}{
		{
			desc: "general case",
			input: []http.Field{
				{Name: []byte("Content-Type"), Value: []byte("Hey")},
				{Name: []byte("Quoted"), Value: []byte("\"Hey\"")},
				{Name: []byte("non-canonical"), Value: []byte("Hey")},
				{Name: []byte("Multiple-Values"), Value: []byte("Hey, There")},
			},
			expected: map[string][]string{
				"Content-Type":    {"Hey"},
				"Quoted":          {"Hey"},
				"Non-Canonical":   {"Hey"},
				"Multiple-Values": {"Hey", "There"},
			},
		},
		{
			desc: "duplicate field name (overwritten)",
			input: []http.Field{
				{Name: []byte("Content-Type"), Value: []byte("Hey")},
				{Name: []byte("Content-Type"), Value: []byte("Bye")},
			},
			mergeValues: false,
			expected: map[string][]string{
				"Content-Type": {"Bye"},
			},
		},
		{
			desc: "duplicate field name (merged)",
			input: []http.Field{
				{Name: []byte("Content-Type"), Value: []byte("Hey")},
				{Name: []byte("Content-Type"), Value: []byte("Bye")},
			},
			mergeValues: true,
			expected: map[string][]string{
				"Content-Type": {"Hey", "Bye"},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			headers := HeadersFrom(tc.input, tc.mergeValues)
			assert.Equal(t, tc.expected, headers.underlying)
		})
	}
}

func TestHeaderFields(t *testing.T) {
	hashmap := map[string][]string{
		"A": {"a"},
		"B": {"b"},
	}

	h := NewHeaders(hashmap)

	fields := h.Fields()
	assert.Len(t, fields, len(hashmap))
	assert.Contains(t, fields, "A")
	assert.Equal(t, []string{"a"}, fields["A"])
	assert.Contains(t, fields, "B")
	assert.Equal(t, []string{"b"}, fields["B"])
}

func TestHeaderToRawFields(t *testing.T) {
	hashmap := map[string][]string{
		"A": {"a"},
		"B": {"b"},
	}

	h := NewHeaders(hashmap)

	fields := h.ToRawFields()
	assert.Len(t, fields, len(hashmap))
	assert.Contains(t, fields, http.Field{Name: []byte("A"), Value: []byte("a")})
	assert.Contains(t, fields, http.Field{Name: []byte("B"), Value: []byte("b")})
}

func TestHeaderGet(t *testing.T) {
	h := NewHeaders(map[string][]string{
		"abc": {"abc", "def"},
		"ghi": {},
	})

	v, ok := h.Get("abc")
	assert.True(t, ok)
	assert.Equal(t, "abc", v)

	v, ok = h.Get("ghi")
	assert.False(t, ok)
	assert.Empty(t, v)

	v, ok = h.Get("jkl")
	assert.False(t, ok)
	assert.Empty(t, v)
}

func TestHeaderValues(t *testing.T) {
	h := NewHeaders(map[string][]string{
		"abc": {"abc", "def"},
		"ghi": {},
	})

	v, ok := h.Values("abc")
	assert.True(t, ok)
	assert.Equal(t, []string{"abc", "def"}, v)

	v, ok = h.Values("ghi")
	assert.True(t, ok)
	assert.Empty(t, v)

	v, ok = h.Values("jkl")
	assert.False(t, ok)
	assert.Empty(t, v)
}

func TestHeaderSet(t *testing.T) {
	h := Headers{}

	h.Set("key", "value")
	v, ok := h.underlying["Key"]
	assert.True(t, ok)
	assert.Equal(t, []string{"value"}, v)

	h.Set("key", "non-value")
	v, ok = h.underlying["Key"]
	assert.True(t, ok)
	assert.Equal(t, []string{"non-value"}, v)
}

func TestHeaderAdd(t *testing.T) {
	h := Headers{}

	h.Add("key", "value")
	v, ok := h.underlying["Key"]
	assert.True(t, ok)
	assert.Equal(t, []string{"value"}, v)

	h.Add("key", "non-value")
	v, ok = h.underlying["Key"]
	assert.True(t, ok)
	assert.Equal(t, []string{"value", "non-value"}, v)
}

func TestHeaderDel(t *testing.T) {
	h := NewHeaders(nil)

	h.Add("key", "value")
	v, ok := h.underlying["Key"]
	require.True(t, ok)
	require.Equal(t, []string{"value"}, v)

	h.Del("key")
	v, ok = h.underlying["Key"]
	assert.False(t, ok)
	assert.Empty(t, v)
}

func TestShouldQuote(t *testing.T) {
	assert.False(t, shouldQuote("hello"))
	assert.True(t, shouldQuote(" hello"))
	assert.True(t, shouldQuote("he,llo"))
}

func TestToRawFieldValues(t *testing.T) {
	testcases := []struct {
		desc     string
		input    []string
		expected []byte
	}{
		{
			desc:     "single value",
			input:    []string{"Hello"},
			expected: []byte("Hello"),
		},
		{
			desc:     "multiple values",
			input:    []string{"Hello", "World"},
			expected: []byte("Hello, World"),
		},
		{
			desc:     "single value quoted",
			input:    []string{"Hell llo!!"},
			expected: []byte("\"Hell llo!!\""),
		},
		{
			desc:     "multiple values quoted",
			input:    []string{"Hell llo!!", ", itscomma"},
			expected: []byte("\"Hell llo!!\", \", itscomma\""),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			output := toRawFieldValues(tc.input)
			assert.Equal(t, tc.expected, output)
		})
	}
}

func TestHeadersGetSet(t *testing.T) {
	h := NewHeaders(nil)

	key, value := "content-type", "do you care?"

	a, ok := h.Get(key)
	assert.False(t, ok)
	assert.Empty(t, a)

	h.Set(key, value)

	assert.Empty(t, h.underlying[key])
	values := h.underlying[toCanonicalFieldName(key)]
	assert.Len(t, values, 1)
	assert.Equal(t, value, values[0])

	a, ok = h.Get(key)
	assert.True(t, ok)
	assert.Equal(t, value, a)
}

func TestToCanonicalFieldName(t *testing.T) {
	testcases := []struct {
		desc     string
		input    string
		expected string
	}{
		{
			desc:     "all lowercase",
			input:    "content-type",
			expected: "Content-Type",
		},
		{
			desc:     "all uppercase",
			input:    "CONTENT-TYPE",
			expected: "Content-Type",
		},
		{
			desc:     "mixed case",
			input:    "cOnTeNt-TyPe",
			expected: "Content-Type",
		},
		{
			desc:     "single word",
			input:    "contenttype",
			expected: "Contenttype",
		},
		{
			desc:     "empty string",
			input:    "",
			expected: "",
		},
		{
			desc:     "already canonical",
			input:    "Content-Type",
			expected: "Content-Type",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			result := toCanonicalFieldName(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestTokenizeFieldValues(t *testing.T) {
	testcases := []struct {
		desc     string
		input    []byte
		expected []string
	}{
		{
			desc:     "single value",
			input:    []byte("hello world"),
			expected: []string{"hello world"},
		},
		{
			desc:     "multiple values with comma",
			input:    []byte("foo, bar,baz"),
			expected: []string{"foo", "bar", "baz"},
		},
		{
			desc:     "quoted value",
			input:    []byte("\"foo\""),
			expected: []string{"foo"},
		},
		{
			desc:     "quoted values with comma",
			input:    []byte("\"foo\", \"bar\""),
			expected: []string{"foo", "bar"},
		},
		{
			desc:     "comma inside quoted string",
			input:    []byte("foo \",bar\""),
			expected: []string{"foo \",bar\""},
		},
		{
			desc:     "escaped characters",
			input:    []byte("\"foo is \\\"bar\\\"\""),
			expected: []string{"foo is \"bar\""},
		},
		{
			desc:     "empty values",
			input:    []byte("foo, , , bar, "),
			expected: []string{"foo", "bar"},
		},
		{
			desc:     "malformed quote",
			input:    []byte("\"foo, bar"),
			expected: []string{"\"foo, bar"},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			output := tokenizeFieldValues(tc.input)
			assert.Equal(t, tc.expected, output)
		})
	}
}

func TestAddToken(t *testing.T) {
	testcases := []struct {
		desc     string
		input    []byte
		expected []string
	}{
		{
			desc:     "empty token",
			input:    []byte(""),
			expected: []string{},
		},
		{
			desc:     "only whitespaces",
			input:    rule.Whitespaces,
			expected: []string{},
		},
		{
			desc:     "normal value",
			input:    []byte("Hello"),
			expected: []string{"Hello"},
		},
		{
			desc:     "quoted value",
			input:    []byte("\"Hello\""),
			expected: []string{"Hello"},
		},
		{
			desc:     "quoted value (not entirely wrapped)",
			input:    []byte("He\"llo\""),
			expected: []string{"He\"llo\""},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			initial := []string{}
			output := addToken(initial, tc.input)
			assert.Equal(t, tc.expected, output)
		})
	}

}

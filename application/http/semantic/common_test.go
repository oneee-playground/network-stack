package semantic

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseDate(t *testing.T) {
	expected := time.Date(1994, 11, 6, 8, 49, 37, 0, time.UTC)

	testcases := []struct {
		desc    string
		input   string
		wantErr bool
	}{
		{
			desc:  "IMF-fixdate",
			input: "Sun, 06 Nov 1994 08:49:37 GMT",
		},
		{
			desc:  "obsolete RFC 850 format",
			input: "Sunday, 06-Nov-94 08:49:37 GMT",
		},
		{
			desc:  "ANSI C's asctime() format",
			input: "Sun Nov  6 08:49:37 1994",
		},
		{
			desc:    "datetime",
			input:   "1994-11-06 08:49:37",
			wantErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			tm, err := ParseDate(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, expected, tm)
		})
	}
}

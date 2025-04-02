package iolib

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testMiddleware struct {
	w       io.WriteCloser
	onWrite func(w io.Writer, p []byte) error
	onClose func(w io.Writer) error
}

func (m *testMiddleware) Write(p []byte) (n int, err error) {
	if err := m.onWrite(m.w, p); err != nil {
		return 0, err
	}
	return m.w.Write(p)
}

func (m *testMiddleware) Close() error {
	if err := m.onClose(m.w); err != nil {
		return err
	}
	return m.w.Close()
}

func TestMiddlewareReader(t *testing.T) {
	N := 10
	input := bytes.Repeat([]byte("ABC"), N)

	testcase := []struct {
		desc     string
		onWrite  func(w io.Writer, p []byte) error
		onClose  func(w io.Writer) error
		expected []byte
		wantErr  bool
	}{
		{
			desc: "example (incr 1)",
			onWrite: func(w io.Writer, p []byte) error {
				for i := range p {
					p[i] = p[i] + 1
				}
				return nil
			},
			onClose: func(w io.Writer) error {
				return nil
			},
			expected: bytes.Repeat([]byte("BCD"), N),
		},
		{
			desc: "example (close write)",
			onWrite: func(w io.Writer, p []byte) error {
				return nil
			},
			onClose: func(w io.Writer) error {
				_, err := w.Write([]byte("DEFG"))
				return err
			},
			expected: append(bytes.Repeat([]byte("ABC"), N), []byte("DEFG")...),
		},
		{
			desc: "write err",
			onWrite: func(w io.Writer, p []byte) error {
				return errors.New("hey")
			},
			onClose: func(w io.Writer) error {
				return nil
			},
			wantErr: true,
		},
		{
			desc: "close err",
			onWrite: func(w io.Writer, p []byte) error {
				return nil
			},
			onClose: func(w io.Writer) error {
				return errors.New("hey")
			},
			wantErr: true,
		},
	}

	for _, tc := range testcase {
		t.Run(tc.desc, func(t *testing.T) {
			r := NewMiddlewareReader(
				bytes.NewReader(input),
				func(wc io.WriteCloser) io.WriteCloser {
					return &testMiddleware{
						w:       wc,
						onWrite: tc.onWrite,
						onClose: tc.onClose,
					}
				},
			)

			b, err := io.ReadAll(r)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, b)

		})
	}
}

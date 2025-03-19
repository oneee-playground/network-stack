package transfer

import (
	"bufio"
	"bytes"
	"io"
	"math/big"
	"network-stack/application/http"
	"network-stack/application/util/rule"
	bytesutil "network-stack/util/bytes"
	"strconv"

	"github.com/pkg/errors"
)

type Chunk struct {
	Size       uint
	Extensions [][2]string
	data       io.Reader
}

type ChunkedReader struct {
	br       *bufio.Reader
	chunk    *Chunk
	read     uint // reset for each chunk
	crlfDump []byte

	// trailerStore points at external trailer storage.
	trailerStore *[]http.Field
}

var _ io.Reader = (*ChunkedReader)(nil)

// NewChunkedReader converts chunked http message into byte stream.
// if trailerStore is not nil, it will be filled on last Read.
func NewChunkedReader(r io.Reader, trailerStore *[]http.Field) *ChunkedReader {
	return &ChunkedReader{
		br:           bufio.NewReader(r),
		crlfDump:     make([]byte, 2),
		trailerStore: trailerStore,
	}
}

func (cr *ChunkedReader) LastChunk() *Chunk {
	return cr.chunk
}

func (cr *ChunkedReader) Read(b []byte) (int, error) {
	if cr.chunk == nil {
		if err := cr.decodeChunk(); err != nil {
			return 0, errors.Wrap(err, "decoding chunk")
		}

		if cr.chunk.Size == 0 {
			// Last chunk.
			if err := cr.decodeTrailers(); err != nil {
				return 0, errors.Wrap(err, "decoding trailer")
			}
			return 0, io.EOF
		}
	}

	remain := cr.chunk.Size - cr.read
	if uint(len(b)) > remain {
		b = b[:remain]
	}

	n, err := cr.chunk.data.Read(b)
	if err != nil {
		return n, errors.Wrap(err, "reading chunk data")
	}

	cr.read += uint(n)

	if cr.read == cr.chunk.Size {
		_, err := cr.chunk.data.Read(cr.crlfDump)
		if err != nil {
			return n, errors.Wrap(err, "reading chunk delimiter")
		}

		if !bytes.Equal(cr.crlfDump, rule.CRLF) {
			return n, errors.New("CRLF delimiter not found")
		}

		cr.chunk = nil
		cr.read = 0
	}

	return n, nil
}

func (cr *ChunkedReader) decodeChunk() error {
	line, err := readLine(cr.br)
	if err != nil {
		return err
	}

	parts := bytes.Split(line, []byte{';'})

	sizeRaw := bytes.TrimFunc(parts[0], rule.IsWhitespace)
	chunkSize, err := decodeChunkSize(sizeRaw)
	if err != nil {
		return errors.Wrap(err, "decoding chunk size")
	}

	// Decode chunk extensions
	parts = parts[1:]
	extensions := make([][2]string, 0)
	for _, part := range parts {
		k, v, _ := bytes.Cut(part, []byte{'='})
		// Trim BWS.
		k = bytes.TrimFunc(k, rule.IsWhitespace)
		v = bytes.TrimFunc(v, rule.IsWhitespace)

		extensions = append(extensions, [2]string{
			string(k),
			string(rule.Unquote(v)),
		})
	}

	cr.chunk = &Chunk{
		Size:       chunkSize,
		Extensions: extensions,
		data:       cr.br,
	}

	return nil
}

func decodeChunkSize(b []byte) (uint, error) {
	n := big.NewInt(0)

	n, ok := n.SetString(string(b), 16)
	if !ok {
		return 0, errors.Errorf("failed to deocode hex: %q", string(b))
	}

	if n.BitLen() > 64 {
		return 0, errors.Errorf("chunk size larger than 64bit: %dbits", n.BitLen())
	}

	size := uint(n.Uint64())
	return size, nil
}

func (cr *ChunkedReader) decodeTrailers() error {
	fields := make([]http.Field, 0)
	for {
		line, err := readLine(cr.br)
		if err != nil {
			return errors.Wrap(err, "reading line")
		}

		if len(line) == 0 {
			// Last field.
			break
		}

		field, err := http.ParseField(line)
		if err != nil {
			return errors.Wrap(err, "parsing field")
		}

		fields = append(fields, field)
	}

	if cr.trailerStore != nil {
		*cr.trailerStore = fields
	}

	return nil
}

type ChunkedWriter struct {
	w         io.Writer
	headerBuf *bytes.Buffer

	extensions [][2]string
	// trailerStore points at external trailer storage.
	trailerStore *[]http.Field
}

var _ io.WriteCloser = (*ChunkedWriter)(nil)

func NewChunkedWriter(w io.Writer, trailerStore *[]http.Field) *ChunkedWriter {
	return &ChunkedWriter{
		w:            w,
		headerBuf:    bytes.NewBuffer(nil),
		trailerStore: trailerStore,
	}
}

// SetExtensions sets extension to the chunk.
// extension lives until [ChunkedWriter.Write].
func (cw *ChunkedWriter) SetExtensions(extensions [][2]string) {
	cw.extensions = extensions
}

func (cw *ChunkedWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		// We should ignore 0 length chunks since it means EOF.
		return 0, nil
	}

	chunk := Chunk{
		Size:       uint(len(p)),
		Extensions: cw.extensions,
		data:       bytes.NewBuffer(p),
	}

	cw.extensions = nil

	n, err = cw.encodeChunk(chunk)
	if err != nil {
		return n, errors.Wrap(err, "encoding chunk")
	}

	return n, nil
}

func (cw *ChunkedWriter) Close() error {
	chunk := Chunk{
		Size:       0,
		Extensions: cw.extensions,
	}

	if _, err := cw.encodeChunk(chunk); err != nil {
		return errors.Wrap(err, "encoding chunk")
	}

	if err := cw.encodeTrailers(); err != nil {
		return errors.Wrap(err, "encoding trailers")
	}

	return nil
}

func (cw *ChunkedWriter) encodeChunk(chunk Chunk) (n int, err error) {
	// size and extensions
	buf := cw.headerBuf
	buf.Reset()
	buf.Write([]byte(strconv.FormatUint(uint64(chunk.Size), 16)))
	for _, ext := range chunk.Extensions {
		buf.Write([]byte{';'})
		buf.Write([]byte(ext[0]))
		buf.Write([]byte{'='})
		buf.Write([]byte(ext[1]))
	}

	if err := writeLine(cw.w, buf.Bytes()); err != nil {
		return 0, errors.Wrap(err, "writing chunk header")
	}

	if chunk.Size == 0 {
		// Last chunk. only write header.
		return 0, nil
	}

	// chunk data + CRLF
	r := io.MultiReader(chunk.data, bytes.NewReader(rule.CRLF))

	n64, err := io.Copy(cw.w, r)
	if err != nil {
		return n, errors.Wrap(err, "writing data")
	}

	return int(n64) - len(rule.CRLF), nil
}

func (cw *ChunkedWriter) encodeTrailers() error {
	if cw.trailerStore != nil {
		for _, field := range *cw.trailerStore {
			if err := writeLine(cw.w, field.Text()); err != nil {
				return errors.Wrap(err, "writing trailer")
			}
		}
	}

	if err := writeLine(cw.w, nil); err != nil {
		return errors.Wrap(err, "writing last trailer line")
	}

	return nil
}

// readLine reads until CRLF and cuts it.
func readLine(br *bufio.Reader) (line []byte, err error) {
	line, err = bytesutil.ReadUntil(br, rule.CRLF)
	if err != nil {
		return nil, err
	}

	return line[:len(line)-2], nil
}

func writeLine(w io.Writer, line []byte) error {
	r := bytes.NewReader(append(line, rule.CRLF...))

	_, err := io.Copy(w, r)
	if err != nil {
		return errors.Wrap(err, "writing line")
	}

	return nil
}

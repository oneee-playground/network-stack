package rule

const (
	CR   byte = '\r'
	LF   byte = '\n'
	SP   byte = ' '
	HTAB byte = '\t'
	VT   byte = 0x0B
	FF   byte = 0x0C
)

var (
	OWS         = []byte{SP, HTAB}
	Whitespaces = []byte{SP, HTAB, VT, FF, CR}
)

func IsWhitespace(c byte) bool {
	for _, ws := range Whitespaces {
		if c == ws {
			return true
		}
	}
	return false
}

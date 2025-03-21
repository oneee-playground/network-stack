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
	CRLF        = []byte{CR, LF}
	Whitespaces = []byte{SP, HTAB, VT, FF, CR}
)

func IsWhitespace(r rune) bool {
	for _, ws := range Whitespaces {
		if r == rune(ws) {
			return true
		}
	}
	return false
}

func IsAlpha(r rune) bool { return ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') }
func IsDigit(r rune) bool { return '0' <= r && r <= '9' }

package extension

import "testing"

func TestALPNProtocols(t *testing.T) {
	orig := &ALPNProtocols{
		ProtocolNameList: []ALPNProtocolName{
			ALPNProtocolName("abc"),
		},
	}

	testExtension(t, orig, TypeALPN)
}

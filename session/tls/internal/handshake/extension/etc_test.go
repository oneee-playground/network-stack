package extension

import (
	"testing"

	"network-stack/session/tls/internal/common"
)

func TestSupportedVersionsCH(t *testing.T) {
	orig := &SupportedVersionsCH{
		Versions: []common.Version{
			common.VersionTLS11, common.VersionTLS12,
		},
	}

	testExtension(t, orig, new(SupportedVersionsCH), TypeSupportedVersions)
}

func TestSupportedVersionsSH(t *testing.T) {
	orig := &SupportedVersionsSH{
		SelectedVersion: common.VersionTLS13,
	}

	testExtension(t, orig, new(SupportedVersionsSH), TypeSupportedVersions)
}

func TestCookie(t *testing.T) {
	orig := &Cookie{
		Cookie: []byte("sample-cookie"),
	}

	testExtension(t, orig, new(Cookie), TypeCookie)
}

func TestPostHandshakeAuth(t *testing.T) {
	orig := &PostHandshakeAuth{}

	testExtension(t, orig, new(PostHandshakeAuth), TypePostHandshakeAuth)
}

func TestEarlyDataNST(t *testing.T) {
	orig := &EarlyDataNST{
		MaxEarlyDataSize: 0xDEADBEEF,
	}

	testExtension(t, orig, new(EarlyDataNST), TypeEarlyData)
}

func TestEarlyDataEmpty(t *testing.T) {
	ch := &EarlyDataCH{}
	ee := &EarlyDataEE{}

	testExtension(t, ch, new(EarlyDataCH), TypeEarlyData)
	testExtension(t, ee, new(EarlyDataEE), TypeEarlyData)
}

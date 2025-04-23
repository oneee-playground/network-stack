package extension

import (
	"testing"
)

func TestSupportedGroups(t *testing.T) {
	orig := &SupportedGroups{
		NamedGroupList: []NamedGroup{
			NamedGroup_Secp256r1,
			NamedGroup_X25519,
		},
	}

	testExtension(t, orig, new(SupportedGroups), TypeSupportedGroups)
}

func TestKeyShareCH(t *testing.T) {
	orig := &KeyShareCH{
		KeyShares: []KeyShareEntry{
			{
				Group:       NamedGroup_Secp256r1,
				KeyExchange: []byte{0x01, 0x02, 0x03},
			},
			{
				Group:       NamedGroup_X25519,
				KeyExchange: []byte{0x04, 0x05, 0x06},
			},
		},
	}

	testExtension(t, orig, new(KeyShareCH), TypeKeyShare)
}

func TestKeyShareHRR(t *testing.T) {
	orig := &KeyShareHRR{
		SelectedGroup: NamedGroup_X448,
	}

	testExtension(t, orig, new(KeyShareHRR), TypeKeyShare)
}

func TestKeyShareSH(t *testing.T) {
	orig := &KeyShareSH{
		KeyShare: KeyShareEntry{
			Group:       NamedGroup_FFDHE2048,
			KeyExchange: []byte{0x07, 0x08, 0x09},
		},
	}

	testExtension(t, orig, new(KeyShareSH), TypeKeyShare)
}

func TestPskKeyExchangeModes(t *testing.T) {
	orig := &PskKeyExchangeModes{
		KeModes: []PskKeyExchangeMode{
			ExchangeMode_PSKKE,
			ExchangeMode_PSKDHEKE,
		},
	}

	testExtension(t, orig, new(PskKeyExchangeModes), TypePskKeyExchangeModes)
}

func TestPreSharedKeySH(t *testing.T) {
	orig := &PreSharedKeySH{
		SelectedIdentity: 0x1234,
	}

	testExtension(t, orig, new(PreSharedKeySH), TypePreSharedKey)
}

func TestPreSharedKeyCH(t *testing.T) {
	orig := &PreSharedKeyCH{
		Identities: []PSKIdentity{
			{
				Identity:            []byte("identity1"),
				ObfuscatedTicketAge: 12345,
			},
			{
				Identity:            []byte("identity2"),
				ObfuscatedTicketAge: 67890,
			},
		},
		Binders: []PSKBinderEntry{
			[]byte{0x01, 0x02},
			[]byte{0x03, 0x04},
		},
	}

	testExtension(t, orig, new(PreSharedKeyCH), TypePreSharedKey)
}

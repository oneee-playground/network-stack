package extension

import (
	"network-stack/session/tls/common/keyexchange"
	"testing"
)

func TestSupportedGroups(t *testing.T) {
	orig := &SupportedGroups{
		NamedGroupList: []keyexchange.GroupID{
			keyexchange.Group_Secp256r1,
			keyexchange.Group_X25519,
		},
	}

	testExtension(t, orig, TypeSupportedGroups)
}

func TestKeyShareCH(t *testing.T) {
	orig := &KeyShareCH{
		KeyShares: []KeyShareEntry{
			{
				Group:       keyexchange.Group_Secp256r1,
				KeyExchange: []byte{0x01, 0x02, 0x03},
			},
			{
				Group:       keyexchange.Group_X25519,
				KeyExchange: []byte{0x04, 0x05, 0x06},
			},
		},
	}

	testExtension(t, orig, TypeKeyShare)
}

func TestKeyShareHRR(t *testing.T) {
	orig := &KeyShareHRR{
		SelectedGroup: keyexchange.Group_X448,
	}

	testExtension(t, orig, TypeKeyShare)
}

func TestKeyShareSH(t *testing.T) {
	orig := &KeyShareSH{
		KeyShare: KeyShareEntry{
			Group:       keyexchange.Group_FFDHE2048,
			KeyExchange: []byte{0x07, 0x08, 0x09},
		},
	}

	testExtension(t, orig, TypeKeyShare)
}

func TestPskKeyExchangeModes(t *testing.T) {
	orig := &PskKeyExchangeModes{
		KeModes: []PSKMode{
			PSKModePSK_KE,
			PSKModePSK_DHE_KE,
		},
	}

	testExtension(t, orig, TypePskKeyExchangeModes)
}

func TestPreSharedKeySH(t *testing.T) {
	orig := &PreSharedKeySH{
		SelectedIdentity: 0x1234,
	}

	testExtension(t, orig, TypePreSharedKey)
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

	testExtension(t, orig, TypePreSharedKey)
}

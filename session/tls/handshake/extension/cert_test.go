package extension

import (
	"testing"
)

func TestCertAuthorities(t *testing.T) {
	orig := &CertAuthorities{
		Authorities: []DistinguishedName{
			[]byte("Authority1"),
			[]byte("Authority2"),
		},
	}

	testExtension(t, orig, new(CertAuthorities), TypeCertAuthorities)
}

func TestOIDFilters(t *testing.T) {
	orig := &OIDFilters{
		Filters: []OIDFilter{
			{
				CertExtensionOID:    []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}, // Example OID
				CertExtensionValues: []byte{0x01, 0x02, 0x03},
			},
			{
				CertExtensionOID:    []byte{0x55, 0x1D, 0x0E}, // Another example OID
				CertExtensionValues: []byte{0x04, 0x05},
			},
		},
	}

	testExtension(t, orig, new(OIDFilters), TypeOidFilters)
}

package extension

import "testing"

func TestServerNameList(t *testing.T) {
	orig := &ServerNameList{
		ServerNameList: []ServerName{
			{
				NameType: ServerNameTypeHostName,
				Name:     []byte("the name"),
			},
		},
	}

	testExtension(t, orig, TypeServerName)
}

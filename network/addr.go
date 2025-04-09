package network

type Addr interface {
	String() string
	Raw() []byte
}

package misc

import (
	"hash"
	"reflect"
)

// See https://github.com/golang/go/issues/69521.
func CopyHash(src hash.Hash) hash.Hash {
	typ := reflect.TypeOf(src)
	val := reflect.ValueOf(src)
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
		val = val.Elem()
	}
	elem := reflect.New(typ).Elem()
	elem.Set(val)
	return elem.Addr().Interface().(hash.Hash)
}

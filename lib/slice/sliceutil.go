package sliceutil

func Map[From any, To any](v []From, f func(From) To) []To {
	out := make([]To, len(v))
	for idx := 0; idx < len(v); idx++ {
		out[idx] = f(v[idx])
	}
	return out
}

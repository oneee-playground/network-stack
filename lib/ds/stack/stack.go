package stack

import (
	"network-stack/lib/ds/internal"

	"github.com/pkg/errors"
)

var ErrStackEmpty = errors.New("stack is empty")

type stack[T any] struct{ underlying []T }

func New[T any](cap uint) *stack[T] {
	return &stack[T]{underlying: make([]T, 0, cap)}
}

func (s *stack[T]) Len() uint {
	return uint(len(s.underlying))
}

func (s *stack[T]) Data() []T {
	out := make([]T, len(s.underlying))
	copy(out, s.underlying)
	return out
}

func (s *stack[T]) Push(data T) {
	s.underlying = append(s.underlying, data)
}

func (s *stack[T]) Pop() (T, error) {
	if s.Len() == 0 {
		return internal.Zero[T](), ErrStackEmpty
	}

	data := s.underlying[s.Len()-1]
	s.underlying = s.underlying[:s.Len()-1]

	return data, nil
}

func (s *stack[T]) Peek() (T, error) {
	if s.Len() == 0 {
		return internal.Zero[T](), ErrStackEmpty
	}

	return s.underlying[s.Len()-1], nil
}

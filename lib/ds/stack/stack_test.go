package stack

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStackNew(t *testing.T) {
	capacity := uint(10)

	stack := New[int](capacity)

	assert.IsType(t, []int{}, stack.underlying)
	assert.Equal(t, capacity, uint(cap(stack.underlying)))
	assert.Len(t, stack.underlying, 0)
}

func TestStackLen(t *testing.T) {
	stack := New[int](0)
	stack.underlying = []int{1, 2, 3}

	assert.Equal(t, stack.Len(), uint(len(stack.underlying)))
}

func TestStackData(t *testing.T) {
	stack := New[int](0)
	stack.underlying = []int{1, 2, 3}

	data := stack.Data()

	assert.Equal(t, stack.underlying, data)
}

func TestStackPush(t *testing.T) {
	data := 1
	stack := New[int](0)

	stack.Push(data)

	assert.Len(t, stack.underlying, 1)
	assert.Equal(t, data, stack.underlying[0])
}

func TestStackPop(t *testing.T) {
	data := 1
	stack := New[int](0)
	stack.underlying = []int{data}

	got, err := stack.Pop()
	assert.NoError(t, err)

	assert.Equal(t, data, got)
	assert.Len(t, stack.underlying, 0)
}

func TestStackPopEmpty(t *testing.T) {
	stack := New[int](0)

	got, err := stack.Pop()
	assert.ErrorIs(t, err, ErrStackEmpty)
	assert.Zero(t, got)
}

func TestStackPeek(t *testing.T) {
	data := 1
	stack := New[int](0)
	stack.underlying = []int{data}

	got, err := stack.Peek()
	assert.NoError(t, err)

	assert.Equal(t, data, got)
	assert.Len(t, stack.underlying, 1)
}

func TestStackPeekEmpty(t *testing.T) {
	stack := New[int](0)

	got, err := stack.Peek()
	assert.ErrorIs(t, err, ErrStackEmpty)
	assert.Zero(t, got)
}

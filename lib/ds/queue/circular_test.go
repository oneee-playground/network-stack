package queue

import (
	"testing"

	"network-stack/lib/ds/internal"

	"github.com/stretchr/testify/assert"
)

func TestQueueNew(t *testing.T) {
	size := uint(5)
	q := NewCircular[int](size)

	assert.Equal(t, size, q.Size())
	assert.Equal(t, uint(0), q.Len())
}

func TestQueueEnqueueDequeue(t *testing.T) {
	size := uint(3)
	q := NewCircular[int](size)

	assert.True(t, q.Enqueue(1))
	assert.True(t, q.Enqueue(2))
	assert.True(t, q.Enqueue(3))
	assert.False(t, q.Enqueue(4)) // should be full

	val, err := q.Dequeue()
	assert.NoError(t, err)
	assert.Equal(t, 1, val)

	assert.True(t, q.Enqueue(4)) // should be space after dequeue
	assert.Equal(t, uint(3), q.Len())
}

func TestQueuePeek(t *testing.T) {
	size := uint(2)
	q := NewCircular[string](size)

	q.Enqueue("hello")
	q.Enqueue("world")

	val, err := q.Peek()
	assert.NoError(t, err)
	assert.Equal(t, "hello", val)

	// should not remove
	assert.Equal(t, uint(2), q.Len())
}

func TestQueueEmpty(t *testing.T) {
	q := NewCircular[int](0)

	val, err := q.Dequeue()
	assert.ErrorIs(t, err, ErrQueueEmpty)
	assert.Equal(t, internal.Zero[int](), val)

	val, err = q.Peek()
	assert.ErrorIs(t, err, ErrQueueEmpty)
	assert.Equal(t, internal.Zero[int](), val)
}

func TestQueueWrapAround(t *testing.T) {
	q := NewCircular[int](4)

	q.Enqueue(1)
	q.Enqueue(2)
	q.Dequeue() // head moves
	q.Enqueue(3)
	q.Enqueue(4) // tail wraps around

	assert.Equal(t, uint(3), q.Len())

	v1, _ := q.Dequeue()
	v2, _ := q.Dequeue()
	v3, _ := q.Dequeue()

	assert.Equal(t, 2, v1)
	assert.Equal(t, 3, v2)
	assert.Equal(t, 4, v3)

	assert.Equal(t, uint(0), q.Len())
}

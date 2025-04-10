package queue

import (
	"errors"
	"network-stack/lib/ds/internal"
)

var ErrQueueEmpty = errors.New("queue is empty")

type Queue[T any] interface {
	Enqueue(v T)
	Dequeue() (T, error)
	Peek() (T, error)
	Len() uint
}

type NaiveQueue[T any] struct {
	queue []T
}

func NewNaive[T any](initialCap uint) *NaiveQueue[T] {
	return &NaiveQueue[T]{queue: make([]T, 0, initialCap)}
}

var _ Queue[int] = (*NaiveQueue[int])(nil)

func (q *NaiveQueue[T]) Enqueue(v T) {
	q.queue = append(q.queue, v)
}

func (q *NaiveQueue[T]) Dequeue() (T, error) {
	if q.Len() == 0 {
		return internal.Zero[T](), ErrQueueEmpty
	}

	v := q.queue[0]
	q.queue = q.queue[1:]

	return v, nil
}

func (q *NaiveQueue[T]) Peek() (T, error) {
	if q.Len() == 0 {
		return internal.Zero[T](), ErrQueueEmpty
	}
	return q.queue[0], nil
}

func (q *NaiveQueue[T]) Len() uint {
	return uint(len(q.queue))
}

// TODO: create a efficient queue
// using the idea from net/http's transport.go

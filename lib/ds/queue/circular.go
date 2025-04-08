package queue

import "network-stack/lib/ds/internal"

type circularQueue[T any] struct {
	queue      []T
	head, tail uint

	count uint
}

func NewCircular[T any](size uint) *circularQueue[T] {
	return &circularQueue[T]{
		queue: make([]T, size),
		head:  0, tail: 0, count: 0,
	}
}

// Enqueue adds an element to the queue. Returns false if the queue is full.
func (q *circularQueue[T]) Enqueue(data T) (success bool) {
	if q.Len() == q.Size() {
		return false
	}

	q.queue[q.tail] = data
	q.tail = q.advance(q.tail)
	q.count++

	return true
}

// Dequeue removes and returns the front element of the queue.
// If the queue is empty. It will return [ErrQueueEmpty].
func (q *circularQueue[T]) Dequeue() (T, error) {
	if q.Len() == 0 {
		return internal.Zero[T](), ErrQueueEmpty
	}

	data := q.queue[q.head]

	q.head = q.advance(q.head)
	q.count--

	return data, nil
}

// Peek returns the head element without removing it.
// If the queue is empty. It will return [ErrQueueEmpty].
func (q *circularQueue[T]) Peek() (T, error) {
	if q.Len() == 0 {
		return internal.Zero[T](), ErrQueueEmpty
	}

	return q.queue[q.head], nil
}

// Len returns the number of elements in the queue.
func (q *circularQueue[T]) Len() uint {
	return q.count
}

// Size returns the size of the queue.
func (q *circularQueue[T]) Size() uint {
	return uint(len(q.queue))
}

func (q *circularQueue[T]) advance(n uint) uint {
	return (n + 1) % uint(len(q.queue))
}

package queue

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type QueueTestSuite struct {
	suite.Suite

	Queue   Queue[int]
	samples []int
}

func (s *QueueTestSuite) SetupTest() {
	s.samples = []int{1, 2, 3}
}

func (s *QueueTestSuite) TestEnqueueDequeue() {
	for _, v := range s.samples {
		s.Queue.Enqueue(v)
	}

	s.Equal(uint(len(s.samples)), s.Queue.Len())

	for _, expected := range s.samples {
		actual, err := s.Queue.Dequeue()
		s.NoError(err)
		s.Equal(expected, actual)
	}

	_, err := s.Queue.Dequeue()
	s.ErrorIs(err, ErrQueueEmpty)
}

func (s *QueueTestSuite) TestPeek() {
	s.Queue.Enqueue(s.samples[0])
	s.Queue.Enqueue(s.samples[1])

	peeked, err := s.Queue.Peek()
	s.NoError(err)
	s.Equal(s.samples[0], peeked)

	s.Equal(uint(2), s.Queue.Len())
}

func (s *QueueTestSuite) TestLen() {
	s.Equal(uint(0), s.Queue.Len())

	s.Queue.Enqueue(s.samples[0])
	s.Equal(uint(1), s.Queue.Len())

	_, _ = s.Queue.Dequeue()
	s.Equal(uint(0), s.Queue.Len())
}

type NaiveQueueTestSuite struct {
	QueueTestSuite
}

func TestNaiveQueueTestSuite(t *testing.T) {
	suite.Run(t, new(NaiveQueueTestSuite))
}

func (s *NaiveQueueTestSuite) SetupTest() {
	s.QueueTestSuite.SetupTest()
	s.Queue = NewNaive[int](0)
}

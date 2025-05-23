package sliceutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMap(t *testing.T) {
	input := []int{1, 2, 3, 4, 5}
	expected := []int{1, 4, 9, 16, 25}

	result := Map(input, func(x int) int {
		return x * x
	})

	assert.Equal(t, expected, result)
}

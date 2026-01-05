package testutil

import "errors"

var ErrMustFail = errors.New("an expected failure for testing purposes")

type TypeConversion[A, B any] struct {
	Source A
	Target B
}

type T2[A, B any] struct {
	A A
	B B
}

func Mutate[T any](original *T, mutator func(*T)) *T {
	mutator(original)
	return original
}

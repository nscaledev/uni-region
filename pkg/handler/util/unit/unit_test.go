/*
Copyright 2026 the Unikorn Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//nolint:testpackage
package unit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type TestCase[I, E any] struct {
	Name     string
	Input    I
	Expected E
}

func TestBytesToGB(t *testing.T) {
	t.Parallel()

	testCases := []TestCase[int64, int64]{
		{
			Name:     "round down #1",
			Input:    999999999,
			Expected: 0,
		},
		{
			Name:     "round down #2",
			Input:    1999999999,
			Expected: 1,
		},
		{
			Name:     "round down #3",
			Input:    2999999999,
			Expected: 2,
		},
		{
			Name:     "exact #1",
			Input:    1000000000,
			Expected: 1,
		},
		{
			Name:     "exact #2",
			Input:    2000000000,
			Expected: 2,
		},
		{
			Name:     "exact #3",
			Input:    3000000000,
			Expected: 3,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			gigabytes := BytesToGB(testCase.Input)
			require.Equal(t, testCase.Expected, gigabytes)
		})
	}
}

func TestGBToBytes(t *testing.T) {
	t.Parallel()

	testCases := []TestCase[int64, int64]{
		{
			Name:     "#1",
			Input:    1,
			Expected: 1000000000,
		},
		{
			Name:     "#2",
			Input:    2,
			Expected: 2000000000,
		},
		{
			Name:     "#3",
			Input:    3,
			Expected: 3000000000,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			bytes := GBToBytes(testCase.Input)
			require.Equal(t, testCase.Expected, bytes)
		})
	}
}

func TestBytesToGiB(t *testing.T) {
	t.Parallel()

	testCases := []TestCase[int64, int64]{
		{
			Name:     "round down #1",
			Input:    1073741823,
			Expected: 0,
		},
		{
			Name:     "round down #2",
			Input:    2147483647,
			Expected: 1,
		},
		{
			Name:     "round down #3",
			Input:    3221225471,
			Expected: 2,
		},
		{
			Name:     "exact #1",
			Input:    1073741824,
			Expected: 1,
		},
		{
			Name:     "exact #2",
			Input:    2147483648,
			Expected: 2,
		},
		{
			Name:     "exact #3",
			Input:    3221225472,
			Expected: 3,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			gibibytes := BytesToGiB(testCase.Input)
			require.Equal(t, testCase.Expected, gibibytes)
		})
	}
}

func TestGiBToBytes(t *testing.T) {
	t.Parallel()

	testCases := []TestCase[int64, int64]{
		{
			Name:     "#1",
			Input:    1,
			Expected: 1073741824,
		},
		{
			Name:     "#2",
			Input:    2,
			Expected: 2147483648,
		},
		{
			Name:     "#3",
			Input:    3,
			Expected: 3221225472,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			bytes := GiBToBytes(testCase.Input)
			require.Equal(t, testCase.Expected, bytes)
		})
	}
}

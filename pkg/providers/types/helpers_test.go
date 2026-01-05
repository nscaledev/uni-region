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
package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFlavor_GPUCount(t *testing.T) {
	t.Parallel()

	type TestCase struct {
		Name     string
		Input    Flavor
		Expected int
	}

	testCases := []TestCase{
		{
			Name:     "returns 0 when GPU is nil",
			Input:    Flavor{},
			Expected: 0,
		},
		{
			Name: "returns logical count when GPU is not nil #1",
			Input: Flavor{
				GPU: &GPU{},
			},
			Expected: 0,
		},
		{
			Name: "returns logical count when GPU is not nil #2",
			Input: Flavor{
				GPU: &GPU{
					LogicalCount: 2,
				},
			},
			Expected: 2,
		},
		{
			Name: "returns logical count when GPU is not nil #3",
			Input: Flavor{
				GPU: &GPU{
					LogicalCount: 4,
				},
			},
			Expected: 4,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			logicalCount := testCase.Input.GPUCount()
			require.Equal(t, testCase.Expected, logicalCount)
		})
	}
}

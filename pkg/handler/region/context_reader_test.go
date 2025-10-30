/*
Copyright 2025 the Unikorn Authors.

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

package region_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/region/pkg/handler/region"
)

func TestContextReader_Read(t *testing.T) {
	t.Parallel()

	type TestCase struct {
		Name   string
		Cancel bool
		Error  error
	}

	testCases := []TestCase{
		{
			Name:   "returns error when context is cancelled",
			Cancel: true,
			Error:  context.Canceled,
		},
		{
			Name:   "reads data successfully",
			Cancel: false,
			Error:  nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			expected := []byte("test")
			inner := bytes.NewBuffer(expected)
			reader := region.NewContextReader(ctx, inner)

			if testCase.Cancel {
				cancel()
			}

			actual := make([]byte, len(expected))

			_, err := reader.Read(actual)
			require.Equal(t, testCase.Error, err)

			if err == nil {
				require.Equal(t, expected, actual)
			}
		})
	}
}

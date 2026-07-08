/*
Copyright 2026 Nscale.

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

package userdata_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/region/pkg/userdata"
)

func TestValidateReturnsCanonical422(t *testing.T) {
	t.Parallel()

	gzipData := []byte{0x1f, 0x8b, 0x08, 0x00}
	malformed := []byte("echo hello")
	valid := []byte("#cloud-config\nusers: []\n")

	tests := []struct {
		name      string
		userData  *[]byte
		managed   bool
		wantError bool
	}{
		{name: "NilUserData", userData: nil, managed: true, wantError: false},
		{name: "EmptyUserData", userData: &[]byte{}, managed: false, wantError: false},
		{name: "ValidUnmanaged", userData: &valid, managed: false, wantError: false},
		{name: "ValidManaged", userData: &valid, managed: true, wantError: false},
		{name: "GzipUnmanaged", userData: &gzipData, managed: false, wantError: false},
		{name: "GzipManaged", userData: &gzipData, managed: true, wantError: true},
		{name: "MalformedUnmanaged", userData: &malformed, managed: false, wantError: true},
		{name: "MalformedManaged", userData: &malformed, managed: true, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := userdata.Validate(test.userData, test.managed)

			if !test.wantError {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			require.True(t, errors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
			require.ErrorContains(t, err, "userData must be a recognized cloud-init format")
			// The internal consistency-error sentinel must not leak to callers.
			require.NotContains(t, err.Error(), "consistency error")
		})
	}
}

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

// Package userdata owns the API-boundary contract for cloud-init user-data
// validation. It is deliberately importable by other services (the compute
// instances API consumes it alongside this repository's own server handler) so
// the HTTP status and message for rejected user-data are identical everywhere
// by construction rather than by convention.
package userdata

import (
	"errors"

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	servermanager "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"
)

// Validate is the canonical boundary check for user-data carried on create
// requests. Absent user-data is valid. managed selects the stricter check for
// payloads that will receive managed cloud-init augmentation (an SSH
// certificate authority is referenced), which excludes gzip. Malformed
// payloads yield the ready HTTP 422 carrying the parser's specific reason.
func Validate(userData *[]byte, managed bool) error {
	if userData == nil || len(*userData) == 0 {
		return nil
	}

	validate := servermanager.ValidateUserData
	if managed {
		validate = servermanager.ValidateManagedUserData
	}

	if err := validate(*userData); err != nil {
		return coreerrors.HTTPUnprocessableContent("userData must be a recognized cloud-init format: " + validationReason(err))
	}

	return nil
}

// validationReason extracts the caller-facing reason from a cloud-init parser
// error, without the internal consistency-error sentinel.
func validationReason(err error) string {
	udErr := &servermanager.UserDataError{}
	if errors.As(err, &udErr) {
		return udErr.Reason
	}

	return err.Error()
}

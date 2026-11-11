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

package api

import "fmt"

// StatusError carries the HTTP status code and response body of a failed API call
// so callers can branch on the status (e.g. a 403 quota rejection) rather than
// string-matching a wrapped error message.
type StatusError struct {
	StatusCode int
	Body       string
	Err        error
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("status %d: %s", e.StatusCode, e.Body)
}

func (e *StatusError) Unwrap() error {
	return e.Err
}

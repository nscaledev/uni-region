/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.

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

package types

import (
	"errors"
)

var (
	// ErrResourceDependency is returned when a resource is in unexpected
	// state or condition.
	ErrResourceDependency = errors.New("resource dependency error")

	// ErrImageNotReadyForUpload is returned when the image record at the provider is not in a state
	// for receiving image file data.
	ErrImageNotReadyForUpload = errors.New("image is not in a desired state for upload")

	// ErrImageStillInUse is returned when a image cannot be deleted because it's in active use.
	ErrImageStillInUse = errors.New("image is still in use by one or more servers")
)

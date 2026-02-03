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

package mock

import (
	"testing"

	"go.uber.org/mock/gomock"
)

//go:generate mockgen -source=../image.go -destination=interfaces.go -package=mock

// This one is so we can return a mock ImageQuery from the provider mock.
//go:generate mockgen -destination=queryinterfaces.go -package=mock github.com/unikorn-cloud/region/pkg/providers/types ImageQuery

// newTestMockProvider creates a new mock provider with a gomock controller.
// The controller is automatically cleaned up when the test finishes.
func NewTestMockProviderAndController(t *testing.T) (*MockProvider, *gomock.Controller) {
	t.Helper()

	mockController := gomock.NewController(t)
	t.Cleanup(mockController.Finish)

	return NewMockProvider(mockController), mockController
}

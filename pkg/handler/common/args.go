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

package common

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClientArgs has the values needed to create handlers and clients.
// The general idea is these things should be either scalars or interfaces
// that can easily be mocked out in tests.
type ClientArgs struct {
	// Client gives cached access to Kubernetes.
	Client client.Client

	// Namespace is the namespace we are running in.
	Namespace string
}

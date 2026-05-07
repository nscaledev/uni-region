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

package loadbalancer

import (
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/provisioners/internal/base"
)

// NewForTest constructs a Provisioner directly for unit tests, bypassing the
// CLI-options plumbing handled by New.
func NewForTest(loadbalancer *unikornv1.LoadBalancer, providers providers.Providers) *Provisioner {
	return &Provisioner{
		loadbalancer: loadbalancer,
		Base: base.Base{
			Providers: providers,
		},
	}
}

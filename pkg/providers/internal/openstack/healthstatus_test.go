/*
Copyright 2025 the Unikorn Authors.
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

package openstack_test

import (
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/assert"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"

	corev1 "k8s.io/api/core/v1"
)

func TestConvertServerHealthStatusRebuild(t *testing.T) {
	t.Parallel()

	status, reason, message := openstack.ConvertServerHealthStatus(&servers.Server{Status: "REBUILD"})

	assert.Equal(t, corev1.ConditionFalse, status)
	assert.Equal(t, unikornv1core.ConditionReasonProvisioning, reason)
	assert.Equal(t, "server is rebuilding", message)
}

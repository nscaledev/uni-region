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

package v1alpha1_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func loadBalancerObservedGeneration(t *testing.T, loadBalancer *regionv1.LoadBalancer) int64 {
	t.Helper()

	condition := meta.FindStatusCondition(loadBalancer.Status.Conditions, string(unikornv1core.ConditionAvailable))
	require.NotNil(t, condition)

	return condition.ObservedGeneration
}

// TestLoadBalancerSetProvisioningConditionStampsGeneration pins that every
// outcome stamps the evaluated generation, and a generation bump is picked up
// on restamp.
func TestLoadBalancerSetProvisioningConditionStampsGeneration(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		status corev1.ConditionStatus
		reason unikornv1core.ProvisioningConditionReason
	}{
		{corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned},
		{corev1.ConditionFalse, unikornv1core.ConditionReasonProvisioning},
		{corev1.ConditionFalse, unikornv1core.ConditionReasonErrored},
		{corev1.ConditionFalse, unikornv1core.ConditionReasonDeprovisioning},
	} {
		loadBalancer := &regionv1.LoadBalancer{ObjectMeta: metav1.ObjectMeta{Generation: 1}}
		loadBalancer.SetProvisioningCondition(tc.status, tc.reason, "message")
		require.Equal(t, int64(1), loadBalancerObservedGeneration(t, loadBalancer))
		require.True(t, loadBalancer.ProvisioningConditionCurrent())

		loadBalancer.Generation = 2
		require.False(t, loadBalancer.ProvisioningConditionCurrent())

		loadBalancer.SetProvisioningCondition(tc.status, tc.reason, "message")
		require.Equal(t, int64(2), loadBalancerObservedGeneration(t, loadBalancer))
		require.True(t, loadBalancer.ProvisioningConditionCurrent())
	}
}

// TestLoadBalancerProvisioningConditionCurrent pins that a missing condition, a
// zero-stamped condition, and a stamp from a previous generation are not current.
func TestLoadBalancerProvisioningConditionCurrent(t *testing.T) {
	t.Parallel()

	for _, setup := range []func(*regionv1.LoadBalancer){
		func(*regionv1.LoadBalancer) {},
		func(loadBalancer *regionv1.LoadBalancer) {
			unikornv1core.UpdateCondition(&loadBalancer.Status.Conditions, unikornv1core.ConditionAvailable, corev1.ConditionTrue, string(unikornv1core.ConditionReasonProvisioned), "provisioned")
		},
		func(loadBalancer *regionv1.LoadBalancer) {
			loadBalancer.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "provisioned")
			loadBalancer.Generation = 2
		},
	} {
		loadBalancer := &regionv1.LoadBalancer{ObjectMeta: metav1.ObjectMeta{Generation: 1}}
		setup(loadBalancer)
		require.False(t, loadBalancer.ProvisioningConditionCurrent())
	}
}

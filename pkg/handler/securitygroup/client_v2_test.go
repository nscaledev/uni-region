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

package securitygroup_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/securitygroup"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

func TestValidation(t *testing.T) {
	t.Parallel()

	portStart := 1000
	portEnd := 2000
	prefix := "10.0.0.0/8"

	tests := []struct {
		name     string
		rule     *openapi.SecurityGroupRuleV2
		expected *regionv1.SecurityGroupRule
		fail     bool
	}{
		{
			name: "Allow Any Ingress Protocol From Anywhere",
			rule: &openapi.SecurityGroupRuleV2{
				Direction: openapi.Ingress,
				Protocol:  openapi.NetworkProtocolAny,
			},
			expected: &regionv1.SecurityGroupRule{
				Direction: regionv1.Ingress,
				Protocol:  regionv1.Any,
			},
		},
		{
			name: "Allow Any Ingress Protocol From a Prefix",
			rule: &openapi.SecurityGroupRuleV2{
				Direction: openapi.Ingress,
				Protocol:  openapi.NetworkProtocolAny,
				Prefix:    &prefix,
			},
			expected: &regionv1.SecurityGroupRule{
				Direction: regionv1.Ingress,
				Protocol:  regionv1.Any,
				CIDR: &corev1.IPv4Prefix{
					IPNet: net.IPNet{
						IP:   net.IP{10, 0, 0, 0},
						Mask: net.IPMask{255, 0, 0, 0},
					},
				},
			},
		},
		{
			name: "Reject Any Ingress Protocol From Anywhere With a Port",
			rule: &openapi.SecurityGroupRuleV2{
				Direction: openapi.Ingress,
				Protocol:  openapi.NetworkProtocolAny,
				Port:      &portStart,
			},
			fail: true,
		},
		{
			name: "Allow Layer 4 Ingress Protocol From Anywhere With a Port",
			rule: &openapi.SecurityGroupRuleV2{
				Direction: openapi.Ingress,
				Protocol:  openapi.NetworkProtocolTcp,
				Port:      &portStart,
			},
			expected: &regionv1.SecurityGroupRule{
				Direction: regionv1.Ingress,
				Protocol:  regionv1.TCP,
				Port: &regionv1.SecurityGroupRulePort{
					Number: &portStart,
				},
			},
		},
		{
			name: "Allow Layer 4 Ingress Protocol From Anywhere With a Port Range",
			rule: &openapi.SecurityGroupRuleV2{
				Direction: openapi.Ingress,
				Protocol:  openapi.NetworkProtocolTcp,
				Port:      &portStart,
				PortMax:   &portEnd,
			},
			expected: &regionv1.SecurityGroupRule{
				Direction: regionv1.Ingress,
				Protocol:  regionv1.TCP,
				Port: &regionv1.SecurityGroupRulePort{
					Range: &regionv1.SecurityGroupRulePortRange{
						Start: portStart,
						End:   portEnd,
					},
				},
			},
		},
		{
			name: "Regect Layer 4 Ingress Protocol From Anywhere With an Invalid Port Range",
			rule: &openapi.SecurityGroupRuleV2{
				Direction: openapi.Ingress,
				Protocol:  openapi.NetworkProtocolTcp,
				Port:      &portEnd,
				PortMax:   &portStart,
			},
			fail: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result, err := securitygroup.GenerateRule(test.rule)

			if test.fail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expected, result)
			}
		})
	}
}

// TestRulesRequired tests that, as it is marked as a required field in the OpenAPI
// specification, rule conversion of an empty list always returns an empty slice
// (as opposed to nil), that will be emitted in the response body.
func TestRulesRequired(t *testing.T) {
	t.Parallel()

	out := securitygroup.ConvertRuleListV2(nil)
	require.NotNil(t, out)
	require.Empty(t, out)
}

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

package v1alpha1

import (
	"maps"
	"regexp"
	"slices"
	"strings"
)

// tagKeyRegex matches a namespaced tag name "<service>.<domain>/<local-name>",
// capturing the service and the local name.
var tagKeyRegex = regexp.MustCompile(
	`^([a-z0-9][a-z0-9-]*)\.[^/]+/([a-z0-9][a-z0-9-]*)$`,
)

// MetadataKey converts a namespaced tag name of the form
// "<service>.unikorn-cloud.org/<local-name>" into the instance metadata key
// "<service>:<local_name>", returning false if the name does not match the
// schema. It is the one rule for every value the region publishes as instance
// metadata under a service's namespace.
func MetadataKey(name string) (string, bool) {
	m := tagKeyRegex.FindStringSubmatch(name)
	if m == nil {
		return "", false
	}

	return m[1] + ":" + strings.ReplaceAll(m[2], "-", "_"), true
}

// ProviderCreateGateOutputKey returns the instance metadata key an output is
// published under: its key named as a tag would be under the gate's own
// "<service>.<domain>/", so "pkey" on
// "fabric.unikorn-cloud.org/partition-ready" is "fabric:pkey". It is false
// when the condition type has no such prefix, or the key is not a tag's local
// name.
func ProviderCreateGateOutputKey(conditionType, key string) (string, bool) {
	domain, _, ok := strings.Cut(conditionType, "/")
	if !ok {
		return "", false
	}

	return MetadataKey(domain + "/" + key)
}

// ProviderCreateGateOutputMetadata returns the outputs of every Open
// gate as instance metadata. Gates are taken in spec order, and a later
// gate's key replaces an earlier one's, as a later tag's does. Outputs that
// map to no metadata key are returned as "<conditionType>: <key>" for the
// caller to report: the API refuses them, so they can only come from a status
// written another way.
func (c *Server) ProviderCreateGateOutputMetadata() (map[string]string, []string) {
	metadata := map[string]string{}

	var unmapped []string

	for _, gate := range c.Spec.ProviderCreateGates {
		status, ok := c.ProviderCreateGateStatusRead(gate.ConditionType)
		if !ok || status.State != ServerProviderCreateGateOpen {
			continue
		}

		for _, key := range slices.Sorted(maps.Keys(status.Outputs)) {
			name, ok := ProviderCreateGateOutputKey(gate.ConditionType, key)
			if !ok {
				unmapped = append(unmapped, gate.ConditionType+": "+key)

				continue
			}

			metadata[name] = status.Outputs[key]
		}
	}

	return metadata, unmapped
}

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
	"regexp"
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

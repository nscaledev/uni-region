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

package volume_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	rbacv1 "k8s.io/api/rbac/v1"

	"sigs.k8s.io/yaml"
)

func TestVolumeControllerHelmRBAC(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm binary not available")
	}

	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)

	chart := filepath.Join(filepath.Dir(filename), "..", "..", "..", "charts", "region")
	command := exec.CommandContext(t.Context(), "helm", "template", "test", chart, "--show-only", "templates/volume-controller/clusterrole.yaml")
	output, err := command.CombinedOutput()
	require.NoErrorf(t, err, "helm template failed: %s", output)

	role := &rbacv1.ClusterRole{}
	require.NoError(t, yaml.Unmarshal(output, role))

	verbs := map[string][]string{}

	for _, rule := range role.Rules {
		for _, resource := range rule.Resources {
			verbs[resource] = append(verbs[resource], rule.Verbs...)
		}
	}

	expected := map[string][]string{
		"servers":        {"list", "watch", "update"},
		"servers/status": {"update"},
	}

	for resource, want := range expected {
		require.ElementsMatchf(t, want, verbs[resource], "rendered Volume controller ClusterRole rule for %q", resource)
	}
}

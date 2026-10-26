#!/usr/bin/env bash
# Copyright 2026 Nscale.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Chart render assertions: RBAC for the API server ClusterRole, and the
# metrics ports. Reads go directly to the API server, so every kind read
# singly needs a get permission, no kind needs watch, and Secrets are only
# ever read.
# `make lint` runs this script.
set -euo pipefail

die() { echo "FAIL: $*" >&2; exit 1; }

out=$(helm template test charts/region)

# server_verbs prints the sorted verbs the server role grants on a resource.
server_verbs() {
	resource="$1" yq -r '
		select(.kind == "ClusterRole" and .metadata.name == "test-server") |
		.rules[] |
		select(.resources[] == strenv(resource)) |
		.verbs[]
	' <<<"$out" | sort -u | paste -sd, -
}

# Direct reads require get; list and watch cannot authorize an API-server GET.
for resource in \
	filestorageclasses filestorages filestoragesnapshots identities loadbalancers \
	networks openstackidentities regions securitygroups servers \
	sshcertificateauthorities volumes; do
	[[ "$(server_verbs "$resource")" == *get* ]] || die "expected get on $resource for the server"
done

# No informers are run, so no kind may be watched.
if yq -r '
	select(.kind == "ClusterRole" and .metadata.name == "test-server") |
	.rules[] | select(.verbs[] == "watch") | .resources[]
' <<<"$out" | grep -q .; then
	die "expected no watch verbs for the server"
fi

# Secrets are only ever read, one GET at a time.
[[ "$(server_verbs secrets)" == "get" ]] || die "expected only get on secrets for the server"

# The shared PodMonitor scrapes the container port named prometheus, and the
# service name on traces is set in code, not by OTEL_SERVICE_NAME.
for deployment in server monitor identity-controller load-balancer-controller \
	network-controller security-group-controller server-controller volume-controller; do
	port=$(deployment="test-$deployment" yq -r '
		select(.kind == "Deployment" and .metadata.name == strenv(deployment)) |
		.spec.template.spec.containers[].ports[] | select(.name == "prometheus") | .containerPort
	' <<<"$out")
	[[ "$port" == "8080" ]] || die "expected a prometheus port 8080 on $deployment, got '$port'"
done

if yq -r 'select(.kind == "Deployment") | .spec.template.spec.containers[].env[]?.name' <<<"$out" | grep -qx OTEL_SERVICE_NAME; then
	die "expected no OTEL_SERVICE_NAME"
fi

echo "chart render checks OK"

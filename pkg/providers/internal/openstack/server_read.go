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

package openstack

import (
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
)

// serverLists keeps each project's Nova servers.  One reader per project,
// shared across credentials: a pinned server is created with the Region admin
// credential and read with the service principal's, both scoped to one
// project, and both see the same rows.  See the README's Kept Lists section.
//
//nolint:gochecknoglobals
var serverLists = newKeptLists[servers.Server]("server list")

// RetireServerLists stops every server list of the project opened before now
// answering a later read.  Deferred by the Nova server mutations, so it runs
// once the request has returned, whether or not it succeeded: a failed request
// may still have been acted on.
func (c *ComputeClient) RetireServerLists() {
	serverLists.retire(c.projectID)
}

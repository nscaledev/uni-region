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
	"context"

	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
)

// Every server in a project reads the same network and security groups each
// pass, so these are kept per project.  Per project and user, not project
// alone: Neutron shows an admin fields a member does not see, such as the
// segmentation ID.  See the README's Kept Lists section.
//
//nolint:gochecknoglobals
var (
	networkLists       = newKeptLists[NetworkExt]("network list")
	securityGroupLists = newKeptLists[groups.SecGroup]("security group list")
)

// retireLists stops every network and security group list of the project
// opened before now answering a later read.  Deferred by every Neutron write,
// so it runs once the request has returned, whether or not it succeeded.
func (c *NetworkClient) retireLists() {
	networkLists.retire(c.projectID)
	securityGroupLists.retire(c.projectID)
}

// listNetworks lists the project's own networks.  Filtered by project because
// an admin token lists every project's.
func (c *NetworkClient) listNetworks(projectID string) func(context.Context) ([]NetworkExt, error) {
	return func(ctx context.Context) ([]NetworkExt, error) {
		page, err := networks.List(c.client, &networks.ListOpts{ProjectID: projectID}).AllPages(ctx)
		if err != nil {
			return nil, err
		}

		var result []NetworkExt

		if err := networks.ExtractNetworksInto(page, &result); err != nil {
			return nil, err
		}

		return result, nil
	}
}

// listSecurityGroups lists the project's own security groups, filtered as
// listNetworks is.
func (c *NetworkClient) listSecurityGroups(projectID string) func(context.Context) ([]groups.SecGroup, error) {
	return func(ctx context.Context) ([]groups.SecGroup, error) {
		page, err := groups.List(c.client, groups.ListOpts{ProjectID: projectID}).AllPages(ctx)
		if err != nil {
			return nil, err
		}

		return groups.ExtractGroups(page)
	}
}

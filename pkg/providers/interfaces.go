/*
Copyright 2024 the Unikorn Authors.

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

package providers

import (
	"context"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

// Providers are expected to provide a provider agnostic manner.
// They are also expected to provide any caching or memoization required
// to provide high performance and a decent UX.
type Provider interface {
	// Region returns the provider's region.
	Region(ctx context.Context) (*unikornv1.Region, error)
	// Flavors list all available flavors.
	Flavors(ctx context.Context) (FlavorList, error)
	// Images lists all available images.
	Images(ctx context.Context) (ImageList, error)
	// CreateIdentity creates a new identity for cloud infrastructure.
	CreateIdentity(ctx context.Context, identity *unikornv1.Identity) error
	// DeleteIdentity cleans up an identity for cloud infrastructure.
	DeleteIdentity(ctx context.Context, identity *unikornv1.Identity) error
	// CreatePhysicalNetwork creates a new physical network.
	CreatePhysicalNetwork(ctx context.Context, identity *unikornv1.Identity, physicalNetwork *unikornv1.PhysicalNetwork) error
	// DeletePhysicalNetwork deletes a physical network.
	DeletePhysicalNetwork(ctx context.Context, identity *unikornv1.Identity, physicalNetwork *unikornv1.PhysicalNetwork) error
	// ListExternalNetworks returns a list of external networks if the platform
	// supports such a concept.
	ListExternalNetworks(ctx context.Context) (ExternalNetworks, error)
	// CreateSecurityGroup creates a new security group.
	CreateSecurityGroup(ctx context.Context, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup) error
	// DeleteSecurityGroup deletes a security group.
	DeleteSecurityGroup(ctx context.Context, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup) error
	// CreateSecurityGroupRule creates a new security group rule.
	CreateSecurityGroupRule(ctx context.Context, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup, rule *unikornv1.SecurityGroupRule) error
	// DeleteSecurityGroupRule deletes a security group rule.
	DeleteSecurityGroupRule(ctx context.Context, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup, rule *unikornv1.SecurityGroupRule) error
}

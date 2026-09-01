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

package server

import (
	"context"
	"fmt"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/saga"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/network"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type createV2Saga struct {
	client  *ClientV2
	request *openapi.ServerV2Create

	network        *regionv1.Network
	organizationID identityids.OrganizationID
	projectID      identityids.ProjectID
	server         *regionv1.Server
}

func (s *createV2Saga) resolveNetwork(ctx context.Context) error {
	network, err := network.New(s.client.Client.ClientArgs).GetV2Raw(ctx, s.request.Spec.NetworkId.String())
	if err != nil {
		return err
	}

	organizationID, projectID, err := network.OrganizationAndProjectID()
	if err != nil {
		return err
	}

	s.network = network
	s.organizationID = organizationID
	s.projectID = projectID

	return nil
}

func (s *createV2Saga) authorize(ctx context.Context) error {
	return rbac.AllowProjectScopeCreateID(ctx, s.client.Identity, "region:servers", identityapi.Create, s.organizationID, s.projectID)
}

func (s *createV2Saga) validate(ctx context.Context) error {
	return s.client.validateCreateV2Request(ctx, s.request, s.network)
}

func (s *createV2Saga) generate(ctx context.Context) error {
	request, err := convertCreateToUpdateRequest(s.request)
	if err != nil {
		return err
	}

	server, err := s.client.generateV2(ctx, s.organizationID, s.projectID, request, s.network, s.request.Spec.SshCertificateAuthorityId, s.request.Spec.InfrastructureRef, resolveSSHInjection(s.request.Spec.SshInjection, s.request.Spec.SshCertificateAuthorityId), generateProviderCreateGates(s.request.Spec.ProviderCreateGates))
	if err != nil {
		return err
	}

	s.server = server

	return nil
}

func (s *createV2Saga) create(ctx context.Context) error {
	if err := s.client.Client.Client.Create(ctx, s.server); err != nil {
		if kerrors.IsAlreadyExists(err) {
			return errors.HTTPConflict()
		}

		return fmt.Errorf("%w: unable to create server", err)
	}

	return nil
}

// Actions leave a reversible-action seam immediately before create for future
// claims; create is terminal because the controller owns cleanup afterwards.
func (s *createV2Saga) Actions() []saga.Action {
	return []saga.Action{
		saga.NewAction("resolve network", s.resolveNetwork, nil),
		saga.NewAction("authorize create", s.authorize, nil),
		saga.NewAction("validate request", s.validate, nil),
		saga.NewAction("generate server", s.generate, nil),
		saga.NewAction("create server", s.create, nil),
	}
}

type updateV2Saga struct {
	client   *ClientV2
	serverID regionids.ServerID
	request  *openapi.ServerV2Update

	current        *regionv1.Server
	network        *regionv1.Network
	organizationID identityids.OrganizationID
	projectID      identityids.ProjectID
	updated        *regionv1.Server
}

func (s *updateV2Saga) getCurrent(ctx context.Context) error {
	current, err := s.client.GetV2Raw(ctx, s.serverID.String())
	if err != nil {
		return err
	}

	organizationID, projectID, err := current.OrganizationAndProjectID()
	if err != nil {
		return err
	}

	s.current = current
	s.organizationID = organizationID
	s.projectID = projectID

	return nil
}

func (s *updateV2Saga) authorize(ctx context.Context) error {
	return rbac.AllowProjectScopeID(ctx, "region:servers", identityapi.Update, s.organizationID, s.projectID)
}

func (s *updateV2Saga) validateImmutability(context.Context) error {
	return validateServerUpdate(s.current, s.request)
}

func (s *updateV2Saga) validateSecurityGroups(ctx context.Context) error {
	return s.client.validateSecurityGroupReferences(ctx, s.current.Labels[constants.NetworkLabel], s.request.Spec.Networking)
}

func (s *updateV2Saga) resolveNetwork(ctx context.Context) error {
	network, err := network.New(s.client.Client.ClientArgs).GetV2Raw(ctx, s.current.Spec.Networks[0].ID.String())
	if err != nil {
		return err
	}

	s.network = network

	return nil
}

func (s *updateV2Saga) validate(ctx context.Context) error {
	return s.client.validateUpdateV2Request(ctx, s.network, s.current, s.request)
}

func (s *updateV2Saga) generate(ctx context.Context) error {
	required, err := s.client.generateV2(ctx, s.organizationID, s.projectID, s.request, s.network, s.current.Spec.SSHCertificateAuthorityID, s.current.Spec.InfrastructureRef, s.current.ResolvedSSHInjection(), s.current.Spec.ProviderCreateGates)
	if err != nil {
		return err
	}

	s.updated = s.current.DeepCopy()
	s.updated.Labels = required.Labels
	s.updated.Annotations = required.Annotations
	s.updated.Spec = required.Spec

	return nil
}

func (s *updateV2Saga) update(ctx context.Context) error {
	if err := s.client.Client.Client.Patch(ctx, s.updated, client.MergeFromWithOptions(s.current, &client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("%w: unable to update server", err)
	}

	return nil
}

// Actions leave a reversible-action seam immediately before update for future
// claim changes; update is terminal because the persisted server is controller-owned.
func (s *updateV2Saga) Actions() []saga.Action {
	return []saga.Action{
		saga.NewAction("get server", s.getCurrent, nil),
		saga.NewAction("authorize update", s.authorize, nil),
		saga.NewAction("validate immutable fields", s.validateImmutability, nil),
		saga.NewAction("validate security groups", s.validateSecurityGroups, nil),
		saga.NewAction("resolve network", s.resolveNetwork, nil),
		saga.NewAction("validate request", s.validate, nil),
		saga.NewAction("generate server", s.generate, nil),
		saga.NewAction("update server", s.update, nil),
	}
}

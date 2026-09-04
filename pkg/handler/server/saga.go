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
	"slices"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
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

func validateVolumes(ctx context.Context, c *ClientV2, network *regionv1.Network, flavorID string, requested *openapi.ServerV2VolumeList, serverID string) (map[string]*regionv1.Volume, error) {
	volumes := map[string]*regionv1.Volume{}

	if requested == nil || len(*requested) == 0 {
		return volumes, nil
	}

	region := &regionv1.Region{}
	if err := c.Client.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: network.Labels[constants.RegionLabel]}, region); err != nil {
		return nil, fmt.Errorf("%w: unable to lookup region", err)
	}

	for _, id := range *requested {
		key := id.String()

		if _, ok := volumes[key]; ok {
			return nil, errors.HTTPUnprocessableContent("volumes must not contain duplicate IDs")
		}

		volume, err := validateVolume(ctx, c, network, region, flavorID, key, serverID)
		if err != nil {
			return nil, err
		}

		volumes[key] = volume
	}

	return volumes, nil
}

func validateVolume(ctx context.Context, c *ClientV2, network *regionv1.Network, region *regionv1.Region, flavorID, volumeID, serverID string) (*regionv1.Volume, error) {
	volume := &regionv1.Volume{}
	if err := c.Client.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: volumeID}, volume); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: unable to lookup volume", err)
	}

	if volume.DeletionTimestamp != nil {
		return nil, errors.HTTPUnprocessableContent("volume is being deleted")
	}

	for _, label := range []string{constants.RegionLabel, constants.IdentityLabel, coreconstants.OrganizationLabel, coreconstants.ProjectLabel} {
		if volume.Labels[label] != network.Labels[label] {
			return nil, errors.HTTPUnprocessableContent("volume must have the same Region, Identity, organization, and project as the Server")
		}
	}

	if claim := volume.Spec.ClaimRef; claim != nil && (claim.Kind != regionv1.VolumeClaimKindServer || claim.ID != serverID) {
		return nil, errors.HTTPUnprocessableContent("volume is attached to another server")
	}

	if !volumeClassSupportsFlavor(region, volume.Spec.VolumeClassID, flavorID) {
		return nil, errors.HTTPUnprocessableContent("volume class does not support the server flavor")
	}

	return volume, nil
}

func currentVolumes(ctx context.Context, c *ClientV2, ids []string, serverID string) (map[string]*regionv1.Volume, error) {
	volumes := map[string]*regionv1.Volume{}

	for _, id := range ids {
		volume := &regionv1.Volume{}
		if err := c.Client.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: id}, volume); err != nil {
			return nil, fmt.Errorf("%w: unable to lookup current volume", err)
		}

		if claim := volume.Spec.ClaimRef; claim != nil && (claim.Kind != regionv1.VolumeClaimKindServer || claim.ID != serverID) {
			return nil, errors.HTTPUnprocessableContent("volume is attached to another server")
		}

		volumes[id] = volume
	}

	return volumes, nil
}

func volumeClassSupportsFlavor(region *regionv1.Region, volumeClassID, flavorID string) bool {
	if region.Spec.Openstack == nil || region.Spec.Openstack.BlockStorage == nil || region.Spec.Openstack.BlockStorage.VolumeClasses == nil {
		return true
	}

	for _, class := range region.Spec.Openstack.BlockStorage.VolumeClasses.Metadata {
		if class.ID == volumeClassID {
			if class.SupportedFlavors == nil || len(class.SupportedFlavors.IDs) == 0 {
				return true
			}

			flavor, err := regionids.ParseFlavorID(flavorID)

			return err == nil && slices.Contains(class.SupportedFlavors.IDs, flavor)
		}
	}

	return true
}

func setClaims(ctx context.Context, c *ClientV2, volumes map[string]*regionv1.Volume, serverID string) error {
	changed := make([]struct{ before, after *regionv1.Volume }, 0, len(volumes))

	for _, volume := range volumes {
		before := volume.DeepCopy()
		after := volume.DeepCopy()

		if serverID == "" {
			after.Spec.ClaimRef = nil
		} else {
			after.Spec.ClaimRef = &regionv1.VolumeClaimRef{Kind: regionv1.VolumeClaimKindServer, ID: serverID}
		}

		if err := c.Client.Client.Patch(ctx, after, client.MergeFromWithOptions(before, &client.MergeFromWithOptimisticLock{})); err != nil {
			for _, change := range slices.Backward(changed) {
				_ = c.Client.Client.Patch(ctx, change.before, client.MergeFromWithOptions(change.after, &client.MergeFromWithOptimisticLock{}))
			}

			return fmt.Errorf("%w: unable to update volume claim", err)
		}

		changed = append(changed, struct{ before, after *regionv1.Volume }{before, after})
		*volume = *after
	}

	return nil
}

func (s *createV2Saga) requestVolumes() *openapi.ServerV2VolumeList {
	return s.request.Spec.Volumes
}

type createV2Saga struct {
	client  *ClientV2
	request *openapi.ServerV2Create

	network        *regionv1.Network
	organizationID identityids.OrganizationID
	projectID      identityids.ProjectID
	server         *regionv1.Server
	volumes        map[string]*regionv1.Volume
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
	if err := s.client.validateCreateV2Request(ctx, s.request, s.network); err != nil {
		return err
	}

	volumes, err := validateVolumes(ctx, s.client, s.network, s.request.Spec.FlavorId.String(), s.requestVolumes(), "")
	if err != nil {
		return err
	}

	s.volumes = volumes

	return nil
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

func (s *createV2Saga) claim(ctx context.Context) error {
	return setClaims(ctx, s.client, s.volumes, s.server.Name)
}

func (s *createV2Saga) release(ctx context.Context) error {
	return setClaims(ctx, s.client, s.volumes, "")
}

// Actions claim Volumes before persisting Server intent. A failed final Server
// write compensates the claims, but has no Server compensation of its own.
func (s *createV2Saga) Actions() []saga.Action {
	return []saga.Action{
		saga.NewAction("resolve network", s.resolveNetwork, nil),
		saga.NewAction("authorize create", s.authorize, nil),
		saga.NewAction("validate request", s.validate, nil),
		saga.NewAction("generate server", s.generate, nil),
		saga.NewAction("claim volumes", s.claim, s.release),
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
	removed        map[string]*regionv1.Volume
	added          map[string]*regionv1.Volume
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
	if err := s.client.validateUpdateV2Request(ctx, s.network, s.current, s.request); err != nil {
		return err
	}

	if s.request.Spec.Volumes == nil {
		return nil
	}

	volumes, err := validateVolumes(ctx, s.client, s.network, s.request.Spec.FlavorId.String(), s.request.Spec.Volumes, s.current.Name)
	if err != nil {
		return err
	}

	current := volumeIDs(s.current.Spec.Volumes)

	stored, err := currentVolumes(ctx, s.client, current, s.current.Name)
	if err != nil {
		return err
	}

	for id, volume := range stored {
		volumes[id] = volume
	}

	requestedIDs := volumeIDs(generateVolumes(s.request.Spec.Volumes))
	s.removed = selectVolumes(volumes, current, requestedIDs, false)
	s.added = selectVolumes(volumes, current, requestedIDs, true)

	return nil
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

	if s.request.Spec.Volumes == nil {
		s.updated.Spec.Volumes = s.current.Spec.Volumes
	}

	return nil
}

func (s *updateV2Saga) revert(ctx context.Context) error {
	return s.client.Client.Client.Patch(ctx, s.current, client.MergeFromWithOptions(s.updated, &client.MergeFromWithOptimisticLock{}))
}

func (s *updateV2Saga) release(ctx context.Context) error {
	return setClaims(ctx, s.client, s.removed, "")
}

func (s *updateV2Saga) reclaim(ctx context.Context) error {
	return setClaims(ctx, s.client, s.removed, s.current.Name)
}

func (s *updateV2Saga) claim(ctx context.Context) error {
	return setClaims(ctx, s.client, s.added, s.current.Name)
}

func (s *updateV2Saga) unclaim(ctx context.Context) error {
	return setClaims(ctx, s.client, s.added, "")
}

func (s *updateV2Saga) update(ctx context.Context) error {
	if err := s.client.Client.Client.Patch(ctx, s.updated, client.MergeFromWithOptions(s.current, &client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("%w: unable to update server", err)
	}

	return nil
}

// Actions release, persist, and claim in order so the persisted Server desired
// set and the internal Volume reservations converge together on failure too.
func (s *updateV2Saga) Actions() []saga.Action {
	return []saga.Action{
		saga.NewAction("get server", s.getCurrent, nil),
		saga.NewAction("authorize update", s.authorize, nil),
		saga.NewAction("validate immutable fields", s.validateImmutability, nil),
		saga.NewAction("validate security groups", s.validateSecurityGroups, nil),
		saga.NewAction("resolve network", s.resolveNetwork, nil),
		saga.NewAction("validate request", s.validate, nil),
		saga.NewAction("generate server", s.generate, nil),
		saga.NewAction("release removed volume claims", s.release, s.reclaim),
		saga.NewAction("update server", s.update, s.revert),
		saga.NewAction("claim added volumes", s.claim, s.unclaim),
	}
}

func volumeIDs(volumes []regionv1.ServerVolumeSpec) []string {
	ids := make([]string, len(volumes))

	for i := range volumes {
		ids[i] = volumes[i].ID
	}

	return ids
}

func selectVolumes(volumes map[string]*regionv1.Volume, current, requested []string, additions bool) map[string]*regionv1.Volume {
	selected := map[string]*regionv1.Volume{}

	for id, volume := range volumes {
		if slices.Contains(requested, id) != slices.Contains(current, id) && slices.Contains(requested, id) == additions {
			selected[id] = volume
		}
	}

	return selected
}

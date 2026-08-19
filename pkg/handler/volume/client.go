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

package volume

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"slices"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/saga"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	identitycommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/network"
	"github.com/unikorn-cloud/region/pkg/handler/util"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const endpoint = "region:volumes:v2"

// Client implements the v2 Volume lifecycle API.
type Client struct {
	common.ClientArgs
}

// New creates a Volume client.
func New(args common.ClientArgs) *Client {
	return &Client{ClientArgs: args}
}

func sizeGiB(quantity resource.Quantity) int64 {
	return quantity.Value() / (1 << 30)
}

func convertV2(in *regionv1.Volume) (*openapi.VolumeV2Read, error) {
	regionID, err := in.RegionID()
	if err != nil {
		return nil, err
	}

	networkID, err := in.NetworkID()
	if err != nil {
		return nil, err
	}

	out := &openapi.VolumeV2Read{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.VolumeV2Spec{
			SizeGiB:       sizeGiB(in.Spec.Size),
			NetworkId:     networkID,
			VolumeClassId: in.Spec.VolumeClassID,
		},
		Status: openapi.VolumeV2Status{
			RegionId: regionID,
		},
	}

	if in.Status.Size != nil {
		out.Status.SizeGiB = ptr.To(sizeGiB(*in.Status.Size))
	}

	return out, nil
}

func convertV2List(in *regionv1.VolumeList) (openapi.VolumesV2Read, error) {
	out := make(openapi.VolumesV2Read, len(in.Items))

	for i := range in.Items {
		volume, err := convertV2(&in.Items[i])
		if err != nil {
			return nil, err
		}

		out[i] = *volume
	}

	return out, nil
}

// ListV2 lists visible v2 Volumes.
func (c *Client) ListV2(ctx context.Context, params openapi.GetApiV2VolumesParams) (openapi.VolumesV2Read, error) {
	selector := labels.SelectorFromSet(map[string]string{
		constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
	})

	var err error

	selector, err = rbac.AddOrganizationAndProjectIDQuery(ctx, selector, util.OrganizationIDQuery(params.OrganizationID), util.ProjectIDQuery(params.ProjectID))
	if err != nil {
		if rbac.HasNoMatches(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("%w: failed to add identity label selector", err)
	}

	selector, err = util.AddRegionIDQuery(selector, params.RegionID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to add region label selector", err)
	}

	selector, err = util.AddNetworkIDQuery(selector, params.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to add network label selector", err)
	}

	result := &regionv1.VolumeList{}
	if err := c.Client.List(ctx, result, &client.ListOptions{Namespace: c.Namespace, LabelSelector: selector}); err != nil {
		return nil, fmt.Errorf("%w: unable to list volumes", err)
	}

	tagSelector, err := coreutil.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource regionv1.Volume) bool {
		return !resource.Spec.Tags.ContainsAll(tagSelector) || rbac.AllowProjectScopeReader(ctx, endpoint, identityapi.Read, &resource) != nil
	})

	slices.SortStableFunc(result.Items, func(a, b regionv1.Volume) int {
		return cmp.Or(
			cmp.Compare(a.Labels[coreconstants.NameLabel], b.Labels[coreconstants.NameLabel]),
			cmp.Compare(a.Name, b.Name),
		)
	})

	return convertV2List(result)
}

// GetV2Raw retrieves and authorizes a v2 Volume.
func (c *Client) GetV2Raw(ctx context.Context, volumeID string) (*regionv1.Volume, error) {
	result := &regionv1.Volume{}

	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: volumeID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: unable to lookup volume", err)
	}

	if err := rbac.AllowProjectScopeReader(ctx, endpoint, identityapi.Read, result); err != nil {
		return nil, err
	}

	version, err := constants.UnmarshalAPIVersion(result.Labels[constants.ResourceAPIVersionLabel])
	if err != nil || version != 2 {
		return nil, errors.HTTPNotFound()
	}

	return result, nil
}

// GetV2 gets a v2 Volume.
func (c *Client) GetV2(ctx context.Context, volumeID regionids.VolumeID) (*openapi.VolumeV2Read, error) {
	result, err := c.GetV2Raw(ctx, volumeID.String())
	if err != nil {
		return nil, err
	}

	return convertV2(result)
}

func requestedSize(sizeGiB int64) (resource.Quantity, error) {
	if sizeGiB > math.MaxInt64/(1<<30) {
		return resource.Quantity{}, errors.HTTPUnprocessableContent("sizeGiB exceeds the supported maximum")
	}

	return *resource.NewQuantity(sizeGiB*(1<<30), resource.BinarySI), nil
}

func (c *Client) validateVolumeClass(ctx context.Context, regionID, volumeClassID string, sizeGiB int64) error {
	provider, err := c.Providers.LookupCommon(regionID)
	if err != nil {
		return providers.ProviderToServerError(err)
	}

	classes, err := provider.VolumeClasses(ctx)
	if err != nil {
		return fmt.Errorf("%w: failed to list volume classes", err)
	}

	for i := range classes {
		class := &classes[i]
		if class.ID != volumeClassID {
			continue
		}

		if class.MinimumSizeGiB != nil && sizeGiB < *class.MinimumSizeGiB {
			return errors.HTTPUnprocessableContent("sizeGiB is below the VolumeClass minimum")
		}

		if class.MaximumSizeGiB != nil && sizeGiB > *class.MaximumSizeGiB {
			return errors.HTTPUnprocessableContent("sizeGiB exceeds the VolumeClass maximum")
		}

		return nil
	}

	return errors.HTTPUnprocessableContent("volumeClassId is not available in the Network's Region")
}

func (c *Client) generate(ctx context.Context, organizationID identityids.OrganizationID, projectID identityids.ProjectID, metadata *openapi.VolumeV2Update, network *regionv1.Network, volumeClassID string, size resource.Quantity) (*regionv1.Volume, error) {
	out := &regionv1.Volume{
		ObjectMeta: conversion.NewObjectMetadata(&metadata.Metadata, c.Namespace).
			WithLabel(constants.RegionLabel, network.Labels[constants.RegionLabel]).
			WithLabel(constants.IdentityLabel, network.Labels[constants.IdentityLabel]).
			WithLabel(constants.NetworkLabel, network.Name).
			WithLabel(constants.ResourceAPIVersionLabel, constants.MarshalAPIVersion(2)).
			Get(),
		Spec: regionv1.VolumeSpec{
			Tags:          conversion.GenerateTagList(metadata.Metadata.Tags),
			NetworkID:     network.Name,
			VolumeClassID: volumeClassID,
			Size:          size,
		},
	}

	if err := identitycommon.SetIdentityMetadataProjectScope(ctx, &out.ObjectMeta, organizationID, projectID); err != nil {
		return nil, fmt.Errorf("%w: failed to set identity metadata", err)
	}

	if err := controllerutil.SetOwnerReference(network, out, c.Client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		return nil, fmt.Errorf("%w: unable to set resource owner", err)
	}

	return out, nil
}

type createSaga struct {
	client *Client
	volume *regionv1.Volume
}

func (s *createSaga) createAllocation(ctx context.Context) error {
	return identityclient.NewAllocations(s.client.Client, s.client.Identity).Create(ctx, s.volume, identityapi.ResourceAllocationList{{
		Kind:      "volumes",
		Committed: int(s.volume.Spec.Size.Value()),
	}})
}

func (s *createSaga) deleteAllocation(ctx context.Context) error {
	return identityclient.NewAllocations(s.client.Client, s.client.Identity).Delete(ctx, s.volume)
}

func (s *createSaga) createVolume(ctx context.Context) error {
	if err := s.client.Client.Create(ctx, s.volume); err != nil {
		return fmt.Errorf("%w: unable to create volume", err)
	}

	return nil
}

func (s *createSaga) Actions() []saga.Action {
	return []saga.Action{
		saga.NewAction("create quota allocation", s.createAllocation, s.deleteAllocation),
		saga.NewAction("create volume", s.createVolume, nil),
	}
}

// CreateV2 creates a v2 Volume from Network-derived scope.
func (c *Client) CreateV2(ctx context.Context, request *openapi.VolumeV2Create) (*openapi.VolumeV2Read, error) {
	network, err := network.New(c.ClientArgs).GetV2Raw(ctx, request.Spec.NetworkId.String())
	if err != nil {
		return nil, err
	}

	organizationID, projectID, err := network.OrganizationAndProjectID()
	if err != nil {
		return nil, err
	}

	if err := principal.EnrichUserPrincipalProjectScopeReader(ctx, network); err != nil {
		return nil, fmt.Errorf("%w: unable to set principal information", err)
	}

	if err := rbac.AllowProjectScopeCreateID(ctx, c.Identity, endpoint, identityapi.Create, organizationID, projectID); err != nil {
		return nil, err
	}

	regionID := network.Labels[constants.RegionLabel]
	if err := c.validateVolumeClass(ctx, regionID, request.Spec.VolumeClassId, request.Spec.SizeGiB); err != nil {
		return nil, err
	}

	size, err := requestedSize(request.Spec.SizeGiB)
	if err != nil {
		return nil, err
	}

	resource, err := c.generate(ctx, organizationID, projectID, &openapi.VolumeV2Update{Metadata: request.Metadata}, network, request.Spec.VolumeClassId, size)
	if err != nil {
		return nil, err
	}

	// Add the finalizer before the controller can observe the resource, as required by specification §7.2.
	resource.Finalizers = []string{coreconstants.Finalizer}

	if err := saga.Run(ctx, &createSaga{client: c, volume: resource}); err != nil {
		return nil, err
	}

	return convertV2(resource)
}

func (c *Client) generateUpdate(ctx context.Context, current *regionv1.Volume, request *openapi.VolumeV2Update) (*regionv1.Volume, error) {
	organizationID, projectID, err := current.OrganizationAndProjectID()
	if err != nil {
		return nil, err
	}

	network, err := network.New(c.ClientArgs).GetV2Raw(ctx, current.Spec.NetworkID)
	if err != nil {
		return nil, err
	}

	if err := principal.EnrichUserPrincipalProjectScopeReader(ctx, network); err != nil {
		return nil, fmt.Errorf("%w: unable to set principal information", err)
	}

	required, err := c.generate(ctx, organizationID, projectID, request, network, current.Spec.VolumeClassID, current.Spec.Size)
	if err != nil {
		return nil, err
	}

	if err := conversion.UpdateObjectMetadata(required, current, identitycommon.IdentityMetadataMutator); err != nil {
		return nil, fmt.Errorf("%w: failed to merge metadata", err)
	}

	if allocationID := current.Annotations[coreconstants.AllocationAnnotation]; allocationID != "" {
		required.Annotations[coreconstants.AllocationAnnotation] = allocationID
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec.Tags = required.Spec.Tags

	return updated, nil
}

// UpdateV2 updates only Volume metadata and tags.
func (c *Client) UpdateV2(ctx context.Context, volumeID regionids.VolumeID, request *openapi.VolumeV2Update) (*openapi.VolumeV2Read, error) {
	current, err := c.GetV2Raw(ctx, volumeID.String())
	if err != nil {
		return nil, err
	}

	if err := rbac.AllowProjectScopeReader(ctx, endpoint, identityapi.Update, current); err != nil {
		return nil, err
	}

	if current.DeletionTimestamp != nil {
		return nil, errors.OAuth2InvalidRequest("volume is being deleted")
	}

	updated, err := c.generateUpdate(ctx, current, request)
	if err != nil {
		return nil, err
	}

	if err := c.Client.Patch(ctx, updated, client.MergeFromWithOptions(current, &client.MergeFromWithOptimisticLock{})); err != nil {
		if kerrors.IsConflict(err) {
			return nil, errors.HTTPConflict().WithError(err)
		}

		return nil, fmt.Errorf("%w: unable to update volume", err)
	}

	return convertV2(updated)
}

// DeleteV2 deletes an unattached v2 Volume.
func (c *Client) DeleteV2(ctx context.Context, volumeID regionids.VolumeID) error {
	resource, err := c.GetV2Raw(ctx, volumeID.String())
	if err != nil {
		return err
	}

	if err := rbac.AllowProjectScopeReader(ctx, endpoint, identityapi.Delete, resource); err != nil {
		return err
	}

	if resource.DeletionTimestamp != nil {
		return nil
	}

	if resource.Spec.ClaimRef != nil || len(manager.GetResourceReferences(resource)) != 0 {
		return errors.HTTPForbidden("volume is attached and must be detached before deletion")
	}

	if err := c.Client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return fmt.Errorf("%w: unable to delete volume", err)
	}

	return nil
}

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

package storage

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	"github.com/unikorn-cloud/identity/pkg/authz"
	identitycommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const directoryQuotaEndpoint = "region:filestoragedirectoryquotas:v2"

// directoryQuotaIDNamespace is the fixed UUIDv5 namespace of Directory Quota
// IDs, so they cannot collide with another resource type hashed from the same
// File Storage (specification appendix A.1). Changing it changes every ID.
//
//nolint:gochecknoglobals
var directoryQuotaIDNamespace = uuid.MustParse("981ad53a-40b7-4b1d-aeea-7f223b4a9094")

// CreateDirectoryQuota records Directory Quota intent; the controller applies it.
// The ID is derived from the parent ID and path, so Kubernetes rejects a second
// quota on the same path, including while the first is terminating.
func (c *Client) CreateDirectoryQuota(ctx context.Context, storageID regionids.FileStorageID, request *openapi.FileStorageDirectoryQuotaV2Create) (*openapi.FileStorageDirectoryQuotaV2Read, error) {
	target := authz.Target{
		Endpoint:   directoryQuotaEndpoint,
		Operation:  authz.Create,
		Kind:       authz.Primary,
		ObjectName: request.Metadata.Name,
	}

	authz.Declare(ctx, target)

	parent, err := c.getParentFileStorage(ctx, storageID)
	if err != nil {
		return nil, err
	}

	if err := principal.EnrichUserPrincipalProjectScopeReader(ctx, parent); err != nil {
		return nil, fmt.Errorf("%w: unable to set directory quota principal scope", err)
	}

	if err := rbac.AllowProjectScopeCreateReaderOn(ctx, c.Identity, target, parent); err != nil {
		return nil, childAuthorizationError(err)
	}

	if parent.DeletionTimestamp != nil {
		return nil, errors.HTTPConflict()
	}

	spec := directoryQuotaLimitsSpec(&request.Spec)

	if err := validateDirectoryQuotaCreate(request.Spec.Path, spec); err != nil {
		return nil, err
	}

	if err := c.validateDirectoryQuotaHierarchy(ctx, storageID, &parent.Spec.Size, request.Spec.Path, spec.DirectoryLimits); err != nil {
		return nil, err
	}

	resource, err := c.generateDirectoryQuota(ctx, parent, parent.Labels[constants.RegionLabel], storageID, &request.Metadata, request.Spec.Path, spec)
	if err != nil {
		return nil, err
	}

	// Add the finalizer before the controller can observe the resource, as required by specification §7.6.
	resource.Finalizers = []string{coreconstants.Finalizer}

	if err := controllerutil.SetOwnerReference(parent, resource, c.Client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		return nil, fmt.Errorf("%w: failed to set directory quota owner", err)
	}

	if err := c.Client.Create(ctx, resource); err != nil {
		return nil, directoryQuotaWriteError(err, "create")
	}

	return convertDirectoryQuota(resource), nil
}

// UpdateDirectoryQuota replaces everything but the path, which the request
// cannot carry.
func (c *Client) UpdateDirectoryQuota(ctx context.Context, storageID regionids.FileStorageID, quotaID regionids.FileStorageDirectoryQuotaID, request *openapi.FileStorageDirectoryQuotaV2Update) (*openapi.FileStorageDirectoryQuotaV2Read, error) {
	current, err := c.getDirectoryQuota(ctx, storageID, quotaID, authz.Update)
	if err != nil {
		return nil, err
	}

	if current.DeletionTimestamp != nil {
		return nil, errors.HTTPConflict()
	}

	if err := c.validateDirectoryQuotaUpdate(ctx, storageID, current.Spec.Path, &request.Spec); err != nil {
		return nil, err
	}

	if err := principal.EnrichUserPrincipalProjectScopeReader(ctx, current); err != nil {
		return nil, fmt.Errorf("%w: unable to set directory quota principal scope", err)
	}

	required, err := c.generateDirectoryQuota(ctx, current, current.Labels[constants.RegionLabel], storageID, &request.Metadata, current.Spec.Path, &request.Spec)
	if err != nil {
		return nil, err
	}

	if err := conversion.UpdateObjectMetadata(required, current, identitycommon.IdentityMetadataMutator); err != nil {
		return nil, fmt.Errorf("%w: failed to merge metadata", err)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	required.Spec.Pause = current.Spec.Pause
	updated.Spec = required.Spec

	if err := c.Client.Patch(ctx, updated, client.MergeFromWithOptions(current, &client.MergeFromWithOptimisticLock{})); err != nil {
		return nil, directoryQuotaWriteError(err, "update")
	}

	return convertDirectoryQuota(updated), nil
}

// directoryQuotaWriteError maps a create or update failure: an occupied path
// or a stale optimistic lock is 409, and a CRD validation rejection is 422.
func directoryQuotaWriteError(err error, action string) error {
	switch {
	case kerrors.IsAlreadyExists(err), kerrors.IsConflict(err):
		return errors.HTTPConflict().WithError(err)
	case kerrors.IsInvalid(err):
		return errors.HTTPUnprocessableContent().WithError(err)
	}

	return fmt.Errorf("%w: unable to %s directory quota", err, action)
}

// DeleteDirectoryQuota removes the limits; the controller leaves the directory
// and its data untouched.
func (c *Client) DeleteDirectoryQuota(ctx context.Context, storageID regionids.FileStorageID, quotaID regionids.FileStorageDirectoryQuotaID) error {
	resource, err := c.getDirectoryQuota(ctx, storageID, quotaID, authz.Delete)
	if err != nil {
		return err
	}

	if resource.DeletionTimestamp != nil {
		return nil
	}

	if err := c.Client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return fmt.Errorf("%w: unable to delete directory quota", err)
	}

	return nil
}

// ListDirectoryQuotas lists the Directory Quotas of an authorized File Storage.
func (c *Client) ListDirectoryQuotas(ctx context.Context, storageID regionids.FileStorageID, params openapi.GetApiV2FilestorageFilestorageIDDirectoryquotasParams) (openapi.FileStorageDirectoryQuotasV2Read, error) {
	parent, err := c.getParentFileStorage(ctx, storageID)
	if err != nil {
		return nil, err
	}

	if err := rbac.AllowProjectScopeReader(ctx, directoryQuotaEndpoint, identityapi.Read, parent); err != nil {
		return nil, childAuthorizationError(err)
	}

	selector := labels.SelectorFromSet(map[string]string{
		constants.FileStorageLabel: parent.Name,
	})

	selector, err = rbac.AddOrganizationAndProjectIDQuery(ctx, selector,
		[]string{parent.Labels[coreconstants.OrganizationLabel]},
		[]string{parent.Labels[coreconstants.ProjectLabel]})
	if err != nil {
		if rbac.HasNoMatches(err) {
			return openapi.FileStorageDirectoryQuotasV2Read{}, nil
		}

		return nil, fmt.Errorf("%w: failed to add identity label selector", err)
	}

	tagSelector, err := coreutil.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result := &regionv1.FileStorageDirectoryQuotaList{}
	if err := c.Client.List(ctx, result, &client.ListOptions{Namespace: c.Namespace, LabelSelector: selector}); err != nil {
		return nil, fmt.Errorf("%w: unable to list directory quotas", err)
	}

	result.Items = slices.DeleteFunc(result.Items, func(quota regionv1.FileStorageDirectoryQuota) bool {
		if !directoryQuotaMatchesParentID(&quota, storageID) || !quota.Spec.Tags.ContainsAll(tagSelector) {
			return true
		}

		return !rbac.PermitsProjectScopeReader(ctx, directoryQuotaEndpoint, identityapi.Read, &quota)
	})
	slices.SortStableFunc(result.Items, func(a, b regionv1.FileStorageDirectoryQuota) int {
		return cmp.Or(cmp.Compare(a.Labels[coreconstants.NameLabel], b.Labels[coreconstants.NameLabel]), cmp.Compare(a.Name, b.Name))
	})

	out := make(openapi.FileStorageDirectoryQuotasV2Read, len(result.Items))
	for i := range result.Items {
		out[i] = *convertDirectoryQuota(&result.Items[i])
	}

	return out, nil
}

// GetDirectoryQuota reads one Directory Quota, authorizing its own project
// without requiring the parent to exist.
func (c *Client) GetDirectoryQuota(ctx context.Context, storageID regionids.FileStorageID, quotaID regionids.FileStorageDirectoryQuotaID) (*openapi.FileStorageDirectoryQuotaV2Read, error) {
	result, err := c.getDirectoryQuota(ctx, storageID, quotaID, authz.Read)
	if err != nil {
		return nil, err
	}

	return convertDirectoryQuota(result), nil
}

// getDirectoryQuota fetches and authorizes a Directory Quota. Missing,
// inaccessible and wrong-parent quotas all answer 404.
func (c *Client) getDirectoryQuota(ctx context.Context, storageID regionids.FileStorageID, quotaID regionids.FileStorageDirectoryQuotaID, operation authz.Operation) (*regionv1.FileStorageDirectoryQuota, error) {
	target := authz.Target{
		Endpoint:  directoryQuotaEndpoint,
		Operation: operation,
		ObjectID:  uuid.UUID(quotaID),
	}

	if operation != authz.Read {
		target.Kind = authz.Primary
		authz.Declare(ctx, target)
	}

	result := &regionv1.FileStorageDirectoryQuota{}
	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: quotaID.String()}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: unable to lookup directory quota", err)
	}

	target.ObjectName = result.Labels[coreconstants.NameLabel]

	if err := rbac.AllowProjectScopeReaderOn(ctx, target, result); err != nil {
		return nil, childAuthorizationError(err)
	}

	if !directoryQuotaMatchesParentID(result, storageID) {
		return nil, errors.HTTPNotFound()
	}

	return result, nil
}

// generateDirectoryQuota builds the stored resource. scope supplies the
// organization and project, and path the directory: the parent and the
// request's path on create, the quota and its stored path on update.
func (c *Client) generateDirectoryQuota(ctx context.Context, scope identityids.ProjectScopeReader, regionID string, storageID regionids.FileStorageID, metadata *coreopenapi.ResourceWriteMetadata, path string, spec *openapi.FileStorageDirectoryQuotaV2UpdateSpec) (*regionv1.FileStorageDirectoryQuota, error) {
	organizationID, projectID, err := scope.OrganizationAndProjectID()
	if err != nil {
		return nil, err
	}

	resource := &regionv1.FileStorageDirectoryQuota{
		ObjectMeta: conversion.NewDeterministicObjectMetadata(metadata, c.Namespace,
			directoryQuotaIDNamespace, storageID.String()+"/"+path).
			WithLabel(constants.FileStorageLabel, storageID.String()).
			WithLabel(constants.RegionLabel, regionID).
			WithLabel(constants.ResourceAPIVersionLabel, constants.MarshalAPIVersion(2)).
			Get(),
		Spec: regionv1.FileStorageDirectoryQuotaSpec{
			FileStorageID:      storageID,
			Path:               path,
			DirectoryLimits:    generateDirectoryQuotaLimits(spec.DirectoryLimits),
			DefaultUserLimits:  generateDirectoryQuotaLimits(spec.DefaultUserLimits),
			DefaultGroupLimits: generateDirectoryQuotaLimits(spec.DefaultGroupLimits),
			Tags:               conversion.GenerateTagList(metadata.Tags),
		},
	}

	for _, rule := range ptr.Deref(spec.Rules, nil) {
		resource.Spec.Rules = append(resource.Spec.Rules, regionv1.FileStorageDirectoryQuotaRule{
			Subject: regionv1.FileStorageDirectoryQuotaSubject{
				Kind: regionv1.FileStorageDirectoryQuotaSubjectKind(rule.Subject.Kind),
				Name: rule.Subject.Name,
				ID:   rule.Subject.Id,
			},
			Limits: *generateDirectoryQuotaLimits(&rule.Limits),
		})
	}

	if err := identitycommon.SetIdentityMetadataProjectScope(ctx, &resource.ObjectMeta, organizationID, projectID); err != nil {
		return nil, fmt.Errorf("%w: failed to set directory quota identity metadata", err)
	}

	return resource, nil
}

func generateDirectoryQuotaLimits(in *openapi.FileStorageDirectoryQuotaLimits) *regionv1.FileStorageDirectoryQuotaLimits {
	if in == nil {
		return nil
	}

	out := &regionv1.FileStorageDirectoryQuotaLimits{
		Inodes: in.Inodes,
	}

	if in.CapacityBytes != nil {
		out.Capacity = resource.NewQuantity(*in.CapacityBytes, resource.BinarySI)
	}

	return out
}

// directoryQuotaLimitsSpec drops the path, which only create sets, so create
// and update share validation and generation.
func directoryQuotaLimitsSpec(in *openapi.FileStorageDirectoryQuotaV2CreateSpec) *openapi.FileStorageDirectoryQuotaV2UpdateSpec {
	return &openapi.FileStorageDirectoryQuotaV2UpdateSpec{
		DirectoryLimits:    in.DirectoryLimits,
		DefaultUserLimits:  in.DefaultUserLimits,
		DefaultGroupLimits: in.DefaultGroupLimits,
		Rules:              in.Rules,
	}
}

func validateDirectoryQuotaCreate(path string, spec *openapi.FileStorageDirectoryQuotaV2UpdateSpec) error {
	if err := validatePathComponents("path", path); err != nil {
		return err
	}

	return validateDirectoryQuota(spec)
}

// validateDirectoryQuota enforces the rules the OpenAPI schema cannot express.
func validateDirectoryQuota(spec *openapi.FileStorageDirectoryQuotaV2UpdateSpec) error {
	rules := ptr.Deref(spec.Rules, nil)

	if spec.DirectoryLimits == nil && spec.DefaultUserLimits == nil && spec.DefaultGroupLimits == nil && len(rules) == 0 {
		return errors.HTTPUnprocessableContent("at least one of directoryLimits, defaultUserLimits, defaultGroupLimits or rules is required")
	}

	if err := validateDirectoryQuotaSubjects(rules); err != nil {
		return err
	}

	return validateDirectoryQuotaCeiling(spec, rules)
}

// validateDirectoryQuotaUpdate also checks the hierarchy and rejects an update
// under a deleting parent. A quota whose parent is gone is about to be garbage
// collected, so its size check is skipped.
func (c *Client) validateDirectoryQuotaUpdate(ctx context.Context, storageID regionids.FileStorageID, path string, spec *openapi.FileStorageDirectoryQuotaV2UpdateSpec) error {
	if err := validateDirectoryQuota(spec); err != nil {
		return err
	}

	var size *resource.Quantity

	parent, err := c.getParentFileStorage(ctx, storageID)

	switch {
	case err == nil && parent.DeletionTimestamp != nil:
		return errors.HTTPConflict()
	case err == nil:
		size = &parent.Spec.Size
	case !errors.IsHTTPNotFound(err):
		return err
	}

	return c.validateDirectoryQuotaHierarchy(ctx, storageID, size, path, spec.DirectoryLimits)
}

// validateDirectoryQuotaHierarchy rejects directoryLimits above the File
// Storage size or an ancestor quota's directoryLimits, or below a descendant's.
// Every ancestor and descendant is compared, not only the nearest, so a quota
// without directoryLimits in between hides nothing. Quotas being deleted are
// ignored: their limits are going away.
// shortcut: concurrent writes can still break the hierarchy, the controller must re-validate.
func (c *Client) validateDirectoryQuotaHierarchy(ctx context.Context, storageID regionids.FileStorageID, size *resource.Quantity, path string, limits *openapi.FileStorageDirectoryQuotaLimits) error {
	if limits == nil {
		return nil
	}

	if size != nil && limits.CapacityBytes != nil && *limits.CapacityBytes > size.Value() {
		return errors.HTTPUnprocessableContent("directoryLimits.capacityBytes must not exceed the File Storage size")
	}

	quotas := &regionv1.FileStorageDirectoryQuotaList{}

	selector := labels.SelectorFromSet(map[string]string{constants.FileStorageLabel: storageID.String()})
	if err := c.Client.List(ctx, quotas, &client.ListOptions{Namespace: c.Namespace, LabelSelector: selector}); err != nil {
		return fmt.Errorf("%w: unable to list directory quotas", err)
	}

	for i := range quotas.Items {
		if other := &quotas.Items[i]; other.DeletionTimestamp == nil && directoryQuotaMatchesParentID(other, storageID) {
			if err := validateNestedDirectoryQuota(path, limits, other); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateNestedDirectoryQuota compares limits on path with one other quota,
// which matters only when it is on a parent directory or a subdirectory.
func validateNestedDirectoryQuota(path string, limits *openapi.FileStorageDirectoryQuotaLimits, other *regionv1.FileStorageDirectoryQuota) error {
	otherLimits := convertDirectoryQuotaLimits(other.Spec.DirectoryLimits)
	if otherLimits == nil {
		return nil
	}

	if strings.HasPrefix(path, other.Spec.Path+"/") && exceedsLimit(limits, otherLimits) {
		return errors.HTTPUnprocessableContent("directoryLimits must not exceed the directoryLimits of a quota on a parent directory")
	}

	if strings.HasPrefix(other.Spec.Path, path+"/") && exceedsLimit(otherLimits, limits) {
		return errors.HTTPUnprocessableContent("directoryLimits must not be below the directoryLimits of a quota on a subdirectory")
	}

	return nil
}

func validateDirectoryQuotaSubjects(rules openapi.FileStorageDirectoryQuotaRules) error {
	seen := make(map[directoryQuotaSubjectKey]bool, len(rules))

	for _, rule := range rules {
		key := newDirectoryQuotaSubjectKey(string(rule.Subject.Kind), rule.Subject.Name, rule.Subject.Id)
		if seen[key] {
			return errors.HTTPUnprocessableContent("rules must not repeat a subject")
		}

		seen[key] = true
	}

	return nil
}

// validateDirectoryQuotaCeiling rejects default and rule limits above directoryLimits.
func validateDirectoryQuotaCeiling(spec *openapi.FileStorageDirectoryQuotaV2UpdateSpec, rules openapi.FileStorageDirectoryQuotaRules) error {
	if spec.DirectoryLimits == nil {
		return nil
	}

	limits := []*openapi.FileStorageDirectoryQuotaLimits{spec.DefaultUserLimits, spec.DefaultGroupLimits}
	for i := range rules {
		limits = append(limits, &rules[i].Limits)
	}

	for _, l := range limits {
		if exceedsLimit(l, spec.DirectoryLimits) {
			return errors.HTTPUnprocessableContent("default and rule limits must not exceed directoryLimits")
		}
	}

	return nil
}

func exceedsLimit(in, ceiling *openapi.FileStorageDirectoryQuotaLimits) bool {
	if in == nil {
		return false
	}

	exceeds := func(v, ceiling *int64) bool {
		return v != nil && ceiling != nil && *v > *ceiling
	}

	return exceeds(in.CapacityBytes, ceiling.CapacityBytes) || exceeds(in.Inodes, ceiling.Inodes)
}

// directoryQuotaSubjectKey compares subjects by value; name and id are optional.
type directoryQuotaSubjectKey struct {
	kind   string
	name   string
	id     int64
	byName bool
}

func newDirectoryQuotaSubjectKey(kind string, name *string, id *int64) directoryQuotaSubjectKey {
	return directoryQuotaSubjectKey{kind: kind, name: ptr.Deref(name, ""), id: ptr.Deref(id, 0), byName: name != nil}
}

func storedSubjectKey(in regionv1.FileStorageDirectoryQuotaSubject) directoryQuotaSubjectKey {
	return newDirectoryQuotaSubjectKey(string(in.Kind), in.Name, in.ID)
}

func convertDirectoryQuota(in *regionv1.FileStorageDirectoryQuota) *openapi.FileStorageDirectoryQuotaV2Read {
	out := &openapi.FileStorageDirectoryQuotaV2Read{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.FileStorageDirectoryQuotaV2Spec{
			FileStorageId:      in.Spec.FileStorageID,
			Path:               in.Spec.Path,
			DirectoryLimits:    convertDirectoryQuotaLimits(in.Spec.DirectoryLimits),
			DefaultUserLimits:  convertDirectoryQuotaLimits(in.Spec.DefaultUserLimits),
			DefaultGroupLimits: convertDirectoryQuotaLimits(in.Spec.DefaultGroupLimits),
		},
		Status: openapi.FileStorageDirectoryQuotaV2Status{
			Usage: convertDirectoryQuotaDirectoryUsage(in.Status.Usage),
		},
	}

	if len(in.Spec.Rules) == 0 {
		return out
	}

	// Rule status written for an older generation describes limits the
	// controller has not applied yet, so those rules stay pending.
	ruleStatus := map[directoryQuotaSubjectKey]regionv1.FileStorageDirectoryQuotaRuleStatus{}

	if ptr.Deref(in.Status.ObservedGeneration, 0) == in.Generation {
		for _, s := range in.Status.Rules {
			ruleStatus[storedSubjectKey(s.Subject)] = s
		}
	}

	ruleUsage := map[directoryQuotaSubjectKey]regionv1.FileStorageDirectoryQuotaUsedAmount{}

	if in.Status.Usage != nil {
		for _, u := range in.Status.Usage.Rules {
			ruleUsage[storedSubjectKey(u.Subject)] = u.Usage
		}
	}

	specRules := make(openapi.FileStorageDirectoryQuotaRules, len(in.Spec.Rules))
	statusRules := make([]openapi.FileStorageDirectoryQuotaRuleStatus, len(in.Spec.Rules))

	for i, rule := range in.Spec.Rules {
		subject := openapi.FileStorageDirectoryQuotaSubject{
			Kind: openapi.FileStorageDirectoryQuotaSubjectKind(rule.Subject.Kind),
			Name: rule.Subject.Name,
			Id:   rule.Subject.ID,
		}

		specRules[i] = openapi.FileStorageDirectoryQuotaRule{
			Subject: subject,
			Limits:  *convertDirectoryQuotaLimits(&rule.Limits),
		}

		key := storedSubjectKey(rule.Subject)
		statusRules[i] = convertDirectoryQuotaRuleStatus(subject, ruleStatus[key])

		if u, ok := ruleUsage[key]; ok {
			statusRules[i].Usage = convertDirectoryQuotaUsage(u)
		}
	}

	out.Spec.Rules = &specRules
	out.Status.Rules = &statusRules

	return out
}

// convertDirectoryQuotaRuleStatus projects stored rule status. A rule the
// controller has not observed yet has a zero status and is pending.
func convertDirectoryQuotaRuleStatus(subject openapi.FileStorageDirectoryQuotaSubject, in regionv1.FileStorageDirectoryQuotaRuleStatus) openapi.FileStorageDirectoryQuotaRuleStatus {
	out := openapi.FileStorageDirectoryQuotaRuleStatus{
		Subject:            subject,
		ProvisioningStatus: coreopenapi.ResourceProvisioningStatusPending,
	}

	switch in.ProvisioningStatus {
	case regionv1.FileStorageDirectoryQuotaRuleProvisioned:
		out.ProvisioningStatus = coreopenapi.ResourceProvisioningStatusProvisioned
	case regionv1.FileStorageDirectoryQuotaRuleErrored:
		out.ProvisioningStatus = coreopenapi.ResourceProvisioningStatusError

		if in.Message != "" {
			out.Message = &in.Message
		}
	case regionv1.FileStorageDirectoryQuotaRulePending:
	}

	return out
}

func convertDirectoryQuotaDirectoryUsage(in *regionv1.FileStorageDirectoryQuotaUsage) *openapi.FileStorageDirectoryQuotaDirectoryUsage {
	if in == nil || (in.Directory == nil && in.Timestamp == nil) {
		return nil
	}

	out := &openapi.FileStorageDirectoryQuotaDirectoryUsage{}

	if in.Directory != nil {
		used := convertDirectoryQuotaUsage(*in.Directory)
		out.UsedBytes = used.UsedBytes
		out.UsedInodes = used.UsedInodes
	}

	if in.Timestamp != nil {
		out.UpdatedAt = &in.Timestamp.Time
	}

	return out
}

func convertDirectoryQuotaLimits(in *regionv1.FileStorageDirectoryQuotaLimits) *openapi.FileStorageDirectoryQuotaLimits {
	if in == nil {
		return nil
	}

	out := &openapi.FileStorageDirectoryQuotaLimits{
		Inodes: in.Inodes,
	}

	if in.Capacity != nil {
		out.CapacityBytes = ptr.To(in.Capacity.Value())
	}

	return out
}

func convertDirectoryQuotaUsage(in regionv1.FileStorageDirectoryQuotaUsedAmount) *openapi.FileStorageDirectoryQuotaUsage {
	out := &openapi.FileStorageDirectoryQuotaUsage{
		UsedInodes: in.UsedInodes,
	}

	if in.UsedCapacity != nil {
		out.UsedBytes = ptr.To(in.UsedCapacity.Value())
	}

	return out
}

func directoryQuotaMatchesParentID(quota *regionv1.FileStorageDirectoryQuota, storageID regionids.FileStorageID) bool {
	return quota.Spec.FileStorageID == storageID &&
		quota.Labels[constants.FileStorageLabel] == storageID.String()
}

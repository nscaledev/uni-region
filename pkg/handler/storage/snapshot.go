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
	"time"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const snapshotEndpoint = "region:filestoragesnapshots:v2"

// ListSnapshots lists non-expired Manual Snapshots within an authorized File
// Storage. Region intent and one request-time observation determine visibility.
func (c *Client) ListSnapshots(ctx context.Context, storageID regionids.FileStorageID, params openapi.GetApiV2FilestorageFilestorageIDSnapshotsParams) (openapi.FileStorageSnapshotsV2Read, error) {
	now := c.Clock.Now()

	parent, err := c.getSnapshotParent(ctx, storageID)
	if err != nil {
		return nil, err
	}

	selector := labels.SelectorFromSet(map[string]string{
		constants.FileStorageLabel:        parent.Name,
		constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
		coreconstants.OrganizationLabel:   parent.Labels[coreconstants.OrganizationLabel],
		coreconstants.ProjectLabel:        parent.Labels[coreconstants.ProjectLabel],
	})

	result := &regionv1.FileStorageSnapshotList{}
	if err := c.Client.List(ctx, result, &client.ListOptions{Namespace: c.Namespace, LabelSelector: selector}); err != nil {
		return nil, fmt.Errorf("%w: unable to list snapshots", err)
	}

	tagSelector, err := coreutil.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(snapshot regionv1.FileStorageSnapshot) bool {
		return !snapshotBelongsToParent(&snapshot, parent, storageID) ||
			snapshotExpired(&snapshot, now) || !snapshot.Spec.Tags.ContainsAll(tagSelector)
	})
	slices.SortStableFunc(result.Items, func(a, b regionv1.FileStorageSnapshot) int {
		return cmp.Or(cmp.Compare(a.Spec.Name, b.Spec.Name), cmp.Compare(a.Name, b.Name))
	})

	out := make(openapi.FileStorageSnapshotsV2Read, len(result.Items))
	for i := range result.Items {
		out[i] = *convertSnapshot(&result.Items[i])
	}

	return out, nil
}

// GetSnapshot reads one Manual Snapshot from the Region ledger, under its
// authorized parent. It never discovers or adopts provider snapshots.
func (c *Client) GetSnapshot(ctx context.Context, storageID regionids.FileStorageID, snapshotID regionids.FileStorageSnapshotID) (*openapi.FileStorageSnapshotV2Read, error) {
	now := c.Clock.Now()

	parent, err := c.getSnapshotParent(ctx, storageID)
	if err != nil {
		return nil, err
	}

	result := &regionv1.FileStorageSnapshot{}
	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: snapshotID.String()}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: unable to lookup snapshot", err)
	}

	if !snapshotBelongsToParent(result, parent, storageID) || snapshotExpired(result, now) {
		return nil, errors.HTTPNotFound()
	}

	return convertSnapshot(result), nil
}

func convertSnapshot(in *regionv1.FileStorageSnapshot) *openapi.FileStorageSnapshotV2Read {
	out := &openapi.FileStorageSnapshotV2Read{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.FileStorageSnapshotV2Spec{
			FileStorageId: in.Spec.FileStorageID,
			ProtectedPath: in.Spec.ProtectedPath,
		},
		Status: openapi.FileStorageSnapshotV2Status{
			AbsoluteProtectedPath: in.Status.AbsoluteProtectedPath,
		},
	}
	// Manual Snapshot Name is immutable intent; its metadata label is a mirror.
	out.Metadata.Name = in.Spec.Name

	if in.Spec.ExpirationTime != nil {
		out.Spec.ExpirationTime = &in.Spec.ExpirationTime.Time
	}

	if in.Status.SnapshotTime != nil {
		out.Status.SnapshotTime = &in.Status.SnapshotTime.Time
	}

	return out
}

// getSnapshotParent resolves the parent and both Read permissions before any
// child lookup. All visibility failures use the same canonical not-found body.
func (c *Client) getSnapshotParent(ctx context.Context, storageID regionids.FileStorageID) (*regionv1.FileStorage, error) {
	parent, err := c.GetRaw(ctx, storageID.String())
	if err != nil {
		if errors.IsHTTPNotFound(err) || errors.IsForbidden(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, err
	}

	if err := rbac.AllowProjectScopeReader(ctx, snapshotEndpoint, identityapi.Read, parent); err != nil {
		return nil, errors.HTTPNotFound().WithError(err)
	}

	return parent, nil
}

func snapshotBelongsToParent(snapshot *regionv1.FileStorageSnapshot, parent *regionv1.FileStorage, storageID regionids.FileStorageID) bool {
	return snapshot.Spec.FileStorageID == storageID &&
		snapshot.Labels[constants.FileStorageLabel] == parent.Name &&
		snapshot.Labels[coreconstants.OrganizationLabel] == parent.Labels[coreconstants.OrganizationLabel] &&
		snapshot.Labels[coreconstants.ProjectLabel] == parent.Labels[coreconstants.ProjectLabel] &&
		snapshot.Labels[constants.ResourceAPIVersionLabel] == constants.MarshalAPIVersion(2)
}

func snapshotExpired(snapshot *regionv1.FileStorageSnapshot, now time.Time) bool {
	return snapshot.Spec.ExpirationTime != nil && !snapshot.Spec.ExpirationTime.After(now)
}

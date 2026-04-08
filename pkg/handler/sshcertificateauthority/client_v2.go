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

package sshcertificateauthority

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	identitycommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	handlerutil "github.com/unikorn-cloud/region/pkg/handler/util"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const endpoint = "region:sshcertificateauthorities:v2"

type Client struct {
	common.ClientArgs
}

func New(clientArgs common.ClientArgs) *Client {
	return &Client{
		ClientArgs: clientArgs,
	}
}

func convertV2(in *regionv1.SSHCertificateAuthority) *openapi.SshCertificateAuthorityV2Read {
	return &openapi.SshCertificateAuthorityV2Read{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.SshCertificateAuthorityV2Spec{
			PublicKey: in.Spec.PublicKey,
		},
	}
}

func convertV2List(in *regionv1.SSHCertificateAuthorityList) openapi.SshCertificateAuthoritiesV2Read {
	out := make(openapi.SshCertificateAuthoritiesV2Read, len(in.Items))

	for i := range in.Items {
		out[i] = *convertV2(&in.Items[i])
	}

	return out
}

func normalizePublicKey(in string) string {
	return strings.TrimSpace(in)
}

func validatePublicKey(in string) (string, error) {
	normalized := normalizePublicKey(in)
	if normalized == "" {
		return "", errors.HTTPUnprocessableContent("public key must be specified")
	}

	key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(normalized))
	if err != nil {
		return "", errors.HTTPUnprocessableContent("public key must be a valid OpenSSH authorized key").WithError(err)
	}

	if len(rest) != 0 {
		return "", errors.HTTPUnprocessableContent("public key must contain a single key")
	}

	if len(options) != 0 {
		return "", errors.HTTPUnprocessableContent("public key options are not supported")
	}

	switch key.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoRSA, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
	default:
		return "", errors.HTTPUnprocessableContent("public key type is not supported for SSH certificate authorities")
	}

	if comment == "" {
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), nil
	}

	return normalized, nil
}

func (c *Client) ListV2(ctx context.Context, params openapi.GetApiV2SshcertificateauthoritiesParams) (openapi.SshCertificateAuthoritiesV2Read, error) {
	selector := labels.Everything()

	var err error

	selector, err = rbac.AddOrganizationAndProjectIDQuery(ctx, selector, handlerutil.OrganizationIDQuery(params.OrganizationID), handlerutil.ProjectIDQuery(params.ProjectID))
	if err != nil {
		if rbac.HasNoMatches(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("%w: failed to add identity label selector", err)
	}

	options := &client.ListOptions{
		Namespace:     c.Namespace,
		LabelSelector: selector,
	}

	result := &regionv1.SSHCertificateAuthorityList{}

	if err := c.Client.List(ctx, result, options); err != nil {
		return nil, fmt.Errorf("%w: unable to list SSH certificate authorities", err)
	}

	tagSelector, err := coreutil.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource regionv1.SSHCertificateAuthority) bool {
		return !resource.Spec.Tags.ContainsAll(tagSelector) ||
			rbac.AllowProjectScope(ctx, endpoint, identityapi.Read, resource.Labels[coreconstants.OrganizationLabel], resource.Labels[coreconstants.ProjectLabel]) != nil
	})

	slices.SortStableFunc(result.Items, func(a, b regionv1.SSHCertificateAuthority) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertV2List(result), nil
}

func (c *Client) GetV2Raw(ctx context.Context, sshCertificateAuthorityID string) (*regionv1.SSHCertificateAuthority, error) {
	result := &regionv1.SSHCertificateAuthority{}

	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: sshCertificateAuthorityID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: unable to lookup SSH certificate authority", err)
	}

	if err := rbac.AllowProjectScope(ctx, endpoint, identityapi.Read, result.Labels[coreconstants.OrganizationLabel], result.Labels[coreconstants.ProjectLabel]); err != nil {
		return nil, err
	}

	v, ok := result.Labels[constants.ResourceAPIVersionLabel]
	if !ok {
		return nil, errors.HTTPNotFound()
	}

	version, err := constants.UnmarshalAPIVersion(v)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to parse API version", err)
	}

	if version != 2 {
		return nil, errors.HTTPNotFound()
	}

	return result, nil
}

func (c *Client) GetV2(ctx context.Context, sshCertificateAuthorityID string) (*openapi.SshCertificateAuthorityV2Read, error) {
	result, err := c.GetV2Raw(ctx, sshCertificateAuthorityID)
	if err != nil {
		return nil, err
	}

	return convertV2(result), nil
}

func (c *Client) CreateV2(ctx context.Context, request *openapi.SshCertificateAuthorityV2Create) (*openapi.SshCertificateAuthorityV2Read, error) {
	if err := rbac.AllowProjectScopeCreate(ctx, c.Identity, endpoint, identityapi.Create, request.Spec.OrganizationId, request.Spec.ProjectId); err != nil {
		return nil, err
	}

	publicKey, err := validatePublicKey(request.Spec.PublicKey)
	if err != nil {
		return nil, err
	}

	resource := &regionv1.SSHCertificateAuthority{
		ObjectMeta: conversion.NewObjectMetadata(&request.Metadata, c.Namespace).
			WithOrganization(request.Spec.OrganizationId).
			WithProject(request.Spec.ProjectId).
			WithLabel(constants.ResourceAPIVersionLabel, constants.MarshalAPIVersion(2)).
			Get(),
		Spec: regionv1.SSHCertificateAuthoritySpec{
			Tags:      conversion.GenerateTagList(request.Metadata.Tags),
			PublicKey: publicKey,
		},
	}

	if err := handlerutil.InjectUserPrincipal(ctx, request.Spec.OrganizationId, request.Spec.ProjectId); err != nil {
		return nil, fmt.Errorf("%w: unable to set principal information", err)
	}

	if err := identitycommon.SetIdentityMetadata(ctx, &resource.ObjectMeta); err != nil {
		return nil, fmt.Errorf("%w: failed to set identity metadata", err)
	}

	if err := c.Client.Create(ctx, resource); err != nil {
		return nil, fmt.Errorf("%w: unable to create SSH certificate authority", err)
	}

	return convertV2(resource), nil
}

func (c *Client) DeleteV2(ctx context.Context, sshCertificateAuthorityID string) error {
	resource, err := c.GetV2Raw(ctx, sshCertificateAuthorityID)
	if err != nil {
		return err
	}

	if err := rbac.AllowProjectScope(ctx, endpoint, identityapi.Delete, resource.Labels[coreconstants.OrganizationLabel], resource.Labels[coreconstants.ProjectLabel]); err != nil {
		return err
	}

	if resource.DeletionTimestamp != nil {
		return nil
	}

	if len(manager.GetResourceReferences(resource)) > 0 {
		return errors.HTTPForbidden("SSH certificate authority is in use and cannot be deleted")
	}

	if err := c.Client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return fmt.Errorf("%w: unable to delete SSH certificate authority", err)
	}

	return nil
}

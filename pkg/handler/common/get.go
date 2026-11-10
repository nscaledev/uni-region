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

package common

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/authz"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/constants"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Object is a resource that reports the project it belongs to.
type Object interface {
	client.Object
	ids.ProjectScopeReader
}

// GetV2 loads a v2 resource and authorizes the target on it, naming the
// resource.  A primary target is the request's own operation: it is declared
// before the fetch, so a request that fails on it is still recorded.  See the
// handler README's Authorization section.
func GetV2(ctx context.Context, cli client.Client, namespace, id string, target authz.Target, result Object) error {
	// A malformed ID names no object; the fetch below answers 404 for it.
	objectID, _ := uuid.Parse(id)

	target.ObjectID = objectID

	if target.Kind == authz.Primary {
		authz.Declare(ctx, target)
	}

	if err := FetchV2(ctx, cli, namespace, id, result); err != nil {
		return err
	}

	target.ObjectName = result.GetLabels()[coreconstants.NameLabel]

	return rbac.AllowProjectScopeReaderOn(ctx, target, result)
}

// FetchV2 loads a v2 resource WITHOUT authorizing it.  The caller MUST
// authorize what it does with it, and MUST NOT return it to the caller
// unchecked.  Only resources created by the v2 API are found.
func FetchV2(ctx context.Context, cli client.Client, namespace, id string, result Object) error {
	if err := cli.Get(ctx, client.ObjectKey{Namespace: namespace, Name: id}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return fmt.Errorf("%w: unable to lookup resource", err)
	}

	v, ok := result.GetLabels()[constants.ResourceAPIVersionLabel]
	if !ok {
		return errors.HTTPNotFound()
	}

	version, err := constants.UnmarshalAPIVersion(v)
	if err != nil {
		return fmt.Errorf("%w: unable to parse API version", err)
	}

	if version != 2 {
		return errors.HTTPNotFound()
	}

	return nil
}

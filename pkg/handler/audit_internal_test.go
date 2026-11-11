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

package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/authz"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	regionconstants "github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/loadbalancer"
	"github.com/unikorn-cloud/region/pkg/handler/network"
	"github.com/unikorn-cloud/region/pkg/handler/securitygroup"
	"github.com/unikorn-cloud/region/pkg/handler/server"
	"github.com/unikorn-cloud/region/pkg/handler/sshcertificateauthority"
	"github.com/unikorn-cloud/region/pkg/handler/storage"
	"github.com/unikorn-cloud/region/pkg/handler/volume"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/openapi"
	providertypes "github.com/unikorn-cloud/region/pkg/providers/types"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	auditNamespace = "audit-test"
	auditOrg       = "d4600d6e-e965-4b44-a808-84fb2fa36702"
	auditProject   = "cae219d7-10e5-4601-8c2c-ee7e066b93ce"

	auditNetwork       = "11111111-0000-4000-a000-000000000001"
	auditSecurityGroup = "11111111-0000-4000-a000-000000000002"
	auditVolume        = "11111111-0000-4000-a000-000000000003"
	auditLoadBalancer  = "11111111-0000-4000-a000-000000000004"
	auditSSHCA         = "11111111-0000-4000-a000-000000000005"
	auditServer        = "11111111-0000-4000-a000-000000000006"
	auditFileStorage   = "11111111-0000-4000-a000-000000000007"
	auditSnapshot      = "11111111-0000-4000-a000-000000000008"
	auditIdentity      = "11111111-0000-4000-a000-000000000009"
	auditImage         = "11111111-0000-4000-a000-00000000000a"
	auditMissing       = "11111111-0000-4000-a000-0000000000ff"
)

// auditObject names a v2 resource in the audit project.  File storage carries
// no API version label.
func auditObject[T client.Object](obj T, id string, versioned bool, extra labels) T {
	l := projectScopedLabels(auditOrg, auditProject, extra)
	l[coreconstants.NameLabel] = "name-" + id[len(id)-1:]

	if versioned {
		l[regionconstants.ResourceAPIVersionLabel] = "2"
	}

	return withMeta(obj, id, auditNamespace, l)
}

func auditObjects() []client.Object {
	return []client.Object{
		auditObject(&regionv1.Network{}, auditNetwork, true, nil),
		auditObject(&regionv1.SecurityGroup{}, auditSecurityGroup, true, labels{regionconstants.NetworkLabel: auditNetwork}),
		auditObject(&regionv1.Volume{}, auditVolume, true, nil),
		auditObject(&regionv1.LoadBalancer{}, auditLoadBalancer, true, labels{regionconstants.NetworkLabel: auditNetwork}),
		auditObject(&regionv1.SSHCertificateAuthority{}, auditSSHCA, true, nil),
		auditObject(&regionv1.Server{}, auditServer, true, labels{regionconstants.IdentityLabel: auditIdentity}),
		auditObject(&regionv1.FileStorage{}, auditFileStorage, false, nil),
		auditObject(&regionv1.FileStorageSnapshot{}, auditSnapshot, true, labels{regionconstants.FileStorageLabel: auditFileStorage}),
	}
}

// deletingObjects are auditObjects already being deleted.
func deletingObjects() []client.Object {
	objects := auditObjects()

	for _, object := range objects {
		object.SetFinalizers([]string{"example.com/hold"})
		object.SetDeletionTimestamp(&metav1.Time{Time: metav1.Now().Time})
	}

	return objects
}

var errNoProvider = errors.New("no provider in this test")

// effects counts what a request did beyond reading: Kubernetes writes and
// cloud provider lookups.
type effects struct {
	writes  atomic.Int32
	lookups atomic.Int32
}

func (e *effects) LookupCommon(string) (providertypes.CommonProvider, error) {
	e.lookups.Add(1)
	return nil, errNoProvider
}

func (e *effects) LookupCloud(string) (providertypes.Provider, error) {
	e.lookups.Add(1)
	return nil, errNoProvider
}

// observedArgs is auditArgs that counts effects.  Providers are present but
// unusable, so a request that gets past its check fails rather than panics.
func observedArgs(t *testing.T, objects ...client.Object) (common.ClientArgs, *effects) {
	t.Helper()

	e := &effects{}

	write := func() { e.writes.Add(1) }

	base, ok := fakeClientWithSchema(t, objects...).(client.WithWatch)
	require.True(t, ok)

	kube := interceptor.NewClient(base, interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			write()
			return c.Create(ctx, obj, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			write()
			return c.Update(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			write()
			return c.Patch(ctx, obj, patch, opts...)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			write()
			return c.Delete(ctx, obj, opts...)
		},
		SubResourcePatch: func(ctx context.Context, c client.Client, subResource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			write()
			return c.SubResource(subResource).Patch(ctx, obj, patch, opts...)
		},
	})

	return common.ClientArgs{
		Client:    kube,
		Namespace: auditNamespace,
		Providers: e,
	}, e
}

func auditArgs(t *testing.T, objects ...client.Object) common.ClientArgs {
	t.Helper()

	return common.ClientArgs{
		Client:    fakeClientWithSchema(t, objects...),
		Namespace: auditNamespace,
	}
}

// auditContext gives the caller the operations on every region endpoint
// across the organization, and a recorder to see what was decided.
func auditContext(t *testing.T, operations ...identityapi.AclOperation) (context.Context, *authz.Recorder) {
	t.Helper()

	acl := newOrganisationACLBuilder(auditOrg)

	for _, endpoint := range []string{
		"region:networks:v2", "region:networks:v2/references", "region:securitygroups:v2",
		"region:volumes:v2", "region:loadbalancers:v2", "region:sshcertificateauthorities:v2",
		"region:servers", "region:servers:v2/provider-create-gates", "region:images",
		"region:filestorage:v2", "region:filestoragesnapshots:v2",
		"region:identities", "region:networks", "region:securitygroups",
	} {
		acl.addEndpoint(endpoint, operations...)
	}

	recorder := &authz.Recorder{}

	return authz.NewContext(acl.buildContext(t.Context()), recorder), recorder
}

type objectWrite struct {
	name     string
	endpoint string
	action   string
	id       string
	// hidden is set where a refusal answers 404 rather than 403.
	hidden bool
	call   func(ctx context.Context, args common.ClientArgs, id string) error
}

func networkID(id string) regionids.NetworkID { return regionids.NetworkID(uuid.MustParse(id)) }
func serverID(id string) regionids.ServerID   { return regionids.ServerID(uuid.MustParse(id)) }

// objectWrites is every v2 write on an existing object, with the action its
// audit record must carry.
//
//nolint:gochecknoglobals
var objectWrites = []objectWrite{
	{"network update", "region:networks:v2", "update", auditNetwork, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		_, err := network.New(args).Update(ctx, networkID(id), &openapi.NetworkV2Update{})
		return err
	}},
	{"network delete", "region:networks:v2", "delete", auditNetwork, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		return network.New(args).DeleteV2(ctx, networkID(id))
	}},
	{"network reference", "region:networks:v2/references", "reference", auditNetwork, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		return network.New(args).ReferenceCreateV2(ctx, networkID(id), "example.com/ref")
	}},
	{"network unreference", "region:networks:v2/references", "unreference", auditNetwork, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		return network.New(args).ReferenceDeleteV2(ctx, networkID(id), "example.com/ref")
	}},
	{"security group update", "region:securitygroups:v2", "update", auditSecurityGroup, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		_, err := securitygroup.New(args).UpdateV2(ctx, regionids.SecurityGroupID(uuid.MustParse(id)), &openapi.SecurityGroupV2Update{})
		return err
	}},
	{"security group delete", "region:securitygroups:v2", "delete", auditSecurityGroup, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		return securitygroup.New(args).DeleteV2(ctx, regionids.SecurityGroupID(uuid.MustParse(id)))
	}},
	{"volume update", "region:volumes:v2", "update", auditVolume, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		_, err := volume.New(args).UpdateV2(ctx, regionids.VolumeID(uuid.MustParse(id)), &openapi.VolumeV2Update{})
		return err
	}},
	{"volume delete", "region:volumes:v2", "delete", auditVolume, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		return volume.New(args).DeleteV2(ctx, regionids.VolumeID(uuid.MustParse(id)))
	}},
	{"load balancer update", "region:loadbalancers:v2", "update", auditLoadBalancer, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		_, err := loadbalancer.New(args).UpdateV2(ctx, regionids.LoadBalancerID(uuid.MustParse(id)), &openapi.LoadBalancerV2Update{})
		return err
	}},
	{"load balancer delete", "region:loadbalancers:v2", "delete", auditLoadBalancer, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		return loadbalancer.New(args).DeleteV2(ctx, regionids.LoadBalancerID(uuid.MustParse(id)))
	}},
	{"ssh certificate authority delete", "region:sshcertificateauthorities:v2", "delete", auditSSHCA, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		return sshcertificateauthority.New(args).DeleteV2(ctx, regionids.SSHCertificateAuthorityID(uuid.MustParse(id)))
	}},
	{"server update", "region:servers", "update", auditServer, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		_, err := server.NewClientV2(args).UpdateV2(ctx, serverID(id), &openapi.ServerV2Update{})
		return err
	}},
	{"server delete", "region:servers", "delete", auditServer, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		return server.NewClientV2(args).DeleteV2(ctx, serverID(id))
	}},
	{"server start", "region:servers", "start", auditServer, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		return server.NewClientV2(args).StartV2(ctx, serverID(id))
	}},
	{"server stop", "region:servers", "stop", auditServer, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		return server.NewClientV2(args).StopV2(ctx, serverID(id))
	}},
	{"server soft reboot", "region:servers", "softreboot", auditServer, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		return server.NewClientV2(args).RebootV2(ctx, serverID(id), false)
	}},
	{"server hard reboot", "region:servers", "hardreboot", auditServer, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		return server.NewClientV2(args).RebootV2(ctx, serverID(id), true)
	}},
	{"server snapshot", "region:servers", "snapshot", auditServer, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		_, err := server.NewClientV2(args).CreateV2Snapshot(ctx, serverID(id), &openapi.SnapshotCreate{})
		return err
	}},
	{"server provider create gate", "region:servers:v2/provider-create-gates", "satisfy-create-gate", auditServer, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		return server.NewClientV2(args).SatisfyProviderCreateGate(ctx, serverID(id), &openapi.ServerProviderCreateGateAction{
			ConditionType: "example", Reason: "test", Message: "test",
		})
	}},
	{"server provider create gate withhold", "region:servers:v2/provider-create-gates", "withhold-create-gate", auditServer, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		return server.NewClientV2(args).WithholdProviderCreateGate(ctx, serverID(id), &openapi.ServerProviderCreateGateWithholdAction{
			ConditionType: "example", Reason: "test", Message: "test",
		})
	}},
	{"file storage update", "region:filestorage:v2", "update", auditFileStorage, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		_, err := storage.New(args).Update(ctx, regionids.FileStorageID(uuid.MustParse(id)), &openapi.StorageV2Update{})
		return err
	}},
	{"file storage delete", "region:filestorage:v2", "delete", auditFileStorage, false, func(ctx context.Context, args common.ClientArgs, id string) error {
		return storage.New(args).Delete(ctx, regionids.FileStorageID(uuid.MustParse(id)))
	}},
	{"file storage snapshot delete", "region:filestoragesnapshots:v2", "delete", auditSnapshot, true, func(ctx context.Context, args common.ClientArgs, id string) error {
		return storage.New(args).DeleteSnapshot(ctx, regionids.FileStorageID(uuid.MustParse(auditFileStorage)), regionids.FileStorageSnapshotID(uuid.MustParse(id)))
	}},
}

// A caller who may only read is refused every write, and each refusal is
// recorded as what was attempted, on what, and where.  Actions on a server,
// snapshot included, need update.
func TestWritesRecordTheirRefusal(t *testing.T) {
	t.Parallel()

	for _, w := range objectWrites {
		t.Run(w.name, func(t *testing.T) {
			t.Parallel()

			ctx, recorder := auditContext(t, identityapi.Read)

			args, e := observedArgs(t, auditObjects()...)

			err := w.call(ctx, args, w.id)
			require.Error(t, err)
			require.Zero(t, e.writes.Load(), "a refused write changes nothing")
			require.Zero(t, e.lookups.Load(), "a refused write never reaches a cloud")

			if w.hidden {
				require.True(t, coreerrors.IsHTTPNotFound(err), "expected not found, got: %v", err)
			} else {
				require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)
			}

			request, state := recorder.Request()
			require.Equal(t, authz.Checked, state)
			require.False(t, request.Allowed)
			require.Equal(t, w.endpoint, request.Endpoint)
			require.Equal(t, w.action, request.Operation.Action)
			require.Equal(t, uuid.MustParse(w.id), request.ObjectID)
			require.Equal(t, "name-"+w.id[len(w.id)-1:], request.ObjectName)
			require.Equal(t, auditProject, request.Scope.ProjectID.String())
			require.Len(t, authz.Primaries(recorder.Decisions()), 1)
			require.Empty(t, recorder.Defects())
		})
	}
}

// access is what each action requires: actions on a server change it.
func access(action string) identityapi.AclOperation {
	switch action {
	case "delete", "unreference":
		return identityapi.Delete
	case "reference":
		return identityapi.Create
	default:
		return identityapi.Update
	}
}

// guarded runs a write, turning a panic after its check into an error: this
// harness has no identity service or cloud, so an allowed write may fail in
// any way once it is past its check.  Only what was recorded matters here.
func guarded(call func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: %v", errNoProvider, r)
		}
	}()

	return call()
}

// Holding exactly the access a write requires is enough, and the allowed
// write is recorded as the request's own operation, with no defect.
func TestExactAccessIsEnough(t *testing.T) {
	t.Parallel()

	for _, w := range objectWrites {
		t.Run(w.name, func(t *testing.T) {
			t.Parallel()

			recorder := &authz.Recorder{}

			acl := newOrganisationACLBuilder(auditOrg)
			for _, endpoint := range []string{"region:networks:v2", "region:securitygroups:v2", "region:volumes:v2", "region:servers", "region:filestorage:v2"} {
				acl.addEndpoint(endpoint, identityapi.Read)
			}

			acl.addEndpoint("region:images", identityapi.Create)
			acl.addEndpoint(w.endpoint, access(w.action))

			ctx := authz.NewContext(acl.buildContext(t.Context()), recorder)

			args, _ := observedArgs(t, auditObjects()...)

			err := guarded(func() error { return w.call(ctx, args, w.id) })
			require.False(t, coreerrors.IsForbidden(err), "refused: %v", err)

			request, state := recorder.Request()
			require.Equal(t, authz.Checked, state)
			require.True(t, request.Allowed)
			require.Equal(t, w.endpoint, request.Endpoint)
			require.Equal(t, w.action, request.Operation.Action)
			require.Equal(t, uuid.MustParse(w.id), request.ObjectID)
			require.Equal(t, "name-"+w.id[len(w.id)-1:], request.ObjectName)
			require.Equal(t, auditProject, request.Scope.ProjectID.String())
			require.Len(t, authz.Primaries(recorder.Decisions()), 1)
			require.Empty(t, recorder.Defects())
		})
	}
}

// Holding exactly create in the project is enough for every create, and the
// allowed create is recorded as the request's own operation, with no defect.
func TestExactAccessIsEnoughToCreate(t *testing.T) {
	t.Parallel()

	creates := append([]networkScopedCreate{
		{"network", "region:networks:v2", func(ctx context.Context, args common.ClientArgs) error {
			request := &openapi.NetworkV2Create{}
			request.Metadata.Name = "new"
			request.Spec.OrganizationId = auditOrg
			request.Spec.ProjectId = auditProject

			_, err := network.New(args).CreateV2(ctx, request)

			return err
		}},
		{"ssh certificate authority", "region:sshcertificateauthorities:v2", func(ctx context.Context, args common.ClientArgs) error {
			request := &openapi.SshCertificateAuthorityV2Create{}
			request.Metadata.Name = "new"
			request.Spec.OrganizationId = auditOrg
			request.Spec.ProjectId = auditProject

			_, err := sshcertificateauthority.New(args).CreateV2(ctx, request)

			return err
		}},
		{"file storage", "region:filestorage:v2", func(ctx context.Context, args common.ClientArgs) error {
			request := &openapi.StorageV2Create{}
			request.Metadata.Name = "new"
			request.Spec.OrganizationId = auditOrg
			request.Spec.ProjectId = auditProject

			_, err := storage.New(args).CreateV2(ctx, request)

			return err
		}},
		{"file storage snapshot", "region:filestoragesnapshots:v2", func(ctx context.Context, args common.ClientArgs) error {
			request := &openapi.FileStorageSnapshotV2Create{}
			request.Metadata.Name = "new"

			_, err := storage.New(args).CreateSnapshot(ctx, regionids.FileStorageID(uuid.MustParse(auditFileStorage)), request)

			return err
		}},
	}, networkScopedCreates...)

	for _, c := range creates {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			// Project grants, so the create check needs no identity service.
			// Creates record who asked, so the caller has a principal.
			recorder := &authz.Recorder{}
			ctx := authz.NewContext(withPrincipal(newOrganisationACLBuilder(auditOrg).
				addEndpoint("region:networks:v2", identityapi.Read).
				addProjectEndpoint(auditProject, c.endpoint, identityapi.Create).
				buildContext(t.Context())), recorder)

			args, _ := observedArgs(t, auditObjects()...)

			err := guarded(func() error { return c.call(ctx, args) })
			require.False(t, coreerrors.IsForbidden(err), "refused: %v", err)

			request, state := recorder.Request()
			require.Equal(t, authz.Checked, state)
			require.True(t, request.Allowed)
			require.Equal(t, c.endpoint, request.Endpoint)
			require.Equal(t, "create", request.Operation.Action)
			require.Equal(t, "new", request.ObjectName)
			require.Equal(t, auditProject, request.Scope.ProjectID.String())
			require.Empty(t, recorder.Defects())
		})
	}
}

// Deleting something already being deleted is still a delete: the caller must
// hold delete, and a refusal is recorded and changes nothing.
func TestDeleteWhileDeletingIsAuthorized(t *testing.T) {
	t.Parallel()

	for _, w := range objectWrites {
		if w.action != "delete" {
			continue
		}

		t.Run(w.name, func(t *testing.T) {
			t.Parallel()

			ctx, recorder := auditContext(t, identityapi.Read)

			args, e := observedArgs(t, deletingObjects()...)

			err := w.call(ctx, args, w.id)
			require.Error(t, err)
			require.Zero(t, e.writes.Load())

			request, state := recorder.Request()
			require.Equal(t, authz.Checked, state)
			require.False(t, request.Allowed)
			require.Equal(t, uuid.MustParse(w.id), request.ObjectID)
		})
	}
}

// A write on something that does not exist is a 404, and is still recorded as
// what was attempted, naming the ID asked for.  No scope is known.
func TestWritesOnMissingObjectsAreRecorded(t *testing.T) {
	t.Parallel()

	for _, w := range objectWrites {
		t.Run(w.name, func(t *testing.T) {
			t.Parallel()

			ctx, recorder := auditContext(t, identityapi.Create, identityapi.Read, identityapi.Update, identityapi.Delete)

			err := w.call(ctx, auditArgs(t), auditMissing)
			require.True(t, coreerrors.IsHTTPNotFound(err), "expected not found, got: %v", err)

			request, state := recorder.Request()
			require.Equal(t, authz.Declared, state)
			require.Equal(t, w.endpoint, request.Endpoint)
			require.Equal(t, w.action, request.Operation.Action)
			require.Equal(t, uuid.MustParse(auditMissing), request.ObjectID)
			require.False(t, request.Scope.Organization())
			require.Empty(t, recorder.Defects())
		})
	}
}

type networkScopedCreate struct {
	name     string
	endpoint string
	call     func(ctx context.Context, args common.ClientArgs) error
}

//nolint:gochecknoglobals
var networkScopedCreates = []networkScopedCreate{
	{"security group", "region:securitygroups:v2", func(ctx context.Context, args common.ClientArgs) error {
		request := &openapi.SecurityGroupV2Create{}
		request.Metadata.Name = "new"
		request.Spec.NetworkId = networkID(auditNetwork)

		_, err := securitygroup.New(args).CreateV2(ctx, request)

		return err
	}},
	{"volume", "region:volumes:v2", func(ctx context.Context, args common.ClientArgs) error {
		request := &openapi.VolumeV2Create{}
		request.Metadata.Name = "new"
		request.Spec.NetworkId = networkID(auditNetwork)

		_, err := volume.New(args).CreateV2(ctx, request)

		return err
	}},
	{"load balancer", "region:loadbalancers:v2", func(ctx context.Context, args common.ClientArgs) error {
		request := &openapi.LoadBalancerV2Create{}
		request.Metadata.Name = "new"
		request.Spec.NetworkId = networkID(auditNetwork)

		_, err := loadbalancer.New(args).CreateV2(ctx, request)

		return err
	}},
	{"server", "region:servers", func(ctx context.Context, args common.ClientArgs) error {
		request := &openapi.ServerV2Create{}
		request.Metadata.Name = "new"
		request.Spec.NetworkId = networkID(auditNetwork)

		_, err := server.NewClientV2(args).CreateV2(ctx, request)

		return err
	}},
}

// A create scoped by a network is recorded in the network's project even when
// the caller may not read the network, and when the caller may not create.
func TestNetworkScopedCreatesRecordTheirProject(t *testing.T) {
	t.Parallel()

	for _, c := range networkScopedCreates {
		t.Run(c.name+" refused the network", func(t *testing.T) {
			t.Parallel()

			recorder := &authz.Recorder{}
			ctx := authz.NewContext(newOrganisationACLBuilder(auditOrg).
				addProjectEndpoint(auditProject, c.endpoint, identityapi.Create).
				buildContext(t.Context()), recorder)

			err := c.call(ctx, auditArgs(t, auditObjects()...))
			require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)

			// The create was allowed before the network was refused, so the
			// record carries the project the create was checked in.
			request, state := recorder.Request()
			require.Equal(t, authz.Checked, state)
			require.True(t, request.Allowed)
			require.Equal(t, c.endpoint, request.Endpoint)
			require.Equal(t, "create", request.Operation.Action)
			require.Equal(t, "new", request.ObjectName)
			require.Equal(t, auditProject, request.Scope.ProjectID.String())
		})

		t.Run(c.name+" refused the create", func(t *testing.T) {
			t.Parallel()

			recorder := &authz.Recorder{}
			ctx := authz.NewContext(newOrganisationACLBuilder(auditOrg).
				addEndpoint("region:networks:v2", identityapi.Read).
				buildContext(t.Context()), recorder)

			err := c.call(ctx, auditArgs(t, auditObjects()...))
			require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)

			request, state := recorder.Request()
			require.Equal(t, authz.Checked, state)
			require.False(t, request.Allowed)
			require.Equal(t, "create", request.Operation.Action)
			require.Equal(t, auditProject, request.Scope.ProjectID.String())
		})
	}
}

// A request that fails before its own check is still recorded as what it
// attempted.
func TestWritesFailingBeforeTheirCheckAreRecorded(t *testing.T) {
	t.Parallel()

	type early struct {
		name     string
		endpoint string
		action   string
		id       string
		call     func(ctx context.Context, args common.ClientArgs) error
	}

	writes := []early{
		{"network create with no organization", "region:networks:v2", "create", "", func(ctx context.Context, args common.ClientArgs) error {
			request := &openapi.NetworkV2Create{}
			request.Metadata.Name = "new"

			_, err := network.New(args).CreateV2(ctx, request)

			return err
		}},
		{"ssh certificate authority create with no organization", "region:sshcertificateauthorities:v2", "create", "", func(ctx context.Context, args common.ClientArgs) error {
			request := &openapi.SshCertificateAuthorityV2Create{}
			request.Metadata.Name = "new"

			_, err := sshcertificateauthority.New(args).CreateV2(ctx, request)

			return err
		}},
		{"file storage create with no organization", "region:filestorage:v2", "create", "", func(ctx context.Context, args common.ClientArgs) error {
			request := &openapi.StorageV2Create{}
			request.Metadata.Name = "new"

			_, err := storage.New(args).CreateV2(ctx, request)

			return err
		}},
		{"file storage snapshot create on a missing parent", "region:filestoragesnapshots:v2", "create", "", func(ctx context.Context, args common.ClientArgs) error {
			request := &openapi.FileStorageSnapshotV2Create{}
			request.Metadata.Name = "new"

			_, err := storage.New(args).CreateSnapshot(ctx, regionids.FileStorageID(uuid.MustParse(auditMissing)), request)

			return err
		}},
		{"provider create gate with no condition", "region:servers:v2/provider-create-gates", "satisfy-create-gate", auditServer, func(ctx context.Context, args common.ClientArgs) error {
			return server.NewClientV2(args).SatisfyProviderCreateGate(ctx, serverID(auditServer), &openapi.ServerProviderCreateGateAction{})
		}},
		{"provider create gate withhold with no condition", "region:servers:v2/provider-create-gates", "withhold-create-gate", auditServer, func(ctx context.Context, args common.ClientArgs) error {
			return server.NewClientV2(args).WithholdProviderCreateGate(ctx, serverID(auditServer), &openapi.ServerProviderCreateGateWithholdAction{})
		}},
	}

	for _, w := range writes {
		t.Run(w.name, func(t *testing.T) {
			t.Parallel()

			ctx, recorder := auditContext(t, identityapi.Create, identityapi.Read, identityapi.Update, identityapi.Delete)

			require.Error(t, w.call(ctx, auditArgs(t, auditObjects()...)))

			request, state := recorder.Request()
			require.Equal(t, authz.Declared, state)
			require.Equal(t, w.endpoint, request.Endpoint)
			require.Equal(t, w.action, request.Operation.Action)

			if w.id != "" {
				require.Equal(t, uuid.MustParse(w.id), request.ObjectID)
			} else {
				require.Equal(t, "new", request.ObjectName)
			}
		})
	}
}

// A v1 server update needs update; create, which it used to check, is not
// enough.
func TestV1ServerUpdateNeedsUpdate(t *testing.T) {
	t.Parallel()

	h, err := New(auditArgs(t), &Options{})
	require.NoError(t, err)

	recorder := &authz.Recorder{}
	ctx := authz.NewContext(newOrganisationACLBuilder(auditOrg).
		addEndpoint("region:servers", identityapi.Create).
		buildContext(t.Context()), recorder)

	w := httptest.NewRecorder()
	h.PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerID(w,
		httptest.NewRequestWithContext(ctx, http.MethodPut, "/", strings.NewReader("{}")),
		identityids.OrganizationID(uuid.MustParse(auditOrg)), identityids.ProjectID(uuid.MustParse(auditProject)),
		regionids.IdentityID(uuid.MustParse(auditIdentity)), serverID(auditServer))

	require.Equal(t, http.StatusForbidden, w.Code)

	request, _ := recorder.Request()
	require.Equal(t, "update", request.Operation.Action)
}

// A delete retried after a conflict checks twice, and is still one request
// with no defect.
func TestRetriedDeleteIsOneRecord(t *testing.T) {
	t.Parallel()

	conflicted := false

	kube := fake.NewClientBuilder().
		WithScheme(fakeClientWithSchema(t).Scheme()).
		WithObjects(auditObjects()...).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if !conflicted {
					conflicted = true

					return kerrors.NewConflict(schema.GroupResource{Resource: "securitygroups"}, obj.GetName(), nil)
				}

				return c.Delete(ctx, obj, opts...)
			},
		}).Build()

	ctx, recorder := auditContext(t, identityapi.Read, identityapi.Delete)

	args := common.ClientArgs{Client: kube, Namespace: auditNamespace}

	require.NoError(t, securitygroup.New(args).DeleteV2(ctx, regionids.SecurityGroupID(uuid.MustParse(auditSecurityGroup))))
	require.True(t, conflicted)

	request, state := recorder.Request()
	require.Equal(t, authz.Checked, state)
	require.True(t, request.Allowed)
	require.Len(t, authz.Primaries(recorder.Decisions()), 1)
	require.Empty(t, recorder.Defects())
}

// v1 handlers check before anything is fetched, naming the object by its path
// ID, so a refusal is recorded with what was attempted and where.
func TestV1WritesRecordTheirRefusal(t *testing.T) {
	t.Parallel()

	org := identityids.OrganizationID(uuid.MustParse(auditOrg))
	project := identityids.ProjectID(uuid.MustParse(auditProject))
	identityID := regionids.IdentityID(uuid.MustParse(auditIdentity))

	type v1Write struct {
		name     string
		endpoint string
		action   string
		id       string
		call     func(h *Handler, w http.ResponseWriter, r *http.Request)
	}

	writes := []v1Write{
		{"identity create", "region:identities", "create", "", func(h *Handler, w http.ResponseWriter, r *http.Request) {
			h.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentities(w, r, org, project)
		}},
		{"identity delete", "region:identities", "delete", auditIdentity, func(h *Handler, w http.ResponseWriter, r *http.Request) {
			h.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityID(w, r, org, project, identityID)
		}},
		{"network create", "region:networks", "create", "", func(h *Handler, w http.ResponseWriter, r *http.Request) {
			h.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDNetworks(w, r, org, project, identityID)
		}},
		{"network delete", "region:networks", "delete", auditNetwork, func(h *Handler, w http.ResponseWriter, r *http.Request) {
			h.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDNetworksNetworkID(w, r, org, project, identityID, networkID(auditNetwork))
		}},
		{"security group create", "region:securitygroups", "create", "", func(h *Handler, w http.ResponseWriter, r *http.Request) {
			h.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroups(w, r, org, project, identityID)
		}},
		{"security group delete", "region:securitygroups", "delete", auditSecurityGroup, func(h *Handler, w http.ResponseWriter, r *http.Request) {
			h.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupID(w, r, org, project, identityID, regionids.SecurityGroupID(uuid.MustParse(auditSecurityGroup)))
		}},
		{"security group update", "region:securitygroups", "update", auditSecurityGroup, func(h *Handler, w http.ResponseWriter, r *http.Request) {
			h.PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupID(w, r, org, project, identityID, regionids.SecurityGroupID(uuid.MustParse(auditSecurityGroup)))
		}},
		{"server create", "region:servers", "create", "", func(h *Handler, w http.ResponseWriter, r *http.Request) {
			h.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServers(w, r, org, project, identityID)
		}},
		{"server delete", "region:servers", "delete", auditServer, func(h *Handler, w http.ResponseWriter, r *http.Request) {
			h.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerID(w, r, org, project, identityID, serverID(auditServer))
		}},
		{"server update", "region:servers", "update", auditServer, func(h *Handler, w http.ResponseWriter, r *http.Request) {
			h.PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerID(w, r, org, project, identityID, serverID(auditServer))
		}},
		{"server hard reboot", "region:servers", "hardreboot", auditServer, func(h *Handler, w http.ResponseWriter, r *http.Request) {
			h.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDHardreboot(w, r, org, project, identityID, serverID(auditServer))
		}},
		{"server soft reboot", "region:servers", "softreboot", auditServer, func(h *Handler, w http.ResponseWriter, r *http.Request) {
			h.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDSoftreboot(w, r, org, project, identityID, serverID(auditServer))
		}},
		{"server start", "region:servers", "start", auditServer, func(h *Handler, w http.ResponseWriter, r *http.Request) {
			h.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDStart(w, r, org, project, identityID, serverID(auditServer))
		}},
		{"server stop", "region:servers", "stop", auditServer, func(h *Handler, w http.ResponseWriter, r *http.Request) {
			h.PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDStop(w, r, org, project, identityID, serverID(auditServer))
		}},
		{"image create", "region:images", "create", "", func(h *Handler, w http.ResponseWriter, r *http.Request) {
			h.PostApiV1OrganizationsOrganizationIDRegionsRegionIDImages(w, r, org, regionids.RegionID(uuid.New()))
		}},
		{"image delete", "region:images", "delete", auditImage, func(h *Handler, w http.ResponseWriter, r *http.Request) {
			h.DeleteApiV1OrganizationsOrganizationIDRegionsRegionIDImagesImageID(w, r, org, regionids.RegionID(uuid.New()), regionids.ImageID(uuid.MustParse(auditImage)))
		}},
	}

	for _, write := range writes {
		t.Run(write.name, func(t *testing.T) {
			t.Parallel()

			args := auditArgs(t)

			h, err := New(args, &Options{})
			require.NoError(t, err)

			ctx, recorder := auditContext(t, identityapi.Read)

			w := httptest.NewRecorder()
			write.call(h, w, httptest.NewRequestWithContext(ctx, http.MethodPost, "/", strings.NewReader("{}")))

			require.Equal(t, http.StatusForbidden, w.Code)

			request, state := recorder.Request()
			require.Equal(t, authz.Checked, state)
			require.False(t, request.Allowed)
			require.Equal(t, write.endpoint, request.Endpoint)
			require.Equal(t, write.action, request.Operation.Action)
			require.Equal(t, auditOrg, request.Scope.OrganizationID.String())

			if write.id != "" {
				require.Equal(t, uuid.MustParse(write.id), request.ObjectID)
			}
		})
	}
}

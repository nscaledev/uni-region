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

// Package coordinator materializes attachment records from Server volume intent.
package coordinator

import (
	"context"
	"sort"

	"github.com/google/uuid"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/manager/options"
	"github.com/unikorn-cloud/core/pkg/util"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// Factory builds the Volume-keyed attachment coordinator.
type Factory struct{}

var _ coremanager.ControllerFactory = &Factory{}

// Metadata returns the coordinator service descriptor.
func (*Factory) Metadata() util.ServiceDescriptor {
	return constants.ServiceDescriptor()
}

// Options returns no controller-specific options.
func (*Factory) Options() coremanager.ControllerOptions {
	return nil
}

// Reconciler returns the Volume-keyed coordinator.
func (*Factory) Reconciler(_ *options.Options, _ coremanager.ControllerOptions, manager manager.Manager) reconcile.Reconciler {
	return &reconciler{client: manager.GetClient(), scheme: manager.GetScheme()}
}

// RegisterWatches enqueues Volumes directly and maps Server intent to Volume IDs.
func (*Factory) RegisterWatches(manager manager.Manager, controller controller.Controller) error {
	if err := controller.Watch(source.Kind(manager.GetCache(), &unikornv1.Volume{}, &handler.TypedEnqueueRequestForObject[*unikornv1.Volume]{}, &predicate.TypedGenerationChangedPredicate[*unikornv1.Volume]{})); err != nil {
		return err
	}

	if err := controller.Watch(source.Kind(manager.GetCache(), &unikornv1.Server{}, handler.TypedEnqueueRequestsFromMapFunc(func(_ context.Context, server *unikornv1.Server) []reconcile.Request {
		requests := make([]reconcile.Request, 0, len(server.Spec.Volumes))
		for _, volume := range server.Spec.Volumes {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKey{Namespace: server.Namespace, Name: volume.ID}})
		}

		return requests
	}), &predicate.TypedGenerationChangedPredicate[*unikornv1.Server]{})); err != nil {
		return err
	}

	return controller.Watch(source.Kind(manager.GetCache(), &unikornv1.ServerVolumeAttachment{}, handler.TypedEnqueueRequestsFromMapFunc(func(_ context.Context, attachment *unikornv1.ServerVolumeAttachment) []reconcile.Request {
		return []reconcile.Request{{NamespacedName: client.ObjectKey{Namespace: attachment.Namespace, Name: attachment.Spec.VolumeID}}}
	}), &predicate.TypedGenerationChangedPredicate[*unikornv1.ServerVolumeAttachment]{}))
}

// Schemes returns the Region resource scheme.
func (*Factory) Schemes() []coreclient.SchemeAdder {
	return []coreclient.SchemeAdder{unikornv1.AddToScheme}
}

type reconciler struct {
	client client.Client
	scheme *runtime.Scheme
}

func attachmentName(serverID, volumeID string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("server-volume-attachment/"+serverID+"/"+volumeID)).String()
}

func desiredServerIDs(servers *unikornv1.ServerList, volumeID string) map[string]*unikornv1.Server {
	result := map[string]*unikornv1.Server{}
	for i := range servers.Items {
		server := &servers.Items[i]
		for _, desired := range server.Spec.Volumes {
			if desired.ID == volumeID {
				result[server.Name] = server
			}
		}
	}

	return result
}

func oldestAttachment(attachments []unikornv1.ServerVolumeAttachment) *unikornv1.ServerVolumeAttachment {
	if len(attachments) == 0 {
		return nil
	}

	sort.Slice(attachments, func(i, j int) bool {
		left, right := attachments[i], attachments[j]
		if left.CreationTimestamp.Equal(&right.CreationTimestamp) {
			return left.Name < right.Name
		}

		return left.CreationTimestamp.Before(&right.CreationTimestamp)
	})

	return &attachments[0]
}

func (r *reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	volume := &unikornv1.Volume{}
	if err := r.client.Get(ctx, request.NamespacedName, volume); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	servers := &unikornv1.ServerList{}
	if err := r.client.List(ctx, servers, client.InNamespace(volume.Namespace)); err != nil {
		return reconcile.Result{}, err
	}

	desired := desiredServerIDs(servers, volume.Name)
	for _, server := range desired {
		attachment := &unikornv1.ServerVolumeAttachment{}
		attachment.Name = attachmentName(server.Name, volume.Name)
		attachment.Namespace = volume.Namespace

		_, err := controllerutil.CreateOrUpdate(ctx, r.client, attachment, func() error {
			attachment.Spec.ServerID = server.Name
			attachment.Spec.VolumeID = volume.Name

			return controllerutil.SetControllerReference(server, attachment, r.scheme, controllerutil.WithBlockOwnerDeletion(true))
		})
		if err != nil {
			return reconcile.Result{}, err
		}
	}

	attachments := &unikornv1.ServerVolumeAttachmentList{}
	if err := r.client.List(ctx, attachments, client.InNamespace(volume.Namespace)); err != nil {
		return reconcile.Result{}, err
	}

	candidates := make([]unikornv1.ServerVolumeAttachment, 0, len(attachments.Items))
	cleanupPending := false
	for i := range attachments.Items {
		attachment := &attachments.Items[i]
		if attachment.Spec.VolumeID != volume.Name {
			continue
		}

		if _, ok := desired[attachment.Spec.ServerID]; !ok {
			if attachment.DeletionTimestamp.IsZero() {
				if err := r.client.Delete(ctx, attachment); err != nil {
					return reconcile.Result{}, err
				}
			}
			cleanupPending = true

			continue
		}

		if attachment.DeletionTimestamp.IsZero() {
			candidates = append(candidates, *attachment)
		}
	}

	winner := oldestAttachment(candidates)
	if winner == nil && !cleanupPending {
		if volume.Spec.ClaimRef != nil {
			volume.Spec.ClaimRef = nil
			if err := r.client.Update(ctx, volume); err != nil {
				return reconcile.Result{}, err
			}
		}

		return reconcile.Result{}, nil
	}

	if volume.Spec.ClaimRef == nil {
		volume.Spec.ClaimRef = &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: winner.Spec.ServerID}
		if err := r.client.Update(ctx, volume); err != nil {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

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

package reaper

import (
	"context"
	"errors"
	"fmt"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/region"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	ErrInvalidClient = errors.New("client invalid")

	ErrDataMissing = errors.New("data missing")

	ErrUnexpectedType = errors.New("unexpected type")

	ErrCleanup = errors.New("cleanup failed")
)

// Seasons don't fear the reaper, nor do wind or the sun or the rain.
// Peforms asynchronous cleanup tasks.
type Reaper struct {
	client    client.Client
	namespace string
}

func New(client client.Client, namespace string) *Reaper {
	return &Reaper{
		client:    client,
		namespace: namespace,
	}
}

func (r *Reaper) Run(ctx context.Context) error {
	log := log.FromContext(ctx)

	watchingClient, ok := r.client.(client.WithWatch)
	if !ok {
		return fmt.Errorf("%w: client does not implement watches", ErrInvalidClient)
	}

	// TODO: This is insecure, enything can raise an event and have identities deleted.
	// We should syncronously trigger the cleanup from various component deprovisioners
	// but then you are faced with the problem that there is no access token to allow
	// API access.
	options := &client.ListOptions{
		FieldSelector: fields.SelectorFromSet(fields.Set{
			"reason": coreconstants.IdentityCleanupReadyEventReason,
		}),
	}

	// Please note when using Kubernetes watches of events that you may see
	// some historical events for things in the last hour.
	go func() {
		var zeroEvent watch.Event

		for {
			var events corev1.EventList

			watcher, err := watchingClient.Watch(ctx, &events, options)
			if err != nil {
				log.Error(err, "failed to setup watch")
				continue
			}

			eventStream := watcher.ResultChan()

			for {
				event := <-eventStream

				// Zero value returned, closed channel, this happens, start it back
				// up again...
				if event == zeroEvent {
					break
				}

				log.V(1).Info("witnessed an event", "event", event)

				if event.Type != watch.Added {
					continue
				}

				realEvent, ok := event.Object.(*corev1.Event)
				if !ok {
					log.Error(ErrUnexpectedType, "unable to decode event")
				}

				if err := r.handleEvent(ctx, realEvent); err != nil {
					log.Error(err, "event handling failed")
				}
			}
		}
	}()

	return nil
}

func (r *Reaper) handleEvent(ctx context.Context, event *corev1.Event) error {
	log := log.FromContext(ctx)

	log.Info("processing cluster deletion event", "event", event)

	identityID, ok := event.Annotations[coreconstants.CloudIdentityAnnotation]
	if !ok {
		return fmt.Errorf("%w: identity annotation not present", ErrDataMissing)
	}

	identity := &unikornv1.Identity{}

	if err := r.client.Get(ctx, client.ObjectKey{Namespace: r.namespace, Name: identityID}, identity); err != nil {
		return err
	}

	provider, err := region.NewClient(r.client, r.namespace).Provider(ctx, identity.Labels[constants.RegionLabel])
	if err != nil {
		return fmt.Errorf("%w: failed to create provider client", err)
	}

	if err := provider.DeleteIdentity(ctx, identity); err != nil {
		return fmt.Errorf("%w: failed to delete identity", err)
	}

	return nil
}

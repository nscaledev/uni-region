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
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/manager/options"
	"github.com/unikorn-cloud/core/pkg/util"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/managers"
	volumeprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/volume"

	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// Factory builds the Volume controller.
type Factory struct {
	managers.ProvidersInit
}

var _ interface {
	coremanager.ControllerFactory
	coremanager.ControllerInitializer
} = &Factory{}

// Metadata returns the application, version and revision.
func (*Factory) Metadata() util.ServiceDescriptor {
	return constants.ServiceDescriptor()
}

// Options returns flags passed to the Volume provisioner.
func (*Factory) Options() coremanager.ControllerOptions {
	return &volumeprovisioner.Options{}
}

// Reconciler returns a Volume reconciler.
func (f *Factory) Reconciler(options *options.Options, controllerOptions coremanager.ControllerOptions, manager manager.Manager) reconcile.Reconciler {
	return coremanager.NewReconciler(options, controllerOptions, manager, f.ProvisionerCreate(volumeprovisioner.New))
}

func volumeDeletionRequested(e event.TypedUpdateEvent[*unikornv1.Volume]) bool {
	if e.ObjectOld == nil || e.ObjectNew == nil {
		return false
	}

	return e.ObjectOld.DeletionTimestamp == nil && e.ObjectNew.DeletionTimestamp != nil
}

// RegisterWatches registers the Volume desired-state watch.
func (*Factory) RegisterWatches(manager manager.Manager, controller controller.Controller) error {
	volumePredicate := predicate.Or(
		predicate.TypedGenerationChangedPredicate[*unikornv1.Volume]{},
		predicate.TypedFuncs[*unikornv1.Volume]{
			UpdateFunc: volumeDeletionRequested,
		},
	)

	return controller.Watch(source.Kind(
		manager.GetCache(),
		&unikornv1.Volume{},
		&handler.TypedEnqueueRequestForObject[*unikornv1.Volume]{},
		volumePredicate,
	))
}

// Schemes returns the Region resource scheme used by the controller.
func (*Factory) Schemes() []coreclient.SchemeAdder {
	return []coreclient.SchemeAdder{
		unikornv1.AddToScheme,
	}
}

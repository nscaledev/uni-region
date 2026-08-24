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

// Package servervolumeattachment wires the attachment-keyed UNI lifecycle controller.
package servervolumeattachment

import (
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/manager/options"
	"github.com/unikorn-cloud/core/pkg/util"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	regionmanagers "github.com/unikorn-cloud/region/pkg/managers"
	attachmentprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/server-volume-attachment"

	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type Factory struct {
	regionmanagers.ProvidersInit
}

var _ interface {
	coremanager.ControllerFactory
	coremanager.ControllerInitializer
} = &Factory{}

func (*Factory) Metadata() util.ServiceDescriptor       { return constants.ServiceDescriptor() }
func (*Factory) Options() coremanager.ControllerOptions { return nil }

func (f *Factory) Reconciler(options *options.Options, controllerOptions coremanager.ControllerOptions, manager manager.Manager) reconcile.Reconciler {
	return coremanager.NewReconciler(options, controllerOptions, manager, f.ProvisionerCreate(attachmentprovisioner.New))
}

func (*Factory) RegisterWatches(manager manager.Manager, controller controller.Controller) error {
	return controller.Watch(source.Kind(manager.GetCache(), &unikornv1.ServerVolumeAttachment{}, &handler.TypedEnqueueRequestForObject[*unikornv1.ServerVolumeAttachment]{}, &predicate.TypedGenerationChangedPredicate[*unikornv1.ServerVolumeAttachment]{}))
}

func (*Factory) Schemes() []coreclient.SchemeAdder {
	return []coreclient.SchemeAdder{unikornv1.AddToScheme}
}

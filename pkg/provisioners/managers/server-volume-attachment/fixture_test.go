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

package servervolumeattachment

import (
	"testing"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func lifecycleFixture(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := unikornv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	mapper := apimeta.NewDefaultRESTMapper([]schema.GroupVersion{unikornv1.SchemeGroupVersion})
	mapper.Add(unikornv1.SchemeGroupVersion.WithKind("Server"), apimeta.RESTScopeNamespace)
	mapper.Add(unikornv1.SchemeGroupVersion.WithKind("Volume"), apimeta.RESTScopeNamespace)
	mapper.Add(unikornv1.SchemeGroupVersion.WithKind("ServerVolumeAttachment"), apimeta.RESTScopeNamespace)

	return fake.NewClientBuilder().WithScheme(scheme).WithRESTMapper(mapper).WithStatusSubresource(&unikornv1.Server{}, &unikornv1.ServerVolumeAttachment{}).WithObjects(objects...).Build()
}

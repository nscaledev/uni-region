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

//nolint:revive,testpackage // Ginkgo suite uses dot imports and package-local helper access.
package api

import (
	"context"
	"io/fs"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var _ = Describe("Snapshot CR observer", func() {
	Context("When checking actual snapshot existence independently of the Region API", func() {
		Describe("Given a namespace-scoped direct reader", func() {
			var (
				observer *SnapshotObserver
				reader   client.WithWatch
			)

			BeforeEach(func() {
				scheme := runtime.NewScheme()
				Expect(regionv1.AddToScheme(scheme)).To(Succeed())
				// An expired, paused CR must remain observable: unlike Region GET,
				// this observer does not apply expiration or pause filtering.
				snapshot := &regionv1.FileStorageSnapshot{
					ObjectMeta: metav1.ObjectMeta{Namespace: "region-test", Name: "snapshot", UID: "original"},
					Spec: regionv1.FileStorageSnapshotSpec{
						Pause:          true,
						ExpirationTime: &metav1.Time{Time: metav1.Unix(1, 0).Time},
					},
				}
				reader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(snapshot).Build()
				observer = &SnapshotObserver{reader: reader, namespace: "region-test"}
			})

			It("reads an expired CR without hiding it or changing it", func() {
				read, err := observer.GetSnapshot(context.Background(), "snapshot")
				Expect(err).NotTo(HaveOccurred())
				Expect(read.Namespace).To(Equal("region-test"))
				Expect(string(read.UID)).To(Equal("original"))
				Expect(read.Spec.Pause).To(BeTrue())
				Expect(read.Spec.ExpirationTime.Time).To(Equal(metav1.Unix(1, 0).Time))
				Expect(read.DeletionTimestamp.IsZero()).To(BeTrue())
			})

			It("preserves Kubernetes NotFound for a removed CR", func() {
				read, err := observer.GetSnapshot(context.Background(), "missing")
				Expect(read).To(BeNil())
				Expect(apierrors.IsNotFound(err)).To(BeTrue())
			})

			It("does not find the same ID in another namespace", func() {
				observer.namespace = "another-region"
				_, err := observer.GetSnapshot(context.Background(), "snapshot")
				Expect(apierrors.IsNotFound(err)).To(BeTrue())
			})

			It("does not mistake denied access for CR absence", func() {
				denied := apierrors.NewForbidden(schema.GroupResource{Group: regionv1.GroupName, Resource: "filestoragesnapshots"}, "snapshot", fs.ErrPermission)
				observer.reader = interceptor.NewClient(reader, interceptor.Funcs{
					Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
						return denied
					},
				})
				read, err := observer.GetSnapshot(context.Background(), "snapshot")
				Expect(read).To(BeNil())
				Expect(apierrors.IsForbidden(err)).To(BeTrue())
				Expect(apierrors.IsNotFound(err)).To(BeFalse())
			})
		})
	})
})

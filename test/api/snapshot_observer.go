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

package api

import (
	"context"
	"fmt"
	"time"

	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	"k8s.io/apimachinery/pkg/runtime"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// SnapshotObserver reads snapshot CRs directly, bypassing Region's expiration
// filtering. It deliberately exposes no Kubernetes mutation operations.
type SnapshotObserver struct {
	reader    client.Reader
	namespace string
}

// NewSnapshotObserver uses the runner's kubeconfig (or in-cluster credentials).
// Call only in specs that need CR observations, not global API-suite setup.
// Credentials must grant snapshot get access in the supplied Region namespace.
func NewSnapshotObserver(namespace string) (*SnapshotObserver, error) {
	config, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("loading snapshot observer kubeconfig: %w", err)
	}

	config.Timeout = 15 * time.Second
	scheme := runtime.NewScheme()

	if err := regionv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("registering Region snapshot scheme: %w", err)
	}

	reader, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("constructing snapshot observer: %w", err)
	}

	return &SnapshotObserver{reader: reader, namespace: namespace}, nil
}

// GetSnapshot observes a single known snapshot ID, without listing other tenants'
// resources. Kubernetes NotFound means actual CR removal, not API invisibility.
func (o *SnapshotObserver) GetSnapshot(ctx context.Context, snapshotID string) (*regionv1.FileStorageSnapshot, error) {
	snapshot := &regionv1.FileStorageSnapshot{}
	if err := o.reader.Get(ctx, client.ObjectKey{Namespace: o.namespace, Name: snapshotID}, snapshot); err != nil {
		return nil, fmt.Errorf("observing snapshot %s/%s: %w", o.namespace, snapshotID, err)
	}

	return snapshot, nil
}

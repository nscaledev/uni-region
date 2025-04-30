/*
Copyright 2024-2025 the Unikorn Authors.

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

package vlan

import (
	"context"
	"errors"
	"fmt"
	"slices"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrAllocation = errors.New("allocation failure")
)

type Allocator struct {
	client    client.Client
	namespace string
	name      string
	spec      *unikornv1.VLANSpec
}

func New(client client.Client, namespace, name string, spec *unikornv1.VLANSpec) *Allocator {
	return &Allocator{
		client:    client,
		namespace: namespace,
		name:      name,
		spec:      spec,
	}
}

func (a *Allocator) allocatable() [4096]bool {
	var table [4096]bool

	if a.spec == nil {
		for i := 1; i < 4095; i++ {
			table[i] = true
		}

		return table
	}

	for _, segment := range a.spec.Segments {
		for i := segment.StartID; i <= segment.EndID; i++ {
			table[i] = true
		}
	}

	return table
}

func (a *Allocator) getVLANAllocation(ctx context.Context) (*unikornv1.VLANAllocation, error) {
	allocation := &unikornv1.VLANAllocation{}

	if err := a.client.Get(ctx, client.ObjectKey{Namespace: a.namespace, Name: a.name}, allocation); err != nil {
		return nil, err
	}

	return allocation, nil
}

func (a *Allocator) getOrCreateVLANAllocation(ctx context.Context) (*unikornv1.VLANAllocation, bool, error) {
	create := false

	allocation, err := a.getVLANAllocation(ctx)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return nil, false, err
		}

		allocation = &unikornv1.VLANAllocation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: a.namespace,
				Name:      a.name,
			},
		}

		create = true
	}

	return allocation, create, nil
}

func (a *Allocator) Allocate(ctx context.Context, networkID string) (int, error) {
	allocation, create, err := a.getOrCreateVLANAllocation(ctx)
	if err != nil {
		return -1, err
	}

	allocatable := a.allocatable()

	// Do an exhaustive search through all allocatable VLAN IDs...
	// TODO: this is a O(n^2) problem, admittedly bounded.
	for id := 1; id < 4095; id++ {
		if !allocatable[id] {
			continue
		}

		// If there is already an allocation for that ID keep going....
		callback := func(allocation unikornv1.VLANAllocationEntry) bool {
			return allocation.ID == id
		}

		if index := slices.IndexFunc(allocation.Spec.Allocations, callback); index >= 0 {
			continue
		}

		// Perform an atomic update of the allocation table.
		allocation.Spec.Allocations = append(allocation.Spec.Allocations, unikornv1.VLANAllocationEntry{
			ID:        id,
			NetworkID: networkID,
		})

		if create {
			if err := a.client.Create(ctx, allocation); err != nil {
				return -1, err
			}

			return id, nil
		}

		if err := a.client.Update(ctx, allocation); err != nil {
			return -1, err
		}

		return id, nil
	}

	return -1, fmt.Errorf("%w: vlan ids exhausted", ErrAllocation)
}

func (a *Allocator) Free(ctx context.Context, id int) error {
	allocation, err := a.getVLANAllocation(ctx)
	if err != nil {
		return err
	}

	allocationsLength := len(allocation.Spec.Allocations)

	callback := func(allocation unikornv1.VLANAllocationEntry) bool {
		return allocation.ID == id
	}

	allocation.Spec.Allocations = slices.DeleteFunc(allocation.Spec.Allocations, callback)

	if len(allocation.Spec.Allocations) != allocationsLength-1 {
		return fmt.Errorf("%w: vlan id %d not allocated exactly once", ErrAllocation, id)
	}

	if err := a.client.Update(ctx, allocation); err != nil {
		return err
	}

	return nil
}

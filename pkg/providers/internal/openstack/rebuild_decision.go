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

package openstack

import (
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

type rebuildAction string

const (
	rebuildNoop   rebuildAction = "noop"
	rebuildArm    rebuildAction = "arm"
	rebuildCommit rebuildAction = "commit"
	rebuildCall   rebuildAction = "call"
	rebuildClear  rebuildAction = "clear"
	rebuildPark   rebuildAction = "park"
	rebuildUnpark rebuildAction = "unpark"
)

type providerOp string

const (
	providerIdle    providerOp = "idle"
	providerBusy    providerOp = "busy"
	providerErrored providerOp = "errored"
)

type rebuildInputs struct {
	DesiredImageID string
	Marker         *unikornv1.ServerRebuildStatus
	ProviderImage  string
	ProviderOp     providerOp
	// ProviderLaunched reports whether the provider has ever booted this server.
	// Before first boot the image is a create parameter rather than something to
	// converge, so this gates arming and calling — and only those. A marker that
	// already exists must still be able to settle, park, and retarget, or a
	// pre-boot attempt could never be retired.
	ProviderLaunched bool
	// AppliedImage is the deploy layer's answer to "what is actually running".
	// Nil where no second channel applies (no baremetal node). A caller that
	// cannot reach the second channel must not call this function at all: it
	// yields and retries, rather than deciding on one channel.
	AppliedImage *string
}

// rebuildDecision picks the single action a reconcile pass should take, from
// the object and a fresh provider read. It reads no observation subtree: a
// stale observation may cost a wasted pass, never a wrong action.
//
//nolint:cyclop // one branch per row of the protocol table; row order is load-bearing.
func rebuildDecision(in rebuildInputs) rebuildAction {
	if in.Marker != nil && in.Marker.Parked {
		if in.Marker.TargetImageID.String() != in.DesiredImageID {
			return rebuildUnpark
		}

		return rebuildNoop
	}

	// An empty provider image ref means we cannot decide — except from an errored
	// provider, which is decidable on evidence that does not need the ref at all.
	// Masking that behind the guard would leave a live marker on a terminally
	// errored server yielding for ever instead of parking.
	if in.ProviderImage == "" && in.ProviderOp != providerErrored {
		return rebuildNoop
	}

	if in.Marker == nil {
		if in.ProviderImage != in.DesiredImageID && in.ProviderOp == providerIdle && in.ProviderLaunched {
			return rebuildArm
		}

		return rebuildNoop
	}

	target := in.Marker.TargetImageID.String()

	if !in.Marker.Accepted {
		switch {
		case in.ProviderOp == providerBusy && in.ProviderImage == target:
			return rebuildCommit
		case in.ProviderImage == target && in.ProviderOp == providerIdle:
			if in.appliedMatches(target) {
				return rebuildClear
			}

			return rebuildCommit
		case in.ProviderOp == providerIdle || in.ProviderOp == providerErrored:
			return rebuildCommit
		default:
			return rebuildNoop
		}
	}

	switch {
	case in.ProviderImage == target && in.ProviderOp == providerIdle:
		if in.appliedMatches(target) {
			return rebuildClear
		}

		return rebuildPark
	case in.ProviderOp == providerErrored:
		return rebuildPark
	case in.ProviderOp == providerIdle && in.ProviderImage == in.Marker.PreArmImageRef:
		// Not-launched returns here rather than falling through: the rows below
		// would park an attempt the provider was never asked to make.
		if !in.ProviderLaunched {
			return rebuildNoop
		}

		return rebuildCall
	case in.ProviderOp == providerIdle:
		return rebuildPark
	default:
		return rebuildNoop
	}
}

// appliedMatches reports whether the deploy layer agrees the target image is
// what the machine runs. Absent a second channel the provider's word stands.
func (in rebuildInputs) appliedMatches(target string) bool {
	return in.AppliedImage == nil || *in.AppliedImage == target
}

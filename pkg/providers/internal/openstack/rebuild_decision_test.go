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

//nolint:testpackage
package openstack

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
)

// imageID maps a short test label to a stable regionids.ImageID: the type is
// a UUID, but the tests only need distinct, repeatable labels.
func imageID(label string) regionids.ImageID {
	return regionids.ImageID(uuid.NewSHA1(uuid.NameSpaceOID, []byte(label)))
}

// imageIDStr is imageID's string form, for comparison against the plain
// strings rebuildInputs carries (DesiredImageID, ProviderImage).
func imageIDStr(label string) string {
	return imageID(label).String()
}

// marker builds an attempt marker. target stays a parameter even though every
// current row targets the same label: it is the axis the table reads against
// ProviderImage and PreArmImageRef, and collapsing it would hide that.
//
//nolint:unparam
func marker(target, pre string, accepted bool) *unikornv1.ServerRebuildStatus {
	return &unikornv1.ServerRebuildStatus{
		TargetImageID:  imageID(target),
		PreArmImageRef: pre,
		Accepted:       accepted,
	}
}

// parked latches an attempt as abandoned. Parked-ness is a modifier on a
// marker, not a different kind of marker.
func parked(m *unikornv1.ServerRebuildStatus) *unikornv1.ServerRebuildStatus {
	m.Parked = true

	return m
}

func strPtr(s string) *string { return &s }

func TestRebuildDecision(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   rebuildInputs
		want rebuildAction
	}{
		// Parked.
		{"parked, spec still names the parked target",
			rebuildInputs{DesiredImageID: imageIDStr("B"), Marker: parked(marker("B", "A", true)),
				ProviderImage: "A", ProviderOp: providerErrored, ProviderLaunched: true}, rebuildNoop},
		{"parked, spec moved on",
			rebuildInputs{DesiredImageID: "C", Marker: parked(marker("B", "A", true)),
				ProviderImage: "A", ProviderOp: providerErrored, ProviderLaunched: true}, rebuildUnpark},

		// Empty provider image ref: cannot decide, except unpark, which is
		// non-destructive and must not be blocked by an unreadable provider, and
		// except an errored provider, which is decidable without the ref.
		{"no marker, provider reports no image, spec names an image",
			rebuildInputs{DesiredImageID: "B", ProviderImage: "", ProviderOp: providerIdle, ProviderLaunched: true},
			rebuildNoop},
		{"committed, empty pre-arm ref, provider reports no image, idle",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "", true),
				ProviderImage: "", ProviderOp: providerIdle, ProviderLaunched: true}, rebuildNoop},
		{"committed, provider reports no image, busy",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", true),
				ProviderImage: "", ProviderOp: providerBusy, ProviderLaunched: true}, rebuildNoop},
		{"parked, spec moved on, provider reports no image",
			rebuildInputs{DesiredImageID: "C", Marker: parked(marker("B", "A", true)),
				ProviderImage: "", ProviderOp: providerErrored, ProviderLaunched: true}, rebuildUnpark},
		{"committed, provider errored and reports no image — parks on the error alone",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", true),
				ProviderImage: "", ProviderOp: providerErrored, ProviderLaunched: true}, rebuildPark},
		{"no marker, provider errored and reports no image",
			rebuildInputs{DesiredImageID: "B", ProviderImage: "", ProviderOp: providerErrored, ProviderLaunched: true},
			rebuildNoop},

		// No marker.
		{"no marker, image diverges, provider idle",
			rebuildInputs{DesiredImageID: "B", ProviderImage: "A", ProviderOp: providerIdle, ProviderLaunched: true},
			rebuildArm},
		{"no marker, image diverges, provider busy",
			rebuildInputs{DesiredImageID: "B", ProviderImage: "A", ProviderOp: providerBusy, ProviderLaunched: true},
			rebuildNoop},
		{"no marker, image converged",
			rebuildInputs{DesiredImageID: "A", ProviderImage: "A", ProviderOp: providerIdle, ProviderLaunched: true},
			rebuildNoop},

		// Armed, not yet committed.
		{"armed, provider idle at old image",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", false),
				ProviderImage: "A", ProviderOp: providerIdle, ProviderLaunched: true}, rebuildCommit},
		{"armed, provider errored",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", false),
				ProviderImage: "A", ProviderOp: providerErrored, ProviderLaunched: true}, rebuildCommit},
		{"armed, provider already busy toward our target",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", false),
				ProviderImage: imageIDStr("B"), ProviderOp: providerBusy, ProviderLaunched: true}, rebuildCommit},
		{"armed, converged before we asked",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", false),
				ProviderImage: imageIDStr("B"), ProviderOp: providerIdle, ProviderLaunched: true, AppliedImage: strPtr(imageIDStr("B"))},
			rebuildClear},
		{"armed, reported converged but never applied",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", false),
				ProviderImage: imageIDStr("B"), ProviderOp: providerIdle, ProviderLaunched: true, AppliedImage: strPtr("A")},
			rebuildCommit},

		// Committed. The call row: this is the one the pre-arm ref exists for.
		{"committed, provider idle at the pre-arm image — not asked yet",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", true),
				ProviderImage: "A", ProviderOp: providerIdle, ProviderLaunched: true}, rebuildCall},
		{"committed, provider busy — in flight",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", true),
				ProviderImage: imageIDStr("B"), ProviderOp: providerBusy, ProviderLaunched: true}, rebuildNoop},
		{"committed, idle at target, second channel agrees",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", true),
				ProviderImage: imageIDStr("B"), ProviderOp: providerIdle, ProviderLaunched: true, AppliedImage: strPtr(imageIDStr("B"))},
			rebuildClear},
		{"committed, idle at target, second channel disagrees",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", true),
				ProviderImage: imageIDStr("B"), ProviderOp: providerIdle, ProviderLaunched: true, AppliedImage: strPtr("A")},
			rebuildPark},
		{"committed, provider errored",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", true),
				ProviderImage: "A", ProviderOp: providerErrored, ProviderLaunched: true}, rebuildPark},
		{"committed, idle at a foreign image — superseded",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", true),
				ProviderImage: "C", ProviderOp: providerIdle, ProviderLaunched: true}, rebuildPark},

		// No second channel (no baremetal node): the provider's word is all
		// there is, and success is declared on it.
		{"committed, idle at target, no second channel",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", true),
				ProviderImage: imageIDStr("B"), ProviderOp: providerIdle, ProviderLaunched: true}, rebuildClear},

		// Never launched. Before first boot the image is a create parameter, so
		// the two rows that would act on the provider are withheld — and only
		// those, or a marker armed before this axis existed could never be
		// retired and would report a terminal failure forever.
		{"not launched, no marker, image diverges, provider idle",
			rebuildInputs{DesiredImageID: "B", ProviderImage: "A", ProviderOp: providerIdle},
			rebuildNoop},
		{"not launched, committed, provider idle at the pre-arm image",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", true),
				ProviderImage: "A", ProviderOp: providerIdle}, rebuildNoop},
		{"not launched, armed, provider idle at old image",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", false),
				ProviderImage: "A", ProviderOp: providerIdle}, rebuildCommit},
		{"not launched, committed, idle at target — settles",
			rebuildInputs{DesiredImageID: "B", Marker: marker("B", "A", true),
				ProviderImage: imageIDStr("B"), ProviderOp: providerIdle}, rebuildClear},
		{"not launched, parked, spec moved on — retargets",
			rebuildInputs{DesiredImageID: "C", Marker: parked(marker("B", "A", true)),
				ProviderImage: "A", ProviderOp: providerErrored}, rebuildUnpark},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, c.want, rebuildDecision(c.in))
		})
	}
}

// A rebuild is never abandoned without asking the provider: no input with an
// un-called marker may park.
func TestRebuildDecisionNeverParksUntried(t *testing.T) {
	t.Parallel()

	for _, op := range []providerOp{providerIdle, providerBusy, providerErrored} {
		for _, applied := range []*string{nil, strPtr("A"), strPtr("B")} {
			in := rebuildInputs{
				DesiredImageID:   "B",
				Marker:           marker("B", "A", true),
				ProviderImage:    "A", // still at the pre-arm image: never asked
				ProviderOp:       op,
				ProviderLaunched: true,
				AppliedImage:     applied,
			}

			if got := rebuildDecision(in); got == rebuildPark && op != providerErrored {
				t.Fatalf("parked a rebuild at the pre-arm image with op %q: %v", op, got)
			}
		}
	}
}

// Only a committed marker can reach the provider.
func TestRebuildDecisionCallRequiresCommitment(t *testing.T) {
	t.Parallel()

	for _, op := range []providerOp{providerIdle, providerBusy, providerErrored} {
		in := rebuildInputs{
			DesiredImageID:   "B",
			Marker:           marker("B", "A", false),
			ProviderImage:    "A",
			ProviderOp:       op,
			ProviderLaunched: true,
		}

		assert.NotEqual(t, rebuildCall, rebuildDecision(in),
			"an uncommitted marker must never reach the provider")
	}
}

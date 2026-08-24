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

package coordinator

import (
	"testing"
	"time"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAttachmentName(t *testing.T) {
	if got, want := attachmentName("server-a", "volume-a"), attachmentName("server-a", "volume-a"); got != want {
		t.Fatalf("attachment name is not deterministic: got %q, want %q", got, want)
	}

	if attachmentName("server-a", "volume-a") == attachmentName("server-b", "volume-a") {
		t.Fatal("attachment names must distinguish servers")
	}
}

func TestOldestAttachment(t *testing.T) {
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	second := first.Add(time.Second)

	got := oldestAttachment([]unikornv1.ServerVolumeAttachment{
		{ObjectMeta: metav1.ObjectMeta{Name: "later", CreationTimestamp: metav1.NewTime(second)}},
		{ObjectMeta: metav1.ObjectMeta{Name: "first", CreationTimestamp: metav1.NewTime(first)}},
	})
	if got == nil || got.Name != "first" {
		t.Fatalf("oldest attachment = %v, want first", got)
	}

	got = oldestAttachment([]unikornv1.ServerVolumeAttachment{
		{ObjectMeta: metav1.ObjectMeta{Name: "b", CreationTimestamp: metav1.NewTime(first)}},
		{ObjectMeta: metav1.ObjectMeta{Name: "a", CreationTimestamp: metav1.NewTime(first)}},
	})
	if got == nil || got.Name != "a" {
		t.Fatalf("tie-break attachment = %v, want a", got)
	}
}

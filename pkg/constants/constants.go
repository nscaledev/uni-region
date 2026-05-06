/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.
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

package constants

import (
	"fmt"
	"os"
	"path"
	"strconv"

	"github.com/unikorn-cloud/core/pkg/util"
)

var (
	// Application is the application name.
	//nolint:gochecknoglobals
	Application = path.Base(os.Args[0])

	// Version is the application version set via the Makefile.
	//nolint:gochecknoglobals
	Version string

	// Revision is the git revision set via the Makefile.
	//nolint:gochecknoglobals
	Revision string
)

// VersionString returns a canonical version string.  It's based on
// HTTP's User-Agent so can be used to set that too, if this ever has to
// call out ot other micro services.
func VersionString() string {
	return fmt.Sprintf("%s/%s (revision/%s)", Application, Version, Revision)
}

func ServiceDescriptor() util.ServiceDescriptor {
	return util.ServiceDescriptor{
		Name:     Application,
		Version:  Version,
		Revision: Revision,
	}
}

const (
	// ResourceAPIVersionLabel defines what API version a resource belongs to
	// for filtering purposes.
	ResourceAPIVersionLabel = "resource.unikorn-cloud.org/api-version"
	// RegionLabel creates an indexable linkage between resources and their
	// owning region.
	RegionLabel = "regions.unikorn-cloud.org/region-id"
	// IdentityLabel creates an indexable linkage between resources and an
	// owning identity.
	IdentityLabel = "regions.unikorn-cloud.org/identity-id"
	// NetworkLabel creates an indexable linkage between resources
	// and an owning entity.
	NetworkLabel = "regions.unikorn-cloud.org/network-id"
	// SecurityGroupLabel creates an indexable linkage between resources
	// and an owning entity.
	SecurityGroupLabel = "regions.unikorn-cloud.org/security-group-id"
	// ServerLabel creates an indexable linkage between resources and an
	// owning entity.
	ServerLabel = "regions.unikorn-cloud.org/server-id"
	// ServerPendingEntryTimeAnnotation records when a server entered the Pending phase.
	// Value is an RFC 3339 UTC timestamp. The region monitor is the sole writer of this
	// annotation: it is stamped on Pending entry and removed on Pending exit. Manual edits
	// to the timestamp value while the server remains Pending are not corrected — the
	// existing annotation is left intact until the server next leaves or re-enters Pending.
	ServerPendingEntryTimeAnnotation = "regions.unikorn-cloud.org/pending-entry-time"
)

const (
	ImageTagPrefix = "images.unikorn-cloud.org:"

	ImageSourceTag      = ImageTagPrefix + "source" // for the kind of source, e.g., import
	ImageSourceImport   = "import"
	ImageSourceSnapshot = "snapshot"

	ImageOrganizationIDTag = ImageTagPrefix + "organization-id"
)

func MarshalAPIVersion(i int) string {
	return strconv.Itoa(i)
}

func UnmarshalAPIVersion(s string) (int, error) {
	return strconv.Atoi(s)
}

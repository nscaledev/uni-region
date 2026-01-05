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

package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/pflag"
)

// Options defines configurable handler options.
type Options struct {
	// cacheMaxAge defines the max age for cachable items e.g. images and
	// flavors don't change all that often.
	CacheMaxAge time.Duration

	// ImageUploadSizeLimit defines the maximum size for image uploads in bytes.
	ImageUploadSizeLimit int64
}

// AddFlags adds the options flags to the given flag set.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.DurationVar(&o.CacheMaxAge, "cache-max-age", 24*time.Hour, "How long to cache long-lived queries in the browser.")
	f.Int64Var(&o.ImageUploadSizeLimit, "image-upload-size-limit", 30*1024*1024*1024, "The maximum size for image uploads in bytes.") // Default to 30GB.
}

func (o *Options) setCacheable(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", fmt.Sprintf("max-age=%d", o.CacheMaxAge/time.Second))
	w.Header().Add("Cache-Control", "private")
}

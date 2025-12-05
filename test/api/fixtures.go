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

package api

import (
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreutil "github.com/unikorn-cloud/core/pkg/testing/util"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"

	"k8s.io/utils/ptr"
)

// Payload builders for test data, taken from what in uni-compute:
//
// Example pattern using fluent builder:
//
// type IdentityPayloadBuilder struct {
// 	identity regionopenapi.IdentityWrite
// 	config   *TestConfig
// }
//
// func NewIdentityPayload() *IdentityPayloadBuilder {
// 	config, _ := LoadTestConfig()
// 	return &IdentityPayloadBuilder{
// 		config: config,
// 		identity: regionopenapi.IdentityWrite{
// 			Metadata: coreapi.ResourceWriteMetadata{
// 				Name:        coreutil.GenerateRandomName("test-identity"),
// 				Description: ptr.To("Test description"),
// 			},
// 			Spec: regionopenapi.IdentityWriteSpec{
// 				RegionId: config.RegionID,
// 			},
// 		},
// 	}
// }
//
// func (b *IdentityPayloadBuilder) WithName(name string) *IdentityPayloadBuilder {
// 	b.identity.Metadata.Name = name
// 	return b
// }
//
// func (b *IdentityPayloadBuilder) Build() regionopenapi.IdentityWrite {
// 	return b.identity
// }

// Suppress unused import warnings - remove when I add actual builders.
var (
	_ = coreapi.ResourceWriteMetadata{}
	_ = coreutil.GenerateRandomName
	_ = regionopenapi.IdentityWrite{}
	_ = ptr.To[string]
)

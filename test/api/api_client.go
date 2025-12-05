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

//nolint:revive // naming conventions acceptable in test code
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/onsi/ginkgo/v2"

	"github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
)

// GinkgoLogger implements the Logger interface for Ginkgo tests.
type GinkgoLogger struct{}

func (g *GinkgoLogger) Printf(format string, args ...interface{}) {
	ginkgo.GinkgoWriter.Printf(format, args...)
}

// APIClient wraps the core API client with region-specific methods.
// Add methods here as you write tests for specific endpoints.
type APIClient struct {
	*coreclient.APIClient
	config    *TestConfig
	endpoints *Endpoints
}

// NewAPIClient creates a new Region API client.
func NewAPIClient(baseURL string) (*APIClient, error) {
	config, err := LoadTestConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load test configuration: %w", err)
	}

	if baseURL == "" {
		baseURL = config.BaseURL
	}

	return newAPIClientWithConfig(config, baseURL), nil
}

// NewAPIClientWithConfig creates a new Region API client with the given config.
func NewAPIClientWithConfig(config *TestConfig) *APIClient {
	return newAPIClientWithConfig(config, config.BaseURL)
}

// common constructor logic.
func newAPIClientWithConfig(config *TestConfig, baseURL string) *APIClient {
	coreClient := coreclient.NewAPIClient(baseURL, config.AuthToken, config.RequestTimeout, &GinkgoLogger{})
	coreClient.SetLogRequests(config.LogRequests)
	coreClient.SetLogResponses(config.LogResponses)

	return &APIClient{
		APIClient: coreClient,
		config:    config,
		endpoints: NewEndpoints(),
	}
}

// Example API methods, taken from what in uni-compute:
//
// ListRegions lists all regions for an organization.
// func (c *APIClient) ListRegions(ctx context.Context, orgID string) (regionopenapi.Regions, error) {
// 	path := c.endpoints.ListRegions(orgID)
// 	return coreclient.ListResource[regionopenapi.RegionRead](ctx, c.APIClient, path, ...)
// }
//
// CreateIdentity creates a new identity in a project.
// func (c *APIClient) CreateIdentity(ctx context.Context, orgID, projectID string, identity regionopenapi.IdentityWrite) (*openapi.ResourceReadMetadata, error) {
// 	path := c.endpoints.CreateIdentity(orgID, projectID)
// 	body, _ := json.Marshal(identity)
// 	_, respBody, err := c.DoRequest(ctx, http.MethodPost, path, bytes.NewReader(body), http.StatusCreated)
// 	...
// }

// Suppress unused import warnings - remove when you add actual methods.
var (
	_ = bytes.NewReader
	_ = context.Background
	_ = json.Marshal
	_ = http.MethodGet
	_ = openapi.ResourceReadMetadata{}
	_ = regionopenapi.Regions{}
)

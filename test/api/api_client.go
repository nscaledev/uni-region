/*
Copyright 2025 the Unikorn Authors.
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

//nolint:revive // naming conventions acceptable in test code
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/onsi/ginkgo/v2"

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
	regionClient *coreclient.APIClient
	config       *TestConfig
	endpoints    *Endpoints
}

// GetListRegionsPath returns the path for listing regions.
// This is useful for tests that need direct access to the endpoint path.
func (c *APIClient) GetListRegionsPath(orgID string) string {
	return c.endpoints.ListRegions(orgID)
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

	var regionClient *coreclient.APIClient
	if config.RegionBaseURL != "" {
		regionClient = coreclient.NewAPIClient(config.RegionBaseURL, config.AuthToken, config.RequestTimeout, &GinkgoLogger{})
		regionClient.SetLogRequests(config.LogRequests)
		regionClient.SetLogResponses(config.LogResponses)
	}

	return &APIClient{
		APIClient:    coreClient,
		regionClient: regionClient,
		config:       config,
		endpoints:    NewEndpoints(),
	}
}

// ListRegions lists all regions for an organization.
func (c *APIClient) ListRegions(ctx context.Context, orgID string) (regionopenapi.Regions, error) {
	path := c.endpoints.ListRegions(orgID)

	return coreclient.ListResource[regionopenapi.RegionRead](
		ctx,
		c.APIClient,
		path,
		coreclient.ResponseHandlerConfig{
			ResourceType:   "regions",
			ResourceID:     orgID,
			ResourceIDType: "organization",
		},
	)
}

// GetRegionDetail gets detailed information about a specific region.
func (c *APIClient) GetRegionDetail(ctx context.Context, orgID, regionID string) (*regionopenapi.RegionDetailRead, error) {
	path := c.endpoints.GetRegionDetail(orgID, regionID)

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.DoRequest(ctx, http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("getting region detail: %w", err)
	}

	var regionDetail regionopenapi.RegionDetailRead
	if err := json.Unmarshal(respBody, &regionDetail); err != nil {
		return nil, fmt.Errorf("unmarshaling region detail: %w", err)
	}

	return &regionDetail, nil
}

// ListFlavors lists all flavors available in a region.
func (c *APIClient) ListFlavors(ctx context.Context, orgID, regionID string) (regionopenapi.Flavors, error) {
	path := c.endpoints.ListFlavors(orgID, regionID)

	return coreclient.ListResource[regionopenapi.Flavor](
		ctx,
		c.APIClient,
		path,
		coreclient.ResponseHandlerConfig{
			ResourceType:   "flavors",
			ResourceID:     regionID,
			ResourceIDType: "region",
		},
	)
}

// ListImages lists all images available in a region.
func (c *APIClient) ListImages(ctx context.Context, orgID, regionID string) (regionopenapi.Images, error) {
	path := c.endpoints.ListImages(orgID, regionID)

	return coreclient.ListResource[regionopenapi.Image](
		ctx,
		c.APIClient,
		path,
		coreclient.ResponseHandlerConfig{
			ResourceType:   "images",
			ResourceID:     regionID,
			ResourceIDType: "region",
		},
	)
}

// ListExternalNetworks lists all external networks available in a region.
func (c *APIClient) ListExternalNetworks(ctx context.Context, orgID, regionID string) (regionopenapi.ExternalNetworks, error) {
	path := c.endpoints.ListExternalNetworks(orgID, regionID)

	client := c.APIClient
	if c.regionClient != nil {
		client = c.regionClient
	}

	return coreclient.ListResource[regionopenapi.ExternalNetwork](
		ctx,
		client,
		path,
		coreclient.ResponseHandlerConfig{
			ResourceType:   "externalNetworks",
			ResourceID:     regionID,
			ResourceIDType: "region",
		},
	)
}

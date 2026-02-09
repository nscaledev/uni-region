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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	regionClient *coreclient.APIClient // separate client for region-specific endpoints
	config       *TestConfig
	endpoints    *Endpoints
}

// GetListRegionsPath returns the path for listing regions.
// This is useful for tests that need direct access to the endpoint path.
func (c *APIClient) GetListRegionsPath(orgID string) string {
	return c.endpoints.ListRegions(orgID)
}

// GetEndpoints returns the endpoints instance for direct path access in tests.
func (c *APIClient) GetEndpoints() *Endpoints {
	return c.endpoints
}

// DoRegionRequest performs a request using the region base URL client.
// Use this for direct API calls that need to hit the region API.
func (c *APIClient) DoRegionRequest(ctx context.Context, method, path string, body io.Reader, expectedStatus int) (*http.Response, []byte, error) {
	return c.regionClient.DoRequest(ctx, method, path, body, expectedStatus)
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

	// Create a separate client for region endpoints
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

// ListFileStorage lists all file storage resources for a project in a region.
func (c *APIClient) ListFileStorage(ctx context.Context, orgID, projectID, regionID string) (regionopenapi.StorageV2List, error) {
	path := c.endpoints.ListFileStorage(orgID, projectID, regionID)

	return coreclient.ListResource[regionopenapi.StorageV2Read](
		ctx,
		c.regionClient,
		path,
		coreclient.ResponseHandlerConfig{
			ResourceType:   "filestorage",
			ResourceID:     projectID,
			ResourceIDType: "project",
		},
	)
}

// CreateFileStorage creates a new file storage resource.
func (c *APIClient) CreateFileStorage(ctx context.Context, request regionopenapi.StorageV2CreateRequest) (*regionopenapi.StorageV2Read, error) {
	path := c.endpoints.CreateFileStorage()

	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshaling filestorage request: %w", err)
	}

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.regionClient.DoRequest(ctx, http.MethodPost, path, bytes.NewReader(reqBody), http.StatusCreated)
	if err != nil {
		return nil, fmt.Errorf("creating filestorage: %w", err)
	}

	var storage regionopenapi.StorageV2Read
	if err := json.Unmarshal(respBody, &storage); err != nil {
		return nil, fmt.Errorf("unmarshaling filestorage: %w", err)
	}

	return &storage, nil
}

// GetFileStorage gets a specific file storage resource by ID.
func (c *APIClient) GetFileStorage(ctx context.Context, filestorageID string) (*regionopenapi.StorageV2Read, error) {
	path := c.endpoints.GetFileStorage(filestorageID)

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.regionClient.DoRequest(ctx, http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("getting filestorage: %w", err)
	}

	var storage regionopenapi.StorageV2Read
	if err := json.Unmarshal(respBody, &storage); err != nil {
		return nil, fmt.Errorf("unmarshaling filestorage: %w", err)
	}

	return &storage, nil
}

// UpdateFileStorage updates a file storage resource.
func (c *APIClient) UpdateFileStorage(ctx context.Context, filestorageID string, request regionopenapi.StorageV2UpdateRequest) (*regionopenapi.StorageV2Read, error) {
	path := c.endpoints.UpdateFileStorage(filestorageID)

	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshaling filestorage update request: %w", err)
	}

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.regionClient.DoRequest(ctx, http.MethodPut, path, bytes.NewReader(reqBody), http.StatusAccepted)
	if err != nil {
		return nil, fmt.Errorf("updating filestorage: %w", err)
	}

	var storage regionopenapi.StorageV2Read
	if err := json.Unmarshal(respBody, &storage); err != nil {
		return nil, fmt.Errorf("unmarshaling filestorage: %w", err)
	}

	return &storage, nil
}

// DeleteFileStorage deletes a file storage resource.
func (c *APIClient) DeleteFileStorage(ctx context.Context, filestorageID string) error {
	path := c.endpoints.DeleteFileStorage(filestorageID)

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, _, err := c.regionClient.DoRequest(ctx, http.MethodDelete, path, nil, http.StatusAccepted)
	if err != nil {
		return fmt.Errorf("deleting filestorage: %w", err)
	}

	return nil
}

// ListFileStorageClasses lists all available file storage classes for a region.
func (c *APIClient) ListFileStorageClasses(ctx context.Context, regionID string) (regionopenapi.StorageClassListV2Read, error) {
	path := c.endpoints.ListFileStorageClasses(regionID)

	return coreclient.ListResource[regionopenapi.StorageClassV2Read](
		ctx,
		c.regionClient,
		path,
		coreclient.ResponseHandlerConfig{
			ResourceType:   "filestorageclasses",
			ResourceID:     regionID,
			ResourceIDType: "region",
		},
	)
}

// ListNetworks lists all networks for a project in a region.
func (c *APIClient) ListNetworks(ctx context.Context, orgID, projectID, regionID string) (regionopenapi.NetworksV2Read, error) {
	path := c.endpoints.ListNetworks(orgID, projectID, regionID)

	return coreclient.ListResource[regionopenapi.NetworkV2Read](
		ctx,
		c.regionClient,
		path,
		coreclient.ResponseHandlerConfig{
			ResourceType:   "networks",
			ResourceID:     projectID,
			ResourceIDType: "project",
		},
	)
}

// CreateNetwork creates a new network resource.
func (c *APIClient) CreateNetwork(ctx context.Context, request regionopenapi.NetworkV2CreateRequest) (*regionopenapi.NetworkV2Read, error) {
	path := c.endpoints.CreateNetwork()

	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshaling network request: %w", err)
	}

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.regionClient.DoRequest(ctx, http.MethodPost, path, bytes.NewReader(reqBody), http.StatusCreated)
	if err != nil {
		return nil, fmt.Errorf("creating network: %w", err)
	}

	var network regionopenapi.NetworkV2Read
	if err := json.Unmarshal(respBody, &network); err != nil {
		return nil, fmt.Errorf("unmarshaling network: %w", err)
	}

	return &network, nil
}

// DeleteNetwork deletes a network resource.
func (c *APIClient) DeleteNetwork(ctx context.Context, networkID string) error {
	path := c.endpoints.DeleteNetwork(networkID)

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, _, err := c.regionClient.DoRequest(ctx, http.MethodDelete, path, nil, http.StatusAccepted)
	if err != nil {
		return fmt.Errorf("deleting network: %w", err)
	}

	return nil
}

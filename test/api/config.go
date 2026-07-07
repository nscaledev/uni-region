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

package api

import (
	"time"

	coreconfig "github.com/unikorn-cloud/core/pkg/testing/config"
)

// TestConfig extends the base config with Region-specific fields.
type TestConfig struct {
	coreconfig.BaseConfig
	OrgID                   string
	ProjectID               string
	RegionBaseURL           string
	RegionCACertPath        string
	RegionID                string
	PrivateRegionID         string
	SecondaryOrgID          string
	SecondaryProjectID      string
	SecondaryAuthToken      string
	InternalAPICert         string
	InternalAPIKey          string
	InternalAPICN           string
	InternalAPIActor        string
	ServerFlavorID          string
	ServerImageID           string
	ServerInfrastructureRef string
	FileStorageSnapshotDir  string
}

// HasInternalAPIConfig reports whether local internal API credentials are available.
func (c *TestConfig) HasInternalAPIConfig() bool {
	return c.InternalAPICert != "" && c.InternalAPIKey != ""
}

// LoadTestConfig loads configuration from environment variables and .env files using viper.
// Returns an error if required configuration values are missing.
func LoadTestConfig() (*TestConfig, error) {
	// Set up viper with config paths and defaults
	defaults := map[string]interface{}{
		"REQUEST_TIMEOUT":                "60s",
		"TEST_TIMEOUT":                   "20m",
		"SKIP_INTEGRATION":               false,
		"DEBUG_LOGGING":                  false,
		"LOG_REQUESTS":                   false,
		"LOG_RESPONSES":                  false,
		"INTERNAL_API_CN":                "unikorn-compute",
		"INTERNAL_API_ACTOR":             "api-tests",
		"TEST_FILE_STORAGE_SNAPSHOT_DIR": ".snapshot",
	}

	// .env is located in test/ directory
	// Tests are run via: make test-api (from project root)
	// This resolves to ../../.env from test/api/suites/ (where ginkgo executes)
	configPaths := []string{
		"../..",
	}

	v, err := coreconfig.SetupViper(".env", configPaths, defaults)
	if err != nil {
		return nil, err
	}

	config := &TestConfig{
		BaseConfig: coreconfig.BaseConfig{
			BaseURL:         v.GetString("API_BASE_URL"),
			AuthToken:       v.GetString("API_AUTH_TOKEN"),
			RequestTimeout:  coreconfig.GetDurationFromViper(v, "REQUEST_TIMEOUT", 30*time.Second),
			TestTimeout:     coreconfig.GetDurationFromViper(v, "TEST_TIMEOUT", 20*time.Minute),
			SkipIntegration: v.GetBool("SKIP_INTEGRATION"),
			DebugLogging:    v.GetBool("DEBUG_LOGGING"),
			LogRequests:     v.GetBool("LOG_REQUESTS"),
			LogResponses:    v.GetBool("LOG_RESPONSES"),
		},
		RegionBaseURL:           v.GetString("REGION_BASE_URL"),
		RegionCACertPath:        v.GetString("REGION_CA_CERT"),
		OrgID:                   v.GetString("TEST_ORG_ID"),
		ProjectID:               v.GetString("TEST_PROJECT_ID"),
		RegionID:                v.GetString("TEST_REGION_ID"),
		PrivateRegionID:         v.GetString("TEST_PRIVATE_REGION_ID"),
		SecondaryOrgID:          v.GetString("TEST_SECONDARY_ORG_ID"),
		SecondaryProjectID:      v.GetString("TEST_SECONDARY_PROJECT_ID"),
		SecondaryAuthToken:      v.GetString("TEST_SECONDARY_AUTH_TOKEN"),
		InternalAPICert:         v.GetString("INTERNAL_API_CLIENT_CERT"),
		InternalAPIKey:          v.GetString("INTERNAL_API_CLIENT_KEY"),
		InternalAPICN:           v.GetString("INTERNAL_API_CN"),
		InternalAPIActor:        v.GetString("INTERNAL_API_ACTOR"),
		ServerFlavorID:          v.GetString("TEST_SERVER_FLAVOR_ID"),
		ServerImageID:           v.GetString("TEST_SERVER_IMAGE_ID"),
		ServerInfrastructureRef: v.GetString("TEST_SERVER_INFRASTRUCTURE_REF"),
		FileStorageSnapshotDir:  v.GetString("TEST_FILE_STORAGE_SNAPSHOT_DIR"),
	}

	// Validate required fields
	required := map[string]string{
		"API_BASE_URL":    config.BaseURL,
		"REGION_BASE_URL": config.RegionBaseURL,
		"TEST_ORG_ID":     config.OrgID,
		"TEST_PROJECT_ID": config.ProjectID,
	}

	if err := coreconfig.ValidateRequiredFields(required); err != nil {
		return nil, err
	}

	return config, nil
}

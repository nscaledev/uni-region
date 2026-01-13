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
	OrgID      string
	ProjectID  string
	RegionID   string
	IdentityID string
	NetworkID  string
	FlavorID   string
}

// LoadTestConfig loads configuration from environment variables and .env files using viper.
// Returns an error if required configuration values are missing.
func LoadTestConfig() (*TestConfig, error) {
	// Set up viper with config paths and defaults
	defaults := map[string]interface{}{
		"ENVIRONMENT":      "dev",
		"REQUEST_TIMEOUT":  "30s",
		"TEST_TIMEOUT":     "20m",
		"SKIP_INTEGRATION": false,
		"DEBUG_LOGGING":    false,
		"LOG_REQUESTS":     false,
		"LOG_RESPONSES":    false,
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

	// Get environment (dev or uat)
	environment := v.GetString("ENVIRONMENT")

	// Helper function to get environment-aware config value
	// Tries {ENVIRONMENT}_KEY first, falls back to KEY for backward compatibility
	getEnvString := func(key string) string {
		prefixedKey := environment + "_" + key
		if v.IsSet(prefixedKey) {
			return v.GetString(prefixedKey)
		}

		return v.GetString(key)
	}

	config := &TestConfig{
		BaseConfig: coreconfig.BaseConfig{
			BaseURL:         getEnvString("API_BASE_URL"),
			AuthToken:       getEnvString("API_AUTH_TOKEN"),
			RequestTimeout:  coreconfig.GetDurationFromViper(v, "REQUEST_TIMEOUT", 30*time.Second),
			TestTimeout:     coreconfig.GetDurationFromViper(v, "TEST_TIMEOUT", 20*time.Minute),
			SkipIntegration: v.GetBool("SKIP_INTEGRATION"),
			DebugLogging:    v.GetBool("DEBUG_LOGGING"),
			LogRequests:     v.GetBool("LOG_REQUESTS"),
			LogResponses:    v.GetBool("LOG_RESPONSES"),
		},
		OrgID:      getEnvString("TEST_ORG_ID"),
		ProjectID:  getEnvString("TEST_PROJECT_ID"),
		RegionID:   getEnvString("TEST_REGION_ID"),
		IdentityID: getEnvString("TEST_IDENTITY_ID"),
		NetworkID:  getEnvString("TEST_NETWORK_ID"),
		FlavorID:   getEnvString("TEST_FLAVOR_ID"),
	}

	// Validate required fields
	required := map[string]string{
		"API_BASE_URL":    config.BaseURL,
		"TEST_ORG_ID":     config.OrgID,
		"TEST_PROJECT_ID": config.ProjectID,
	}

	if err := coreconfig.ValidateRequiredFields(required); err != nil {
		return nil, err
	}

	return config, nil
}

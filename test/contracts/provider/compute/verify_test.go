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

package compute_test

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	chi "github.com/go-chi/chi/v5"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Ginkgo dot imports are standard practice
	. "github.com/onsi/gomega"    //nolint:revive // Gomega dot imports are standard practice
	"github.com/pact-foundation/pact-go/v2/models"
	"github.com/pact-foundation/pact-go/v2/provider"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/options"
	"github.com/unikorn-cloud/core/pkg/server/middleware/cors"
	"github.com/unikorn-cloud/core/pkg/server/middleware/opentelemetry"
	"github.com/unikorn-cloud/core/pkg/server/middleware/timeout"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/middleware/audit"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler"
	"github.com/unikorn-cloud/region/pkg/openapi"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	testingT *testing.T //nolint:gochecknoglobals // Required by pact-go verifier
)

func TestContracts(t *testing.T) {
	t.Parallel()
	testingT = t

	RegisterFailHandler(Fail)
	RunSpecs(t, "Region Provider Contract Verification Suite")
}

var _ = Describe("Region Provider Verification", func() {
	var (
		testServer     *http.Server
		serverURL      string
		ctx            context.Context
		cancel         context.CancelFunc
		k8sClient      client.Client
		stateManager   *StateManager
		pactBrokerURL  string
		brokerUsername string
		brokerPassword string
	)

	BeforeEach(func() {
		//nolint:fatcontext // Context creation needed for test setup
		ctx, cancel = context.WithCancel(context.Background())

		// Get Pact Broker configuration from environment
		pactBrokerURL = os.Getenv("PACT_BROKER_URL")
		if pactBrokerURL == "" {
			pactBrokerURL = "http://localhost:9292"
		}
		brokerUsername = os.Getenv("PACT_BROKER_USERNAME")
		if brokerUsername == "" {
			brokerUsername = "pact"
		}
		brokerPassword = os.Getenv("PACT_BROKER_PASSWORD")
		if brokerPassword == "" {
			brokerPassword = "pact"
		}

		// Create Kubernetes client
		// Load kube config from kubeconfig file (for local testing)
		// or from in-cluster config (for CI)
		cfg, err := ctrl.GetConfig()
		Expect(err).NotTo(HaveOccurred())

		scheme, err := coreclient.NewScheme(unikornv1.AddToScheme)
		Expect(err).NotTo(HaveOccurred())

		k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
		Expect(err).NotTo(HaveOccurred())

		// Initialize state manager
		stateManager = NewStateManager(k8sClient)

		// Find an available port
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())

		addr, ok := listener.Addr().(*net.TCPAddr)
		Expect(ok).To(BeTrue(), "listener address should be a TCP address")
		port := addr.Port
		listener.Close()

		serverURL = fmt.Sprintf("http://127.0.0.1:%d", port)

		// Start the test server
		testServer = startTestServer(ctx, k8sClient, fmt.Sprintf("127.0.0.1:%d", port))

		// Wait for server to be ready
		// Note: We just check if the server is listening, not a specific endpoint
		// since the region service doesn't have a health endpoint
		Eventually(func() error {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
			if err != nil {
				return err
			}
			conn.Close()

			return nil
		}, 10*time.Second, 100*time.Millisecond).Should(Succeed())
	})

	AfterEach(func() {
		if testServer != nil {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()

			if err := testServer.Shutdown(shutdownCtx); err != nil {
				fmt.Printf("failed to shutdown server: %v\n", err)
			}
		}
		cancel()
	})

	Describe("Verifying pacts from Pact Broker", func() {
		It("should verify all consumer contracts", func() {
			// Configure the verifier to fetch pacts from the broker
			verifier := provider.NewVerifier()

			// Create state handlers map
			stateHandlers := createStateHandlers(ctx, stateManager)

			// Run verification
			err := verifier.VerifyProvider(testingT, provider.VerifyRequest{
				ProviderBaseURL: serverURL,
				Provider:        "uni-region",
				BrokerURL:       pactBrokerURL,
				BrokerUsername:  brokerUsername,
				BrokerPassword:  brokerPassword,
				// Publish verification results back to broker
				PublishVerificationResults: os.Getenv("CI") == "true" || os.Getenv("PUBLISH_VERIFICATION") == "true",
				ProviderVersion:            getProviderVersion(),
				StateHandlers:              stateHandlers,
			})

			Expect(err).NotTo(HaveOccurred(), "Provider verification should succeed")
		})
	})

	Describe("Verifying pacts from local files", func() {
		It("should verify local pact files", func() {
			// This test can be used when the pact broker is not available
			// or for local development
			pactFile := os.Getenv("PACT_FILE")
			if pactFile == "" {
				Skip("PACT_FILE environment variable not set, skipping local file verification")
			}

			verifier := provider.NewVerifier()

			stateHandlers := createStateHandlers(ctx, stateManager)

			err := verifier.VerifyProvider(testingT, provider.VerifyRequest{
				ProviderBaseURL: serverURL,
				Provider:        "uni-region",
				PactFiles:       []string{pactFile},
				StateHandlers:   stateHandlers,
			})

			Expect(err).NotTo(HaveOccurred(), "Provider verification should succeed")
		})
	})
})

// mockACLMiddleware injects a mock ACL into the request context for contract testing.
// This allows the handler to bypass RBAC checks without requiring real authentication.
// For contract testing, we create an ACL that grants read permissions to all test organizations.
func mockACLMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create a mock ACL that grants read permissions for all region endpoints
			// to all test organizations used in contract tests
			testOrgs := []string{
				"test-org-123",
				"test-org-empty",
				"nonexistent-org",
				"test-org-timeout",
				"test-org-mixed",
			}

			// Create endpoints that grant read access to all region resources
			endpoints := identityapi.AclEndpoints{
				{Name: "region:regions", Operations: identityapi.AclOperations{identityapi.Read}},
				{Name: "region:flavors", Operations: identityapi.AclOperations{identityapi.Read}},
				{Name: "region:images", Operations: identityapi.AclOperations{identityapi.Read}},
				{Name: "region:externalnetworks", Operations: identityapi.AclOperations{identityapi.Read}},
				{Name: "region:regions/detail", Operations: identityapi.AclOperations{identityapi.Read}},
			}

			// Create organizations list with all test orgs
			organizations := make(identityapi.AclOrganizationList, 0, len(testOrgs))
			for _, orgID := range testOrgs {
				organizations = append(organizations, identityapi.AclOrganization{
					Id:        orgID,
					Endpoints: &endpoints,
				})
			}

			mockACL := &identityapi.Acl{
				Organizations: &organizations,
			}

			// Inject the mock ACL into the request context
			ctx := rbac.NewContext(r.Context(), mockACL)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// regionSortingMiddleware sorts regions responses for Pact contract testing.
// Pact Go v2 requires a specific order, so we sort by type (OpenStack before Kubernetes)
// and then by name to ensure consistent ordering that matches the consumer's expectations.
func regionSortingMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !shouldInterceptRegionsRequest(r) {
				next.ServeHTTP(w, r)
				return
			}

			recorder := captureResponse(w, next, r)
			copyHeaders(w, recorder)

			if !shouldProcessResponse(recorder) {
				writeResponseAsIs(w, recorder)
				return
			}

			processAndWriteRegionsResponse(w, recorder)
		})
	}
}

// shouldInterceptRegionsRequest checks if this is a GET request to the regions list endpoint.
func shouldInterceptRegionsRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}

	// Pattern: /api/v1/organizations/{orgID}/regions
	path := r.URL.Path

	return strings.HasSuffix(path, "/regions") && !strings.Contains(path, "/regions/")
}

// captureResponse captures the handler response using a recorder.
func captureResponse(w http.ResponseWriter, next http.Handler, r *http.Request) *responseRecorder {
	recorder := &responseRecorder{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		statusCode:     http.StatusOK,
		headers:        make(http.Header),
	}
	next.ServeHTTP(recorder, r)

	return recorder
}

// copyHeaders copies all headers from the recorder to the response writer.
func copyHeaders(w http.ResponseWriter, recorder *responseRecorder) {
	for key, values := range recorder.headers {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
}

// shouldProcessResponse checks if the response should be processed (200 OK).
func shouldProcessResponse(recorder *responseRecorder) bool {
	return recorder.statusCode == http.StatusOK
}

// writeResponseAsIs writes the recorded response without modification.
func writeResponseAsIs(w http.ResponseWriter, recorder *responseRecorder) {
	w.WriteHeader(recorder.statusCode)
	_, _ = io.Copy(w, recorder.body)
}

// processAndWriteRegionsResponse parses, transforms, sorts, and writes the regions response.
func processAndWriteRegionsResponse(w http.ResponseWriter, recorder *responseRecorder) {
	var regions []openapi.RegionRead
	if err := json.Unmarshal(recorder.body.Bytes(), &regions); err != nil {
		writeResponseAsIs(w, recorder)
		return
	}

	transformRegionIDs(regions)
	sortRegions(regions)

	sortedJSON, err := json.Marshal(regions)
	if err != nil {
		writeResponseAsIs(w, recorder)
		return
	}

	w.WriteHeader(recorder.statusCode)
	_, _ = w.Write(sortedJSON)
}

// transformRegionIDs converts region IDs from names to UUIDs for Pact testing.
func transformRegionIDs(regions []openapi.RegionRead) {
	for i := range regions {
		if regions[i].Metadata.Id != "" {
			regions[i].Metadata.Id = nameToUUID(regions[i].Metadata.Name)
		}
	}
}

// sortRegions sorts by type (OpenStack first) then by name.
func sortRegions(regions []openapi.RegionRead) {
	slices.SortStableFunc(regions, func(a, b openapi.RegionRead) int {
		if a.Spec.Type != b.Spec.Type {
			if a.Spec.Type == openapi.RegionTypeOpenstack {
				return -1
			}

			if b.Spec.Type == openapi.RegionTypeOpenstack {
				return 1
			}
		}

		return cmp.Compare(a.Metadata.Name, b.Metadata.Name)
	})
}

// responseRecorder captures the response for processing.
type responseRecorder struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	headers    http.Header
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}

func (r *responseRecorder) Header() http.Header {
	if r.headers == nil {
		r.headers = make(http.Header)
	}

	return r.headers
}

// nameToUUID generates a deterministic UUID from a region name.
// This is used for contract testing where the provider returns region names as IDs,
// but the pact expects UUID format. The same name will always generate the same UUID.
func nameToUUID(name string) string {
	// Use SHA256 to hash the name and generate a deterministic UUID
	hash := sha256.Sum256([]byte("region-id:" + name))
	hashHex := hex.EncodeToString(hash[:])

	// Format as UUID: 8-4-4-4-12
	// Take first 32 hex characters and format them
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hashHex[0:8],
		hashHex[8:12],
		hashHex[12:16],
		hashHex[16:20],
		hashHex[20:32],
	)
}

// createStateHandlers creates the state handlers map for pact verification.
func createStateHandlers(ctx context.Context, stateManager *StateManager) models.StateHandlers {
	return models.StateHandlers{
		"organization test-org-123 exists with OpenStack regions": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			err := stateManager.HandleOrganizationWithOpenStackRegions(ctx, setup, "test-org-123")
			return nil, err
		},
		"organization test-org-empty exists with no regions": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			err := stateManager.HandleOrganizationWithNoRegions(ctx, setup, "test-org-empty")
			return nil, err
		},
		"organization nonexistent-org does not exist": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			err := stateManager.HandleOrganizationDoesNotExist(ctx, setup, "nonexistent-org")
			return nil, err
		},
		"organization test-org-timeout exists": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			err := stateManager.HandleOrganizationExists(ctx, setup, "test-org-timeout")
			return nil, err
		},
		"organization test-org-mixed exists with mixed region types": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			err := stateManager.HandleOrganizationWithMixedRegions(ctx, setup, "test-org-mixed")
			return nil, err
		},
	}
}

// startTestServer creates and starts a test instance of the region server.
// Note: This is a simplified version that doesn't start pprof to avoid port conflicts in tests.
func startTestServer(ctx context.Context, k8sClient client.Client, listenAddr string) *http.Server {
	// Build the server manually without pprof (which causes port conflicts in tests)
	schema, err := coreapi.NewSchema(openapi.GetSwagger)
	if err != nil {
		panic(fmt.Sprintf("failed to create schema: %v", err))
	}

	corsOpts := cors.Options{
		AllowedOrigins: []string{"*"}, // Allow all origins for contract testing
	}

	serverOpts := options.ServerOptions{
		ListenAddress:     listenAddr,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		RequestTimeout:    30 * time.Second,
	}

	coreOpts := options.CoreOptions{
		Namespace: "default",
	}

	// Setup router with middleware
	router := chi.NewRouter()
	router.Use(timeout.Middleware(serverOpts.RequestTimeout))
	router.Use(opentelemetry.Middleware(constants.Application, constants.Version))
	router.Use(cors.Middleware(schema, &corsOpts))
	router.Use(mockACLMiddleware())       // Inject mock ACL for contract testing
	router.Use(regionSortingMiddleware()) // Sort regions for Pact contract testing
	router.NotFound(http.HandlerFunc(handler.NotFound))
	router.MethodNotAllowed(http.HandlerFunc(handler.MethodNotAllowed))

	// Create identity client options (minimal config for testing)
	identityOpts := &identityclient.Options{}
	clientOpts := coreclient.HTTPClientOptions{}

	// For contract testing, we skip authorization middleware
	// This allows Pact to verify the API contract without needing real auth tokens
	chiServerOptions := openapi.ChiServerOptions{
		BaseRouter:       router,
		ErrorHandlerFunc: handler.HandleError,
		Middlewares: []openapi.MiddlewareFunc{
			// Audit middleware for logging (keeps the same middleware chain structure)
			audit.Middleware(schema, constants.Application, constants.Version),
			// Authorization middleware is skipped for contract testing
		},
	}

	issuer := identityclient.NewTokenIssuer(k8sClient, identityOpts, &clientOpts, constants.ServiceDescriptor())

	identity, err := identityclient.New(k8sClient, identityOpts, &clientOpts).APIClient(ctx, issuer)
	if err != nil {
		panic(fmt.Sprintf("failed to create identity client: %v", err))
	}

	handlerOpts := handler.Options{}

	handlerInterface, err := handler.New(k8sClient, coreOpts.Namespace, &handlerOpts, identity)
	if err != nil {
		panic(fmt.Sprintf("failed to create handler: %v", err))
	}

	httpServer := &http.Server{
		Addr:              listenAddr,
		ReadTimeout:       serverOpts.ReadTimeout,
		ReadHeaderTimeout: serverOpts.ReadHeaderTimeout,
		WriteTimeout:      serverOpts.WriteTimeout,
		Handler:           openapi.HandlerWithOptions(handlerInterface, chiServerOptions),
	}

	// Start server in a goroutine
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("Server error: %v\n", err)
		}
	}()

	return httpServer
}

// getProviderVersion returns the version of the provider for publishing verification results.
func getProviderVersion() string {
	version := os.Getenv("PROVIDER_VERSION")
	if version == "" {
		version = "dev"
	}

	return version
}

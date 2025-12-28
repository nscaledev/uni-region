/*
Copyright 2025 the Unikorn Authors.

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
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
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
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler"
	"github.com/unikorn-cloud/region/pkg/openapi"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Test organization IDs.
	testOrg123      = "test-org-123"
	testOrgEmpty    = "test-org-empty"
	testOrgNonExist = "nonexistent-org"
	testOrgTimeout  = "test-org-timeout"
	testOrgMixed    = "test-org-mixed"
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
			// we create the state handlers map here so we can use it in the verifier tests.
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

// createStateHandlers creates the state handlers map for pact verification.
func createStateHandlers(ctx context.Context, stateManager *StateManager) models.StateHandlers {
	return models.StateHandlers{
		"organization test-org-123 exists with OpenStack regions": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			err := stateManager.HandleOrganizationWithOpenStackRegions(ctx, setup, testOrg123)
			return nil, err
		},
		"organization test-org-empty exists with no regions": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			err := stateManager.HandleOrganizationWithNoRegions(ctx, setup, testOrgEmpty)
			return nil, err
		},
		"organization nonexistent-org does not exist": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			err := stateManager.HandleOrganizationDoesNotExist(ctx, setup, testOrgNonExist)
			return nil, err
		},
		"organization test-org-timeout exists": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			err := stateManager.HandleOrganizationExists(ctx, setup, testOrgTimeout)
			return nil, err
		},
		"organization test-org-mixed exists with mixed region types": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			err := stateManager.HandleOrganizationWithMixedRegions(ctx, setup, testOrgMixed)
			return nil, err
		},
	}
}

// buildServerOptions creates server configuration options for contract testing.
func buildServerOptions(listenAddr string) options.ServerOptions {
	return options.ServerOptions{
		ListenAddress:     listenAddr,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		RequestTimeout:    30 * time.Second,
	}
}

// buildCORSOptions creates CORS configuration options for contract testing.
func buildCORSOptions() cors.Options {
	return cors.Options{
		AllowedOrigins: []string{"*"}, // Allow all origins for contract testing
	}
}

// buildRouter creates and configures the Chi router with middleware.
func buildRouter(serverOpts options.ServerOptions, schema *coreapi.Schema, corsOpts *cors.Options) *chi.Mux {
	router := chi.NewRouter()
	router.Use(timeout.Middleware(serverOpts.RequestTimeout))
	router.Use(opentelemetry.Middleware(constants.Application, constants.Version))
	router.Use(cors.Middleware(schema, corsOpts))

	// Create list of test organizations for mock ACL
	testOrgs := []string{
		testOrg123,
		testOrgEmpty,
		testOrgNonExist,
		testOrgTimeout,
		testOrgMixed,
	}

	router.Use(MockACLMiddleware(testOrgs)) // Inject mock ACL for contract testing
	router.Use(RegionSortingMiddleware())   // Sort regions for Pact contract testing
	router.NotFound(http.HandlerFunc(handler.NotFound))
	router.MethodNotAllowed(http.HandlerFunc(handler.MethodNotAllowed))

	return router
}

// buildChiServerOptions creates Chi server options for contract testing.
// Authorization middleware is skipped to allow Pact verification without real auth tokens.
func buildChiServerOptions(router *chi.Mux, schema *coreapi.Schema) openapi.ChiServerOptions {
	return openapi.ChiServerOptions{
		BaseRouter:       router,
		ErrorHandlerFunc: handler.HandleError,
		Middlewares: []openapi.MiddlewareFunc{
			// Audit middleware for logging (keeps the same middleware chain structure)
			audit.Middleware(schema, constants.Application, constants.Version),
			// Authorization middleware is skipped for contract testing
		},
	}
}

// createHandlerInterface creates the region handler with dependencies.
func createHandlerInterface(ctx context.Context, k8sClient client.Client, namespace string) *handler.Handler {
	// Create identity client options (minimal config for testing)
	identityOpts := &identityclient.Options{}
	clientOpts := coreclient.HTTPClientOptions{}

	issuer := identityclient.NewTokenIssuer(k8sClient, identityOpts, &clientOpts, constants.ServiceDescriptor())

	identity, err := identityclient.New(k8sClient, identityOpts, &clientOpts).APIClient(ctx, issuer)
	if err != nil {
		panic(fmt.Sprintf("failed to create identity client: %v", err))
	}

	handlerOpts := handler.Options{}

	handlerInterface, err := handler.New(k8sClient, namespace, &handlerOpts, identity)
	if err != nil {
		panic(fmt.Sprintf("failed to create handler: %v", err))
	}

	return handlerInterface
}

// startServerAsync starts the HTTP server in a background goroutine.
func startServerAsync(httpServer *http.Server) {
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("Server error: %v\n", err)
		}
	}()
}

// startTestServer creates and starts a test instance of the region server.
// Note: This is a simplified version that doesn't start pprof to avoid port conflicts in tests.
func startTestServer(ctx context.Context, k8sClient client.Client, listenAddr string) *http.Server {
	// Build the server manually without pprof (which causes port conflicts in tests)
	schema, err := coreapi.NewSchema(openapi.GetSwagger)
	if err != nil {
		panic(fmt.Sprintf("failed to create schema: %v", err))
	}

	serverOpts := buildServerOptions(listenAddr)
	corsOpts := buildCORSOptions()
	router := buildRouter(serverOpts, schema, &corsOpts)
	chiServerOptions := buildChiServerOptions(router, schema)

	coreOpts := options.CoreOptions{
		Namespace: "default",
	}

	handlerInterface := createHandlerInterface(ctx, k8sClient, coreOpts.Namespace)

	httpServer := &http.Server{
		Addr:              listenAddr,
		ReadTimeout:       serverOpts.ReadTimeout,
		ReadHeaderTimeout: serverOpts.ReadHeaderTimeout,
		WriteTimeout:      serverOpts.WriteTimeout,
		Handler:           openapi.HandlerWithOptions(handlerInterface, chiServerOptions),
	}

	startServerAsync(httpServer)

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

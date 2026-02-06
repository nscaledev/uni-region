//go:build integration

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

package kubernetes_test

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
	"github.com/unikorn-cloud/core/pkg/openapi/helpers"
	"github.com/unikorn-cloud/core/pkg/options"
	"github.com/unikorn-cloud/core/pkg/server/middleware/cors"
	"github.com/unikorn-cloud/core/pkg/server/middleware/logging"
	"github.com/unikorn-cloud/core/pkg/server/middleware/opentelemetry"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/middleware/audit"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers"

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
				ProviderBranch:             getProviderBranch(),
				ConsumerVersionSelectors: []provider.Selector{
					&provider.ConsumerVersionSelector{
						Consumer:   "uni-kubernetes",
						MainBranch: true,
					},
					&provider.ConsumerVersionSelector{
						Consumer:       "uni-kubernetes",
						MatchingBranch: true,
					},
				},
				EnablePending: true,
				StateHandlers: stateHandlers,
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
// Registers state handlers for uni-kubernetes consumer contract tests.
func createStateHandlers(ctx context.Context, stateManager *StateManager) models.StateHandlers {
	return models.StateHandlers{
		// State handler for "region exists"
		StateRegionExists: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			fmt.Printf("State: %s, Parameters: %+v\n", state.Name, state.Parameters)
			err := stateManager.HandleRegionExistsState(ctx, setup, state.Parameters)

			return nil, err
		},

		// State handler for "project exists in region"
		StateProjectExistsInRegion: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			fmt.Printf("State: %s, Parameters: %+v\n", state.Name, state.Parameters)
			err := stateManager.HandleProjectExistsInRegionState(ctx, setup, state.Parameters)

			return nil, err
		},

		// State handler for "server exists in project"
		StateServerExistsInProject: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			fmt.Printf("State: %s, Parameters: %+v\n", state.Name, state.Parameters)
			err := stateManager.HandleServerExistsInProjectState(ctx, setup, state.Parameters)

			return nil, err
		},

		// State handler for "identity exists"
		StateIdentityExists: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			fmt.Printf("State: %s, Parameters: %+v\n", state.Name, state.Parameters)
			err := stateManager.HandleIdentityExistsState(ctx, setup, state.Parameters)

			return nil, err
		},

		// State handler for "identity exists with physical network support"
		StateIdentityExistsWithPhysicalNet: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			fmt.Printf("State: %s, Parameters: %+v\n", state.Name, state.Parameters)
			err := stateManager.HandleIdentityExistsWithPhysicalNetState(ctx, setup, state.Parameters)

			return nil, err
		},

		// State handler for "identity is provisioned"
		StateIdentityIsProvisioned: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			fmt.Printf("State: %s, Parameters: %+v\n", state.Name, state.Parameters)
			err := stateManager.HandleIdentityIsProvisionedState(ctx, setup, state.Parameters)

			return nil, err
		},

		// State handler for "network is provisioned"
		StateNetworkIsProvisioned: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			fmt.Printf("State: %s, Parameters: %+v\n", state.Name, state.Parameters)
			err := stateManager.HandleNetworkIsProvisionedState(ctx, setup, state.Parameters)

			return nil, err
		},

		// State handler for "region has external networks"
		StateRegionHasExternalNetworks: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			fmt.Printf("State: %s, Parameters: %+v\n", state.Name, state.Parameters)
			err := stateManager.HandleRegionHasExternalNetworksState(ctx, setup, state.Parameters)

			return nil, err
		},

		// State handler for "region has flavors"
		StateRegionHasFlavors: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			fmt.Printf("State: %s, Parameters: %+v\n", state.Name, state.Parameters)
			err := stateManager.HandleRegionHasFlavorsState(ctx, setup, state.Parameters)

			return nil, err
		},

		// State handler for "region has images"
		StateRegionHasImages: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			fmt.Printf("State: %s, Parameters: %+v\n", state.Name, state.Parameters)
			err := stateManager.HandleRegionHasImagesState(ctx, setup, state.Parameters)

			return nil, err
		},

		// State handler for "organization has regions"
		StateOrganizationHasRegions: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			fmt.Printf("State: %s, Parameters: %+v\n", state.Name, state.Parameters)
			err := stateManager.HandleOrganizationHasRegionsState(ctx, setup, state.Parameters)

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
func buildRouter(schema *helpers.Schema, corsOpts *cors.Options) *chi.Mux {
	opentelemetry := opentelemetry.New(constants.Application, constants.Version)
	logging := logging.New()
	routeresolver := routeresolver.New(schema)
	cors := cors.New(corsOpts)

	router := chi.NewRouter()
	router.Use(opentelemetry.Middleware)
	router.Use(logging.Middleware)
	router.Use(routeresolver.Middleware)
	router.Use(cors.Middleware)

	// Mock ACL middleware allows all organizations for contract testing
	router.Use(MockACLMiddleware(nil))           // Inject mock ACL for contract testing
	router.Use(IdentityCreationMockMiddleware()) // Mock identity creation for contract testing
	router.Use(ExternalNetworksMockMiddleware()) // Mock external networks for OpenStack-specific tests
	router.Use(ImagesMockMiddleware())           // Mock images for OpenStack-specific tests
	router.Use(RegionSortingMiddleware())        // Sort regions for Pact contract testing
	router.NotFound(http.HandlerFunc(handler.NotFound))
	router.MethodNotAllowed(http.HandlerFunc(handler.MethodNotAllowed))

	return router
}

// buildChiServerOptions creates Chi server options for contract testing.
// Authorization middleware is skipped to allow Pact verification without real auth tokens.
func buildChiServerOptions(router *chi.Mux) openapi.ChiServerOptions {
	audit := audit.New(constants.Application, constants.Version)

	return openapi.ChiServerOptions{
		BaseRouter:       router,
		ErrorHandlerFunc: handler.HandleError,
		Middlewares: []openapi.MiddlewareFunc{
			// Audit middleware for logging (keeps the same middleware chain structure)
			audit.Middleware,
			// Authorization middleware is skipped for contract testing
		},
	}
}

// createHandlerInterface creates the region handler with dependencies.
func createHandlerInterface(ctx context.Context, k8sClient client.Client, namespace string) *handler.Handler {
	// Create identity client options (minimal config for testing)
	identityOpts := identityclient.NewOptions()
	clientOpts := coreclient.HTTPClientOptions{}

	identity, err := identityclient.New(k8sClient, identityOpts, &clientOpts).APIClient(ctx)
	if err != nil {
		panic(fmt.Sprintf("failed to create identity client: %v", err))
	}

	// Create providers interface
	providers := providers.New(k8sClient, namespace)

	handlerOpts := handler.Options{}

	handlerInterface, err := handler.New(common.ClientArgs{
		Client:    k8sClient,
		Namespace: namespace,
		Providers: providers,
		Identity:  identity,
	}, &handlerOpts)
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
	schema, err := helpers.NewSchema(openapi.GetSwagger)
	if err != nil {
		panic(fmt.Sprintf("failed to create schema: %v", err))
	}

	serverOpts := buildServerOptions(listenAddr)
	corsOpts := buildCORSOptions()
	router := buildRouter(schema, &corsOpts)
	chiServerOptions := buildChiServerOptions(router)

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

func getProviderBranch() string {
	return os.Getenv("GIT_BRANCH")
}

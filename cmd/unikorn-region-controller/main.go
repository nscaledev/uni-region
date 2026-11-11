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

package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/server"

	"k8s.io/client-go/rest"

	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// kubernetesClientQPS and kubernetesClientBurst size the client-side
	// rate limiter; every handler read is an API-server request.
	kubernetesClientQPS   = 100
	kubernetesClientBurst = 200
)

// start is the entry point to server.
func start() {
	s := &server.Server{}
	s.AddFlags(pflag.CommandLine)

	pflag.Parse()

	// Get logging going first, log sinks will expect JSON formatted output for everything.
	s.SetupLogging()

	logger := log.Log.WithName(constants.Application)

	// Hello World!
	logger.Info("service starting", "application", constants.Application, "version", constants.Version, "revision", constants.Revision)

	// Create a root context for things to hang off of.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := s.SetupOpenTelemetry(ctx); err != nil {
		logger.Error(err, "failed to setup OpenTelemetry")

		return
	}

	kubernetesClient, err := newKubernetesClient()
	if err != nil {
		logger.Error(err, "failed to create Kubernetes client")

		return
	}

	server, err := s.GetServer(ctx, kubernetesClient)
	if err != nil {
		logger.Error(err, "failed to setup Handler")

		return
	}

	// Register a signal handler to trigger a graceful shutdown.
	stop := make(chan os.Signal, 1)

	signal.Notify(stop, syscall.SIGTERM)

	go func() {
		<-stop

		// Cancel anything hanging off the root context.
		cancel()

		// Shutdown the server, Kubernetes gives us 30 seconds before a SIGKILL.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			logger.Error(err, "server shutdown error")
		}
	}()

	if err := server.ListenAndServe(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return
		}

		logger.Error(err, "unexpected server error")

		return
	}
}

func main() {
	start()
}

// newKubernetesClient returns a client whose reads go straight to the API
// server, so a read cannot miss a write that has been acknowledged. A list is
// one round trip, served from the API server's watch cache where
// ConsistentListFromCache is enabled, the default since Kubernetes 1.31.
func newKubernetesClient() (ctrlclient.Client, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	config.QPS = kubernetesClientQPS
	config.Burst = kubernetesClientBurst

	scheme, err := coreclient.NewScheme(unikornv1.AddToScheme)
	if err != nil {
		return nil, err
	}

	return ctrlclient.New(config, ctrlclient.Options{Scheme: scheme})
}

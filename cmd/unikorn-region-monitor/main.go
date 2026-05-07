/*
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
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/monitor"

	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func run() error {
	// Initialize components with legacy flags.
	zapOptions := &zap.Options{}
	zapOptions.BindFlags(flag.CommandLine)

	// Initialize components with flags, then parse them.
	monitorOptions := &monitor.Options{}
	monitorOptions.AddFlags(pflag.CommandLine)

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()

	// Get logging going first, log sinks will expect JSON formatted output for everything.
	log.SetLogger(zap.New(zap.UseFlagOptions(zapOptions)))

	logger := log.Log.WithName(constants.Application)

	// Hello World!
	logger.Info("service starting", "application", constants.Application, "version", constants.Version, "revision", constants.Revision)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Register a signal handler to trigger a graceful shutdown.
	stop := make(chan os.Signal, 1)

	signal.Notify(stop, syscall.SIGTERM)

	go func() {
		<-stop

		// Cancel anything hanging off the root context.
		cancel()
	}()

	if err := monitorOptions.CoreOptions.SetupOpenTelemetry(ctx); err != nil {
		logger.Error(err, "failed to setup OpenTelemetry")

		return err
	}

	if meterProvider, ok := otel.GetMeterProvider().(*sdkmetric.MeterProvider); ok {
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := meterProvider.Shutdown(shutdownCtx); err != nil {
				logger.Error(err, "failed to shutdown meter provider")
			}
		}()
	} else {
		logger.Info("meter provider type unexpected, skipping graceful shutdown")
	}

	client, err := coreclient.New(ctx, unikornv1.AddToScheme)
	if err != nil {
		logger.Error(err, "failed to create client")

		return err
	}

	return monitor.Run(ctx, client, monitorOptions)
}

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

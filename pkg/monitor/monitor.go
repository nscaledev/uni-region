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

package monitor

import (
	"context"
	"time"

	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel"

	"github.com/unikorn-cloud/core/pkg/options"
	"github.com/unikorn-cloud/region/pkg/constants"
	serverhealth "github.com/unikorn-cloud/region/pkg/monitor/health/server"
	"github.com/unikorn-cloud/region/pkg/providers"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Options allow modification of parameters via the CLI.
type Options struct {
	// CoreOptions provides --namespace, --otlp-endpoint, logging, and OTel setup.
	CoreOptions options.CoreOptions

	// pollPeriod defines how often to run.  There's no harm in having it
	// run with high frequency, reads are all cached.  It's mostly down to
	// burning CPU unnecessarily.
	pollPeriod time.Duration
}

// AddFlags registers option flags with pflag.
func (o *Options) AddFlags(flags *pflag.FlagSet) {
	o.CoreOptions.AddFlags(flags)
	flags.DurationVar(&o.pollPeriod, "poll-period", time.Minute, "Period to poll for updates")
}

// Checker is an interface that monitors must implement.
type Checker interface {
	// Check does whatever the checker is checking for.
	Check(ctx context.Context) error
}

// Run sits in an infinite loop, polling every so often.
// It returns an error if initialisation fails; a nil return means the context
// was cancelled and the monitor shut down cleanly.
func Run(ctx context.Context, c client.Client, o *Options) error {
	log := log.FromContext(ctx)

	providerCache, err := providers.New(ctx, c, c, o.CoreOptions.Namespace, providers.Options{})
	if err != nil {
		log.Error(err, "failed to initialize providers")

		return err
	}

	meter := otel.GetMeterProvider().Meter(constants.Application)

	serverMetrics, err := serverhealth.NewMetrics(meter)
	if err != nil {
		log.Error(err, "failed to initialize server metrics")

		return err
	}

	ticker := time.NewTicker(o.pollPeriod)
	defer ticker.Stop()

	checkers := []Checker{
		serverhealth.New(c, o.CoreOptions.Namespace, providerCache, serverMetrics),
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			for _, checker := range checkers {
				if err := checker.Check(ctx); err != nil {
					log.Error(err, "check failed")
				}
			}
		}
	}
}

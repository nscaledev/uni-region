/*
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

package server

import (
	"context"
	"errors"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	attrState = "state"

	// stateGaugeTimeout bounds a count, so it cannot hold up the scrape of
	// every other metric.
	stateGaugeTimeout = 5 * time.Second
)

// stateKey is one series of the state gauge.
type stateKey struct {
	state      string
	regionID   string
	regionName string
}

type stateGauge struct {
	gauge     metric.Int64ObservableGauge
	reader    client.Reader
	namespace string
}

// RegisterStateGauge registers unikorn_region_server_state, counted from
// reader each time it is collected.  reader MUST be the manager's cache: the
// count reads every server, and makes no API server or cloud call.  See the
// README's Server State Gauge section.
func RegisterStateGauge(meter metric.Meter, reader client.Reader, namespace string) error {
	gauge, err := meter.Int64ObservableGauge(
		"unikorn_region_server_state",
		metric.WithDescription("Number of servers currently in each lifecycle state, per region."),
	)
	if err != nil {
		return err
	}

	g := &stateGauge{
		gauge:     gauge,
		reader:    reader,
		namespace: namespace,
	}

	_, err = meter.RegisterCallback(g.observe, gauge)

	return err
}

// observe reports nothing when it cannot count: a partial count would read as
// servers going away.
func (g *stateGauge) observe(ctx context.Context, o metric.Observer) error {
	ctx, cancel := context.WithTimeout(ctx, stateGaugeTimeout)
	defer cancel()

	counts, err := g.count(ctx)
	if err != nil {
		var notStarted *cache.ErrCacheNotStarted

		if !errors.As(err, &notStarted) {
			log.Log.Error(err, "failed to count servers for the state gauge")
		}

		return nil
	}

	for k, n := range counts {
		o.ObserveInt64(g.gauge, n, metric.WithAttributes(
			attribute.String(attrState, k.state),
			attribute.String(attrRegionID, k.regionID),
			attribute.String(attrRegionName, k.regionName),
		))
	}

	return nil
}

// count leaves out servers being deleted, and servers with no region.  The
// lists are not copied: count only reads them.
func (g *stateGauge) count(ctx context.Context) (map[stateKey]int64, error) {
	regions := &unikornv1.RegionList{}

	if err := g.reader.List(ctx, regions, client.InNamespace(g.namespace), client.UnsafeDisableDeepCopy); err != nil {
		return nil, err
	}

	regionNames := make(map[string]string, len(regions.Items))

	for i := range regions.Items {
		regionNames[regions.Items[i].Name] = regions.Items[i].Labels[coreconstants.NameLabel]
	}

	servers := &unikornv1.ServerList{}

	if err := g.reader.List(ctx, servers, client.InNamespace(g.namespace), client.UnsafeDisableDeepCopy); err != nil {
		return nil, err
	}

	counts := map[stateKey]int64{}

	for i := range servers.Items {
		server := &servers.Items[i]

		if server.DeletionTimestamp != nil {
			continue
		}

		regionID, ok := server.Labels[constants.RegionLabel]
		if !ok {
			continue
		}

		// A server not yet observed has no Active condition, and counts
		// under an empty state.
		var state unikornv1.ActiveConditionReason

		if active, err := unikornv1.GetActiveCondition(server); err == nil {
			state = active.Reason
		}

		counts[stateKey{
			state:      strings.ToLower(string(state)),
			regionID:   regionID,
			regionName: regionNames[regionID],
		}]++
	}

	return counts, nil
}

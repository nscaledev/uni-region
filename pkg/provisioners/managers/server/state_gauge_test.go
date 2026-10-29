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

package server_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	serverprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	gaugeNamespace = "unikorn-region"
	gaugeRegionID  = "region-a"
)

// gaugeServer returns a server in region-a, in the given state; an empty
// reason leaves it unobserved.
func gaugeServer(name string, reason unikornv1.ActiveConditionReason) *unikornv1.Server {
	server := &unikornv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gaugeNamespace,
			Name:      name,
			Labels:    map[string]string{constants.RegionLabel: gaugeRegionID},
		},
	}

	if reason != "" {
		server.SetActiveCondition(reason)
	}

	return server
}

// collectStates registers the gauge over objects and returns its points as
// "state/region_id/region_name" to count.
func collectStates(t *testing.T, funcs interceptor.Funcs, objects ...client.Object) map[string]int64 {
	t.Helper()

	scheme, err := coreclient.NewScheme(unikornv1.AddToScheme)
	require.NoError(t, err)

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithInterceptorFuncs(funcs).Build()

	provider, reader := newTestMeter(t)

	require.NoError(t, serverprovisioner.RegisterStateGauge(provider.Meter("test"), c, gaugeNamespace))

	var data metricdata.ResourceMetrics

	require.NoError(t, reader.Collect(t.Context(), &data))

	points := map[string]int64{}

	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != "unikorn_region_server_state" {
				continue
			}

			gauge, ok := m.Data.(metricdata.Gauge[int64])
			require.True(t, ok)

			for _, point := range gauge.DataPoints {
				points[attr(point.Attributes, "state")+"/"+attr(point.Attributes, "region_id")+"/"+attr(point.Attributes, "region_name")] = point.Value
			}
		}
	}

	return points
}

func attr(set attribute.Set, key string) string {
	v, _ := set.Value(attribute.Key(key))

	return v.AsString()
}

// TestStateGaugeCounts pins what the dashboard reads: servers counted by
// lowercased Active reason and region, with the region's display name, leaving
// out servers being deleted, servers with no region and other namespaces.
func TestStateGaugeCounts(t *testing.T) {
	t.Parallel()

	region := &unikornv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: gaugeNamespace,
			Name:      gaugeRegionID,
			Labels:    map[string]string{coreconstants.NameLabel: "Region A"},
		},
	}

	deleting := gaugeServer("deleting", unikornv1.ActiveConditionReasonRunning)
	deleting.Finalizers = []string{"test"}
	deleting.DeletionTimestamp = &metav1.Time{Time: time.Unix(1, 0)}

	noRegion := gaugeServer("no-region", unikornv1.ActiveConditionReasonRunning)
	noRegion.Labels = nil

	elsewhere := gaugeServer("elsewhere", unikornv1.ActiveConditionReasonRunning)
	elsewhere.Namespace = "other"

	points := collectStates(t, interceptor.Funcs{},
		region,
		gaugeServer("running-1", unikornv1.ActiveConditionReasonRunning),
		gaugeServer("running-2", unikornv1.ActiveConditionReasonRunning),
		gaugeServer("stopped", unikornv1.ActiveConditionReasonStopped),
		gaugeServer("unobserved", ""),
		deleting,
		noRegion,
		elsewhere,
	)

	require.Equal(t, map[string]int64{
		"running/region-a/Region A": 2,
		"stopped/region-a/Region A": 1,
		"/region-a/Region A":        1,
	}, points)
}

// TestStateGaugeReportsNothingWhenItCannotCount pins that a failed read
// reports no series rather than a partial count.
func TestStateGaugeReportsNothingWhenItCannotCount(t *testing.T) {
	t.Parallel()

	for name, failing := range map[string]client.ObjectList{
		"servers": &unikornv1.ServerList{},
		"regions": &unikornv1.RegionList{},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			funcs := interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if fmt.Sprintf("%T", list) == fmt.Sprintf("%T", failing) {
						return errUnavailable
					}

					return c.List(ctx, list, opts...)
				},
			}

			points := collectStates(t, funcs, gaugeServer("running", unikornv1.ActiveConditionReasonRunning))

			require.Empty(t, points)
		})
	}
}

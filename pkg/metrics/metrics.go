/*
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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/external-secrets/external-secrets/pkg/constants"
)

// Constants for Prometheus metrics
const (
	// Subsystem name for external secret metrics
	ExternalSecretSubsystem = "externalsecret"

	// Name of the metric for tracking API calls
	providerAPICalls = "provider_api_calls_count"
)

// Define a Prometheus CounterVec metric to track API calls to the secret provider
var (
	// syncCallsTotal tracks the number of API calls
	syncCallsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Subsystem: ExternalSecretSubsystem, 
		Name:      providerAPICalls,        
		Help:      "Number of API calls towards the secret provider", 
	}, []string{"provider", "call", "status"}) // Labels for categorization
)

// ObserveAPICall records an API call metric
func ObserveAPICall(provider, call string, err error) {
	// Increment the API call counter with the appropriate labels
	syncCallsTotal.WithLabelValues(provider, call, deriveStatus(err)).Inc()
}

// deriveStatus returns the status of an API call based on the error
func deriveStatus(err error) string {
	if err != nil {
		return constants.StatusError // Return 'error' status if there was an error
	}
	return constants.StatusSuccess // Return 'success' status if there was no error
}

// init registers the Prometheus metrics with the metrics registry
func init() {
	// Register syncCallsTotal with DefaultRegisterer
	metrics.Registry.MustRegister(syncCallsTotal)
}

package api

import (
	"net/http"
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	goroutinesGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "controller_goroutines",
		Help: "Number of goroutines",
	})

	registeredAgentsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "controller_registered_agents",
		Help: "Number of registered agents",
	})

	// Add more metrics as needed
)

func init() {
	prometheus.MustRegister(goroutinesGauge)
	prometheus.MustRegister(registeredAgentsGauge)
	// Register more metrics
}

func (ap *ControllerAPI) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	goroutinesGauge.Set(float64(runtime.NumGoroutine()))
	registeredAgentsGauge.Set(float64(ap.controller.GetRegisteredAgentsCount()))

	// Update more metrics here

	promhttp.Handler().ServeHTTP(w, r)
}

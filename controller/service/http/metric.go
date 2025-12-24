package http

import (
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	memoryUsageGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "agent_memory_usage_bytes",
		Help: "Current memory usage of the program in bytes",
	})
	loadRunnerGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "agent_load_runner_count",
		Help: "Successful load runner count",
	})
)

func init() {
	prometheus.MustRegister(memoryUsageGauge, loadRunnerGauge)
	recordMetrics()
}

func recordMetrics() {
	go func() {
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			memoryUsageGauge.Set(float64(m.Alloc))
			time.Sleep(2 * time.Second)
		}
	}()

	go func() {
		for {
			// loadRunnerGauge.Set(float64(len(global.RunnerList)))
			time.Sleep(2 * time.Second)
		}
	}()
}

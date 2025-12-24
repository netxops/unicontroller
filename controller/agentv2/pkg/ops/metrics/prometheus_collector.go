package metrics

// PrometheusCollector 基于 Prometheus client_golang 实现的增强型指标收集器
// 这个实现不直接依赖 node_exporter，而是参考其指标定义，使用 Prometheus 标准库实现

/*
import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// PrometheusMetricsCollector 基于 Prometheus 的指标收集器
type PrometheusMetricsCollector struct {
	logger        *zap.Logger
	registry      *prometheus.Registry
	systemMetrics *domain.SystemMetrics
	mu            sync.RWMutex

	// Prometheus 指标定义（参考 node_exporter 的指标命名）
	cpuSecondsTotal    *prometheus.CounterVec
	memoryMemTotal     prometheus.Gauge
	memoryMemAvailable prometheus.Gauge
	memoryMemFree      prometheus.Gauge
	filesystemSize     *prometheus.GaugeVec
	filesystemAvail    *prometheus.GaugeVec
	networkReceive     *prometheus.CounterVec
	networkTransmit    *prometheus.CounterVec
	load1              prometheus.Gauge
	load5              prometheus.Gauge
	load15             prometheus.Gauge
}

// NewPrometheusMetricsCollector 创建 Prometheus 指标收集器
func NewPrometheusMetricsCollector(logger *zap.Logger) (*PrometheusMetricsCollector, error) {
	registry := prometheus.NewRegistry()

	pc := &PrometheusMetricsCollector{
		logger:        logger,
		registry:      registry,
		systemMetrics: &domain.SystemMetrics{},

		// 初始化 Prometheus 指标（参考 node_exporter 的指标定义）
		cpuSecondsTotal: promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Name: "node_cpu_seconds_total",
				Help: "Seconds the CPUs spent in each mode.",
			},
			[]string{"cpu", "mode"},
		),
		memoryMemTotal: promauto.With(registry).NewGauge(
			prometheus.GaugeOpts{
				Name: "node_memory_MemTotal_bytes",
				Help: "Total memory in bytes.",
			},
		),
		memoryMemAvailable: promauto.With(registry).NewGauge(
			prometheus.GaugeOpts{
				Name: "node_memory_MemAvailable_bytes",
				Help: "Available memory in bytes.",
			},
		),
		memoryMemFree: promauto.With(registry).NewGauge(
			prometheus.GaugeOpts{
				Name: "node_memory_MemFree_bytes",
				Help: "Free memory in bytes.",
			},
		),
		filesystemSize: promauto.With(registry).NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "node_filesystem_size_bytes",
				Help: "Filesystem size in bytes.",
			},
			[]string{"device", "fstype", "mountpoint"},
		),
		filesystemAvail: promauto.With(registry).NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "node_filesystem_avail_bytes",
				Help: "Filesystem available space in bytes.",
			},
			[]string{"device", "fstype", "mountpoint"},
		),
		networkReceive: promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Name: "node_network_receive_bytes_total",
				Help: "Network device statistic receive_bytes.",
			},
			[]string{"device"},
		),
		networkTransmit: promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Name: "node_network_transmit_bytes_total",
				Help: "Network device statistic transmit_bytes.",
			},
			[]string{"device"},
		),
		load1: promauto.With(registry).NewGauge(
			prometheus.GaugeOpts{
				Name: "node_load1",
				Help: "1m load average.",
			},
		),
		load5: promauto.With(registry).NewGauge(
			prometheus.GaugeOpts{
				Name: "node_load5",
				Help: "5m load average.",
			},
		),
		load15: promauto.With(registry).NewGauge(
			prometheus.GaugeOpts{
				Name: "node_load15",
				Help: "15m load average.",
			},
		),
	}

	return pc, nil
}

// UpdateMetrics 更新指标（从 gopsutil 或其他数据源）
func (pc *PrometheusMetricsCollector) UpdateMetrics(ctx context.Context) error {
	// 使用 gopsutil 收集数据并更新 Prometheus 指标
	// 这样可以复用现有的数据收集逻辑，同时提供 Prometheus 标准格式

	// 示例：更新 CPU 指标
	// cpuPercent, err := cpu.Percent(time.Second, false)
	// if err == nil {
	//     // 更新 Prometheus 指标
	//     pc.cpuSecondsTotal.WithLabelValues("0", "user").Add(cpuPercent[0] / 100.0)
	// }

	// 示例：更新内存指标
	// memInfo, err := mem.VirtualMemory()
	// if err == nil {
	//     pc.memoryMemTotal.Set(float64(memInfo.Total))
	//     pc.memoryMemAvailable.Set(float64(memInfo.Available))
	//     pc.memoryMemFree.Set(float64(memInfo.Free))
	// }

	// 收集 Prometheus 指标并转换为 domain.SystemMetrics
	metricFamilies, err := pc.registry.Gather()
	if err != nil {
		return fmt.Errorf("failed to gather metrics: %w", err)
	}

	metrics := pc.convertPrometheusMetrics(metricFamilies)

	pc.mu.Lock()
	pc.systemMetrics = metrics
	pc.mu.Unlock()

	return nil
}

// convertPrometheusMetrics 将 Prometheus 指标转换为 domain.SystemMetrics
func (pc *PrometheusMetricsCollector) convertPrometheusMetrics(
	families []*prometheus.MetricFamily,
) *domain.SystemMetrics {
	metrics := &domain.SystemMetrics{
		LastUpdated: time.Now(),
	}

	for _, family := range families {
		switch family.GetName() {
		case "node_memory_MemTotal_bytes":
			if len(family.Metric) > 0 {
				metrics.MemoryTotal = int64(family.Metric[0].GetGauge().GetValue())
			}
		case "node_memory_MemAvailable_bytes":
			if len(family.Metric) > 0 {
				metrics.MemoryFree = int64(family.Metric[0].GetGauge().GetValue())
			}
		case "node_load1":
			if len(family.Metric) > 0 {
				metrics.LoadAvg1 = family.Metric[0].GetGauge().GetValue()
			}
		case "node_load5":
			if len(family.Metric) > 0 {
				metrics.LoadAvg5 = family.Metric[0].GetGauge().GetValue()
			}
		case "node_load15":
			if len(family.Metric) > 0 {
				metrics.LoadAvg15 = family.Metric[0].GetGauge().GetValue()
			}
		}
	}

	// 计算派生指标
	if metrics.MemoryTotal > 0 {
		metrics.MemoryUsage = float64(metrics.MemoryTotal-metrics.MemoryFree) /
			float64(metrics.MemoryTotal) * 100
	}

	return metrics
}

// GetSystemMetrics 获取系统指标
func (pc *PrometheusMetricsCollector) GetSystemMetrics() *domain.SystemMetrics {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.systemMetrics
}

// GetPrometheusRegistry 获取 Prometheus Registry
func (pc *PrometheusMetricsCollector) GetPrometheusRegistry() *prometheus.Registry {
	return pc.registry
}
*/

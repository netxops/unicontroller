package metrics

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/ops/metrics/protocols"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
)

// ApplicationMetricsCollector 应用指标收集器
// 支持从 Prometheus、StatsD、OpenTelemetry 等协议接收指标
// 支持主动拉取和被动接收两种模式
type ApplicationMetricsCollector struct {
	logger     *zap.Logger
	registry   *prometheus.Registry
	httpServer *http.Server
	metrics    map[string]*domain.ApplicationMetrics
	mu         sync.RWMutex

	// 指标接收端点
	prometheusEndpoint string
	statsdEnabled      bool
	otelEnabled        bool

	// 主动拉取相关
	pullEnabled    bool
	targetManager  *ApplicationTargetManager
	scraperFactory *protocols.ScraperFactory
	pullCtx        context.Context
	pullCancel     context.CancelFunc
	pullWg         sync.WaitGroup
}

// ApplicationMetrics 应用指标
type ApplicationMetrics struct {
	ServiceName string
	Metrics     map[string]float64
	Labels      map[string]string
	Timestamp   time.Time
}

// NewApplicationMetricsCollector 创建应用指标收集器
func NewApplicationMetricsCollector(
	logger *zap.Logger,
	prometheusEndpoint string,
) (*ApplicationMetricsCollector, error) {
	registry := prometheus.NewRegistry()

	ac := &ApplicationMetricsCollector{
		logger:             logger,
		registry:           registry,
		metrics:            make(map[string]*domain.ApplicationMetrics),
		prometheusEndpoint: prometheusEndpoint,
		scraperFactory:     protocols.NewScraperFactory(logger),
	}

	// 如果指定了 Prometheus 端点，启动 HTTP 服务器
	if prometheusEndpoint != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

		ac.httpServer = &http.Server{
			Addr:    prometheusEndpoint,
			Handler: mux,
		}

		go func() {
			if err := ac.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("Failed to start Prometheus metrics server",
					zap.String("endpoint", prometheusEndpoint),
					zap.Error(err))
			}
		}()

		logger.Info("Application metrics collector started",
			zap.String("prometheus_endpoint", prometheusEndpoint))
	}

	return ac, nil
}

// EnablePullMode 启用主动拉取模式
func (ac *ApplicationMetricsCollector) EnablePullMode(targetManager *ApplicationTargetManager) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	ac.pullEnabled = true
	ac.targetManager = targetManager
	ac.pullCtx, ac.pullCancel = context.WithCancel(context.Background())

	ac.logger.Info("Application metrics pull mode enabled")

	// 启动拉取协程
	ac.startPullWorkers()
}

// startPullWorkers 启动拉取工作协程
func (ac *ApplicationMetricsCollector) startPullWorkers() {
	targets := ac.targetManager.GetTargets()

	for key, target := range targets {
		if !target.Enabled {
			continue
		}

		ac.pullWg.Add(1)
		go ac.pullWorker(key, target)
	}

	ac.logger.Info("Started application metrics pull workers",
		zap.Int("target_count", len(targets)))
}

// pullWorker 拉取工作协程
func (ac *ApplicationMetricsCollector) pullWorker(key string, target *PullTarget) {
	defer ac.pullWg.Done()

	interval := time.Duration(target.Interval) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// 立即执行一次
	ac.pullTarget(target)

	for {
		select {
		case <-ac.pullCtx.Done():
			ac.logger.Info("Pull worker stopped",
				zap.String("key", key),
				zap.String("service", target.ServiceName))
			return
		case <-ticker.C:
			ac.pullTarget(target)
		}
	}
}

// pullTarget 拉取单个目标的指标
func (ac *ApplicationMetricsCollector) pullTarget(target *PullTarget) {
	scraper, exists := ac.scraperFactory.GetScraper(target.Protocol)
	if !exists {
		target.LastError = fmt.Errorf("unsupported protocol: %s", target.Protocol)
		ac.logger.Warn("Unsupported protocol",
			zap.String("protocol", target.Protocol),
			zap.String("service", target.ServiceName),
			zap.String("endpoint", target.Endpoint))
		return
	}

	ctx, cancel := context.WithTimeout(ac.pullCtx, 10*time.Second)
	defer cancel()

	metricFamilies, err := scraper.Scrape(ctx, target.Endpoint)
	if err != nil {
		target.LastError = err
		ac.logger.Warn("Failed to scrape metrics",
			zap.String("service", target.ServiceName),
			zap.String("endpoint", target.Endpoint),
			zap.String("protocol", target.Protocol),
			zap.Error(err))
		return
	}

	// 更新目标状态
	target.LastScrape = time.Now()
	target.LastError = nil

	// 转换为应用指标并存储
	ac.processScrapedMetrics(target.ServiceName, metricFamilies, target.Labels)

	ac.logger.Debug("Scraped metrics successfully",
		zap.String("service", target.ServiceName),
		zap.String("endpoint", target.Endpoint),
		zap.String("protocol", target.Protocol),
		zap.Int("metric_count", len(metricFamilies)))
}

// processScrapedMetrics 处理采集到的指标
func (ac *ApplicationMetricsCollector) processScrapedMetrics(
	serviceName string,
	metricFamilies []*dto.MetricFamily,
	labels map[string]string,
) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// 获取或创建服务指标
	appMetrics, exists := ac.metrics[serviceName]
	if !exists {
		appMetrics = &domain.ApplicationMetrics{
			ServiceName: serviceName,
			Metrics:     make(map[string]float64),
			Labels:      make(map[string]string),
			Timestamp:   time.Now(),
		}
		ac.metrics[serviceName] = appMetrics
	}

	// 合并标签
	for k, v := range labels {
		appMetrics.Labels[k] = v
	}

	// 转换指标
	for _, family := range metricFamilies {
		if family.Name == nil {
			continue
		}

		metricName := *family.Name

		// 处理每个指标值
		for _, metric := range family.Metric {
			var value float64

			switch {
			case metric.Gauge != nil && metric.Gauge.Value != nil:
				value = *metric.Gauge.Value
			case metric.Counter != nil && metric.Counter.Value != nil:
				value = *metric.Counter.Value
			case metric.Summary != nil && metric.Summary.SampleCount != nil:
				value = float64(*metric.Summary.SampleCount)
			case metric.Histogram != nil && metric.Histogram.SampleCount != nil:
				value = float64(*metric.Histogram.SampleCount)
			default:
				continue
			}

			// 如果有标签，构建带标签的指标名
			if len(metric.Label) > 0 {
				// 简化处理：使用第一个标签值作为后缀
				for _, label := range metric.Label {
					if label.Name != nil && label.Value != nil {
						metricName = fmt.Sprintf("%s{%s=%s}", *family.Name, *label.Name, *label.Value)
						break
					}
				}
			}

			appMetrics.Metrics[metricName] = value
		}
	}

	appMetrics.Timestamp = time.Now()
}

// RegisterPrometheusMetric 注册 Prometheus 指标
// 返回注册的指标对象，供应用代码使用
func (ac *ApplicationMetricsCollector) RegisterPrometheusMetric(
	name string,
	metricType string,
	help string,
	labels []string,
) (prometheus.Collector, error) {
	var collector prometheus.Collector

	switch metricType {
	case "counter":
		counter := prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: name,
				Help: help,
			},
			labels,
		)
		if err := ac.registry.Register(counter); err != nil {
			return nil, fmt.Errorf("failed to register counter: %w", err)
		}
		collector = counter
	case "gauge":
		gauge := prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: name,
				Help: help,
			},
			labels,
		)
		if err := ac.registry.Register(gauge); err != nil {
			return nil, fmt.Errorf("failed to register gauge: %w", err)
		}
		collector = gauge
	case "histogram":
		histogram := prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: name,
				Help: help,
			},
			labels,
		)
		if err := ac.registry.Register(histogram); err != nil {
			return nil, fmt.Errorf("failed to register histogram: %w", err)
		}
		collector = histogram
	case "summary":
		summary := prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Name: name,
				Help: help,
			},
			labels,
		)
		if err := ac.registry.Register(summary); err != nil {
			return nil, fmt.Errorf("failed to register summary: %w", err)
		}
		collector = summary
	default:
		return nil, fmt.Errorf("unsupported metric type: %s", metricType)
	}

	return collector, nil
}

// ReportMetric 上报业务指标
func (ac *ApplicationMetricsCollector) ReportMetric(
	serviceName string,
	metricName string,
	value float64,
	labels map[string]string,
) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// 获取或创建服务指标
	appMetrics, exists := ac.metrics[serviceName]
	if !exists {
		appMetrics = &domain.ApplicationMetrics{
			ServiceName: serviceName,
			Metrics:     make(map[string]float64),
			Labels:      make(map[string]string),
			Timestamp:   time.Now(),
		}
		ac.metrics[serviceName] = appMetrics
	}

	// 更新指标值
	appMetrics.Metrics[metricName] = value
	appMetrics.Timestamp = time.Now()

	// 合并标签
	for k, v := range labels {
		appMetrics.Labels[k] = v
	}

	return nil
}

// GetApplicationMetrics 获取应用指标
func (ac *ApplicationMetricsCollector) GetApplicationMetrics(serviceName string) (*domain.ApplicationMetrics, bool) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	metrics, exists := ac.metrics[serviceName]
	return metrics, exists
}

// GetAllApplicationMetrics 获取所有应用指标
func (ac *ApplicationMetricsCollector) GetAllApplicationMetrics() map[string]*domain.ApplicationMetrics {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	result := make(map[string]*domain.ApplicationMetrics, len(ac.metrics))
	for serviceName, metrics := range ac.metrics {
		result[serviceName] = metrics
	}
	return result
}

// GetPrometheusRegistry 获取 Prometheus Registry
func (ac *ApplicationMetricsCollector) GetPrometheusRegistry() *prometheus.Registry {
	return ac.registry
}

// Shutdown 关闭收集器
func (ac *ApplicationMetricsCollector) Shutdown(ctx context.Context) error {
	// 停止拉取工作协程
	if ac.pullCancel != nil {
		ac.pullCancel()
		// 等待所有拉取协程退出
		done := make(chan struct{})
		go func() {
			ac.pullWg.Wait()
			close(done)
		}()

		select {
		case <-done:
			ac.logger.Info("All pull workers stopped")
		case <-ctx.Done():
			ac.logger.Warn("Timeout waiting for pull workers to stop")
		}
	}

	if ac.httpServer != nil {
		return ac.httpServer.Shutdown(ctx)
	}
	return nil
}

// ReloadTargets 重新加载采集目标
func (ac *ApplicationMetricsCollector) ReloadTargets(ctx context.Context) error {
	if !ac.pullEnabled || ac.targetManager == nil {
		return nil
	}

	// 停止现有工作协程
	if ac.pullCancel != nil {
		ac.pullCancel()
		ac.pullWg.Wait()
	}

	// 重新加载目标
	if err := ac.targetManager.LoadTargets(ctx); err != nil {
		return fmt.Errorf("failed to reload targets: %w", err)
	}

	// 重新启动工作协程
	ac.pullCtx, ac.pullCancel = context.WithCancel(context.Background())
	ac.startPullWorkers()

	ac.logger.Info("Application targets reloaded")
	return nil
}

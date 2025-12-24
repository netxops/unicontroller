package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/internal/api"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/config"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/ops/metrics"
	"github.com/influxdata/telegraf/controller/pb"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// MetricsCollector 指标收集器接口（避免循环依赖）
type MetricsCollector interface {
	GetSystemMetrics() interface{}
	GetServiceMetrics(serviceID string) (interface{}, bool)
	GetAllServiceMetrics() map[string]interface{}
	GetHistoryCache() interface{}
	GetEnhancedCollector() interface{}
}

// StrategySyncerInterface 策略同步器接口（用于查询策略信息）
type StrategySyncerInterface interface {
	GetLastSyncTime() time.Time
	GetLastVersion() int64
	GetStrategyManager() *metrics.StrategyManager
}

// Server Agent V2 服务器
type Server struct {
	grpcServer       *grpc.Server
	httpServer       *http.Server
	grpcPort         int
	httpPort         int
	logger           *zap.Logger
	metricsCollector MetricsCollector
	// 策略相关（可选，用于查询策略配置信息）
	strategySyncer StrategySyncerInterface
	cfg            *config.Config
	// 策略管理器（用于过滤指标）
	strategyManager interface {
		ShouldCollectMetric(metricName string, currentTime time.Time) bool
		RecordMetricCollectTime(metricName string, collectTime time.Time)
		GetMetricInterval(metricName string) int
		GetMinInterval() int
	}
}

// NewServer 创建新服务器
func NewServer(
	serverConfig ServerConfig,
	logger *zap.Logger,
	packageService *api.PackageService,
	commandService *api.CommandService,
	healthService *api.HealthService,
	metricsService *api.MetricsService,
	fileService *api.FileGRPCService,
	metricsCollector MetricsCollector,
) (*Server, error) {
	return NewServerWithStrategy(serverConfig, logger, packageService, commandService, healthService, metricsService, fileService, metricsCollector, nil, nil)
}

// NewServerWithStrategy 创建新服务器（带策略支持）
func NewServerWithStrategy(
	serverConfig ServerConfig,
	logger *zap.Logger,
	packageService *api.PackageService,
	commandService *api.CommandService,
	healthService *api.HealthService,
	metricsService *api.MetricsService,
	fileService *api.FileGRPCService,
	metricsCollector MetricsCollector,
	strategySyncer StrategySyncerInterface,
	cfg *config.Config,
) (*Server, error) {
	var strategyManager interface {
		ShouldCollectMetric(metricName string, currentTime time.Time) bool
		RecordMetricCollectTime(metricName string, collectTime time.Time)
		GetMetricInterval(metricName string) int
		GetMinInterval() int
	}
	if strategySyncer != nil {
		strategyManager = strategySyncer.GetStrategyManager()
	}

	s := &Server{
		grpcServer:       grpc.NewServer(),
		grpcPort:         serverConfig.GRPCPort,
		httpPort:         serverConfig.HTTPPort,
		logger:           logger,
		metricsCollector: metricsCollector,
		strategySyncer:   strategySyncer,
		cfg:              cfg,
		strategyManager:  strategyManager,
	}

	// 注册 gRPC 服务
	pb.RegisterPackageServer(s.grpcServer, packageService)
	pb.RegisterCommandServer(s.grpcServer, commandService)
	pb.RegisterHealthServer(s.grpcServer, healthService)
	pb.RegisterMetricsServer(s.grpcServer, metricsService)
	if fileService != nil {
		pb.RegisterFileServer(s.grpcServer, fileService)
		s.logger.Info("File gRPC service registered")
	} else {
		s.logger.Warn("File gRPC service is nil, not registering")
	}

	// 启用 gRPC 反射 API（用于 grpcurl 等工具）
	reflection.Register(s.grpcServer)

	// 创建 HTTP 服务器
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.healthHandler)
	mux.HandleFunc("/ready", s.readyHandler)
	mux.HandleFunc("/metrics", s.metricsHandler)
	mux.HandleFunc("/api/v1/metrics/list", s.listMetricsHandler)             // 列出所有采集的指标
	mux.HandleFunc("/api/v1/metrics/config", s.metricsConfigHandler)         // 查询指标采集配置
	mux.HandleFunc("/api/v1/metrics/strategy/rules", s.strategyRulesHandler) // 查询策略规则和匹配的指标

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", serverConfig.HTTPPort),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return s, nil
}

// Start 启动服务器
func (s *Server) Start(ctx context.Context) error {
	// 启动 gRPC 服务器
	grpcLis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.grpcPort))
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port: %w", err)
	}

	go func() {
		s.logger.Info("Starting gRPC server",
			zap.Int("port", s.grpcPort),
			zap.String("services", "Package, Command, Health, Metrics, File"))
		if err := s.grpcServer.Serve(grpcLis); err != nil && err != grpc.ErrServerStopped {
			s.logger.Error("gRPC server error", zap.Error(err))
		}
	}()

	// 启动 HTTP 服务器
	go func() {
		s.logger.Info("Starting HTTP server", zap.Int("port", s.httpPort))
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	return nil
}

// Shutdown 优雅关闭服务器
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down servers")

	// 关闭 gRPC 服务器
	grpcDone := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(grpcDone)
	}()

	// 关闭 HTTP 服务器
	httpCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.httpServer.Shutdown(httpCtx); err != nil {
		s.logger.Error("Error shutting down HTTP server", zap.Error(err))
	}

	// 等待 gRPC 服务器关闭
	select {
	case <-grpcDone:
	case <-ctx.Done():
		s.grpcServer.Stop()
	}

	return nil
}

// healthHandler 健康检查处理器
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
}

// readyHandler 就绪检查处理器
func (s *Server) readyHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ready"}`))
}

// metricsHandler 指标处理器（Prometheus 格式）
// 只使用增强型指标收集器，不提供降级方案
func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	if s.metricsCollector == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("# Metrics collector not available\n"))
		s.logger.Error("Metrics collector is nil")
		return
	}

	// 只使用增强型收集器的 Prometheus registry
	enhancedCollectorInterface := s.metricsCollector.GetEnhancedCollector()
	if enhancedCollectorInterface == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("# Enhanced metrics collector not available. Please enable enhanced_enabled in metrics configuration.\n"))
		s.logger.Error("Enhanced collector not available",
			zap.String("metrics_collector_type", fmt.Sprintf("%T", s.metricsCollector)))
		return
	}

	s.logger.Debug("Enhanced collector retrieved",
		zap.String("type", fmt.Sprintf("%T", enhancedCollectorInterface)),
		zap.Bool("is_nil", enhancedCollectorInterface == nil))

	// 定义接口（EnhancedMetricsCollector 实现了这些方法）
	type prometheusRegistryGetter interface {
		GetPrometheusRegistry() *prometheus.Registry
	}
	type metricsUpdater interface {
		UpdateMetrics(ctx context.Context) error
	}

	// 获取 Prometheus registry
	var registry *prometheus.Registry
	var updater metricsUpdater

	// 类型断言获取 registry
	registryGetter, ok := enhancedCollectorInterface.(prometheusRegistryGetter)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("# Enhanced collector does not implement GetPrometheusRegistry (type: %T)\n", enhancedCollectorInterface)))
		s.logger.Error("Enhanced collector does not implement GetPrometheusRegistry",
			zap.String("type", fmt.Sprintf("%T", enhancedCollectorInterface)),
			zap.Bool("is_nil", enhancedCollectorInterface == nil))
		return
	}

	// 安全地获取 registry
	if registryGetter == nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("# Enhanced collector registry getter is nil\n"))
		s.logger.Error("Enhanced collector registry getter is nil")
		return
	}

	registry = registryGetter.GetPrometheusRegistry()
	if registry == nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("# Enhanced collector registry is nil\n"))
		s.logger.Error("Enhanced collector registry is nil",
			zap.String("collector_type", fmt.Sprintf("%T", enhancedCollectorInterface)))
		return
	}

	// 获取 updater
	if u, ok := enhancedCollectorInterface.(metricsUpdater); ok {
		updater = u
	}

	// 更新指标（在导出前确保数据是最新的）
	if updater != nil {
		if err := updater.UpdateMetrics(r.Context()); err != nil {
			s.logger.Warn("Failed to update enhanced metrics, but continuing",
				zap.Error(err))
			// 继续导出，即使更新失败
		} else {
			s.logger.Debug("Successfully updated enhanced metrics")
		}
	}

	// 使用 Prometheus 标准库导出指标
	s.logger.Debug("Exporting metrics using enhanced collector")

	// 如果启用了策略且策略管理器可用，根据策略规则过滤指标
	if s.cfg != nil && s.cfg.Metrics.StrategyEnabled && s.strategyManager != nil {
		// 创建自定义 Handler，根据策略规则过滤指标
		s.logger.Info("Using strategy-based metrics filter",
			zap.Bool("strategy_enabled", s.cfg.Metrics.StrategyEnabled),
			zap.Bool("strategy_manager_exists", s.strategyManager != nil))
		handler := s.createFilteredMetricsHandler(registry)
		handler.ServeHTTP(w, r)
	} else {
		// 未启用策略，直接导出所有指标
		s.logger.Warn("Strategy not enabled or strategy manager not available, exporting all metrics",
			zap.Bool("cfg_exists", s.cfg != nil),
			zap.Bool("strategy_enabled", s.cfg != nil && s.cfg.Metrics.StrategyEnabled),
			zap.Bool("strategy_manager_exists", s.strategyManager != nil))
		handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		})
		handler.ServeHTTP(w, r)
	}
}

// createFilteredMetricsHandler 创建根据策略规则过滤指标的 Handler
func (s *Server) createFilteredMetricsHandler(registry *prometheus.Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 收集所有指标
		s.logger.Debug("Gathering metrics from registry")
		metricFamilies, err := registry.Gather()
		if err != nil {
			s.logger.Error("Failed to gather metrics", zap.Error(err))
			http.Error(w, "Failed to gather metrics", http.StatusInternalServerError)
			return
		}

		s.logger.Info("Gathered metrics from registry",
			zap.Int("metric_families_count", len(metricFamilies)))

		currentTime := time.Now()
		filteredFamilies := make([]*dto.MetricFamily, 0)
		totalMetrics := len(metricFamilies)
		collectedCount := 0
		skippedCount := 0

		// 过滤指标（只根据规则匹配和 enabled 状态，不进行时间间隔过滤）
		for _, family := range metricFamilies {
			if family == nil || family.Name == nil {
				continue
			}

			metricName := *family.Name

			// 判断是否应该采集此指标（只检查规则匹配和 enabled 状态）
			shouldCollect := s.strategyManager.ShouldCollectMetric(metricName, currentTime)

			if shouldCollect {
				filteredFamilies = append(filteredFamilies, family)
				collectedCount++
			} else {
				skippedCount++
			}
		}

		s.logger.Info("Metrics filtered by strategy",
			zap.Int("total_metrics", totalMetrics),
			zap.Int("collected", collectedCount),
			zap.Int("skipped", skippedCount))

		// 使用 Prometheus 编码器导出过滤后的指标
		enc := expfmt.NewEncoder(w, expfmt.FmtText)
		for _, family := range filteredFamilies {
			if err := enc.Encode(family); err != nil {
				s.logger.Warn("Failed to encode metric family",
					zap.String("family", *family.Name),
					zap.Error(err))
			}
		}
	})
}

// formatSystemMetrics 格式化系统指标为 Prometheus 格式
func (s *Server) formatSystemMetrics(metrics *domain.SystemMetrics) []byte {
	var output []byte

	// CPU 使用率
	output = append(output, []byte("# HELP system_cpu_usage CPU usage percentage\n")...)
	output = append(output, []byte("# TYPE system_cpu_usage gauge\n")...)
	output = append(output, []byte(fmt.Sprintf("system_cpu_usage %.2f\n", metrics.CPUUsage))...)

	// 内存使用率
	output = append(output, []byte("# HELP system_memory_usage Memory usage percentage\n")...)
	output = append(output, []byte("# TYPE system_memory_usage gauge\n")...)
	output = append(output, []byte(fmt.Sprintf("system_memory_usage %.2f\n", metrics.MemoryUsage))...)

	// 内存总量和可用量
	output = append(output, []byte("# HELP system_memory_total_bytes Total memory in bytes\n")...)
	output = append(output, []byte("# TYPE system_memory_total_bytes gauge\n")...)
	output = append(output, []byte(fmt.Sprintf("system_memory_total_bytes %d\n", metrics.MemoryTotal))...)

	output = append(output, []byte("# HELP system_memory_free_bytes Free memory in bytes\n")...)
	output = append(output, []byte("# TYPE system_memory_free_bytes gauge\n")...)
	output = append(output, []byte(fmt.Sprintf("system_memory_free_bytes %d\n", metrics.MemoryFree))...)

	// 磁盘使用率
	output = append(output, []byte("# HELP system_disk_usage Disk usage percentage\n")...)
	output = append(output, []byte("# TYPE system_disk_usage gauge\n")...)
	output = append(output, []byte(fmt.Sprintf("system_disk_usage %.2f\n", metrics.DiskUsage))...)

	// 磁盘总量和可用量
	output = append(output, []byte("# HELP system_disk_total_bytes Total disk space in bytes\n")...)
	output = append(output, []byte("# TYPE system_disk_total_bytes gauge\n")...)
	output = append(output, []byte(fmt.Sprintf("system_disk_total_bytes %d\n", metrics.DiskTotal))...)

	output = append(output, []byte("# HELP system_disk_free_bytes Free disk space in bytes\n")...)
	output = append(output, []byte("# TYPE system_disk_free_bytes gauge\n")...)
	output = append(output, []byte(fmt.Sprintf("system_disk_free_bytes %d\n", metrics.DiskFree))...)

	// 网络流量
	output = append(output, []byte("# HELP system_network_in_bytes Network input bytes\n")...)
	output = append(output, []byte("# TYPE system_network_in_bytes counter\n")...)
	output = append(output, []byte(fmt.Sprintf("system_network_in_bytes %d\n", metrics.NetworkIn))...)

	output = append(output, []byte("# HELP system_network_out_bytes Network output bytes\n")...)
	output = append(output, []byte("# TYPE system_network_out_bytes counter\n")...)
	output = append(output, []byte(fmt.Sprintf("system_network_out_bytes %d\n", metrics.NetworkOut))...)

	// 负载平均值
	output = append(output, []byte("# HELP system_load_avg_1m Load average over 1 minute\n")...)
	output = append(output, []byte("# TYPE system_load_avg_1m gauge\n")...)
	output = append(output, []byte(fmt.Sprintf("system_load_avg_1m %.2f\n", metrics.LoadAvg1))...)

	output = append(output, []byte("# HELP system_load_avg_5m Load average over 5 minutes\n")...)
	output = append(output, []byte("# TYPE system_load_avg_5m gauge\n")...)
	output = append(output, []byte(fmt.Sprintf("system_load_avg_5m %.2f\n", metrics.LoadAvg5))...)

	output = append(output, []byte("# HELP system_load_avg_15m Load average over 15 minutes\n")...)
	output = append(output, []byte("# TYPE system_load_avg_15m gauge\n")...)
	output = append(output, []byte(fmt.Sprintf("system_load_avg_15m %.2f\n", metrics.LoadAvg15))...)

	return output
}

// listMetricsHandler 列出所有采集的指标（JSON 格式，便于查看）
func (s *Server) listMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.metricsCollector == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"error":"Metrics collector not available"}`))
		return
	}

	response := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"metrics":   map[string]interface{}{},
	}

	metricsMap := response["metrics"].(map[string]interface{})

	// 系统指标
	systemMetrics := map[string]interface{}{
		"description": "系统级指标，包括 CPU、内存、磁盘、网络等",
		"enabled":     true,
		"metrics":     []map[string]interface{}{},
	}

	if sysMetrics := s.metricsCollector.GetSystemMetrics(); sysMetrics != nil {
		if metrics, ok := sysMetrics.(*domain.SystemMetrics); ok {
			systemMetricsList := []map[string]interface{}{
				{
					"name":        "cpu_usage",
					"type":        "gauge",
					"description": "CPU 使用率（百分比）",
					"value":       metrics.CPUUsage,
					"unit":        "percent",
				},
				{
					"name":        "cpu_cores",
					"type":        "gauge",
					"description": "CPU 核心数",
					"value":       metrics.CPUCores,
					"unit":        "cores",
				},
				{
					"name":        "memory_usage",
					"type":        "gauge",
					"description": "内存使用率（百分比）",
					"value":       metrics.MemoryUsage,
					"unit":        "percent",
				},
				{
					"name":        "memory_total",
					"type":        "gauge",
					"description": "总内存（字节）",
					"value":       metrics.MemoryTotal,
					"unit":        "bytes",
				},
				{
					"name":        "memory_free",
					"type":        "gauge",
					"description": "空闲内存（字节）",
					"value":       metrics.MemoryFree,
					"unit":        "bytes",
				},
				{
					"name":        "disk_usage",
					"type":        "gauge",
					"description": "磁盘使用率（百分比）",
					"value":       metrics.DiskUsage,
					"unit":        "percent",
				},
				{
					"name":        "disk_total",
					"type":        "gauge",
					"description": "总磁盘空间（字节）",
					"value":       metrics.DiskTotal,
					"unit":        "bytes",
				},
				{
					"name":        "disk_free",
					"type":        "gauge",
					"description": "空闲磁盘空间（字节）",
					"value":       metrics.DiskFree,
					"unit":        "bytes",
				},
				{
					"name":        "load_avg_1",
					"type":        "gauge",
					"description": "1分钟负载平均值",
					"value":       metrics.LoadAvg1,
					"unit":        "load",
				},
				{
					"name":        "load_avg_5",
					"type":        "gauge",
					"description": "5分钟负载平均值",
					"value":       metrics.LoadAvg5,
					"unit":        "load",
				},
				{
					"name":        "load_avg_15",
					"type":        "gauge",
					"description": "15分钟负载平均值",
					"value":       metrics.LoadAvg15,
					"unit":        "load",
				},
			}

			// 网络接口信息
			if len(metrics.NetworkInterfaces) > 0 {
				networkInterfaces := []map[string]interface{}{}
				for _, iface := range metrics.NetworkInterfaces {
					networkInterfaces = append(networkInterfaces, map[string]interface{}{
						"name":     iface.Name,
						"rx_bytes": iface.RxBytes,
						"tx_bytes": iface.TxBytes,
					})
				}
				systemMetricsList = append(systemMetricsList, map[string]interface{}{
					"name":        "network_interfaces",
					"type":        "gauge",
					"description": "网络接口列表",
					"value":       networkInterfaces,
					"unit":        "bytes",
				})
			}

			systemMetrics["metrics"] = systemMetricsList
			systemMetrics["last_updated"] = metrics.LastUpdated.Format(time.RFC3339)
		}
	}
	metricsMap["system"] = systemMetrics

	// 服务指标
	serviceMetrics := map[string]interface{}{
		"description": "服务级指标，包括运行中服务的 CPU、内存使用等",
		"enabled":     true,
		"services":    map[string]interface{}{},
	}

	if allServiceMetrics := s.metricsCollector.GetAllServiceMetrics(); allServiceMetrics != nil {
		servicesMap := serviceMetrics["services"].(map[string]interface{})
		for serviceID, svcMetrics := range allServiceMetrics {
			// 处理类型转换
			metrics, ok := svcMetrics.(*domain.ServiceMetrics)
			if !ok {
				continue
			}

			if metrics != nil {
				servicesMap[serviceID] = map[string]interface{}{
					"metrics": []map[string]interface{}{
						{
							"name":        "cpu_usage",
							"type":        "gauge",
							"description": "CPU 使用率（百分比）",
							"value":       metrics.CPUUsage,
							"unit":        "percent",
						},
						{
							"name":        "memory_usage",
							"type":        "gauge",
							"description": "内存使用率（百分比）",
							"value":       metrics.MemoryUsage,
							"unit":        "percent",
						},
						{
							"name":        "memory_bytes",
							"type":        "gauge",
							"description": "内存使用量（字节）",
							"value":       metrics.MemoryBytes,
							"unit":        "bytes",
						},
						{
							"name":        "request_count",
							"type":        "counter",
							"description": "请求总数",
							"value":       metrics.RequestCount,
							"unit":        "count",
						},
						{
							"name":        "error_count",
							"type":        "counter",
							"description": "错误总数",
							"value":       metrics.ErrorCount,
							"unit":        "count",
						},
					},
					"last_updated": metrics.LastUpdated.Format(time.RFC3339),
				}
			}
		}
	}
	metricsMap["service"] = serviceMetrics

	// 增强型指标（如果启用）
	if enhancedCollector := s.metricsCollector.GetEnhancedCollector(); enhancedCollector != nil {
		enhancedMetrics := map[string]interface{}{
			"description": "增强型指标（基于 Prometheus Node Exporter 标准）",
			"enabled":     true,
			"metrics": []map[string]interface{}{
				{"name": "node_cpu_seconds_total", "type": "counter", "description": "CPU 各模式累计时间（秒）", "labels": []string{"cpu", "mode"}},
				{"name": "node_memory_MemTotal_bytes", "type": "gauge", "description": "总内存（字节）"},
				{"name": "node_memory_MemAvailable_bytes", "type": "gauge", "description": "可用内存（字节）"},
				{"name": "node_memory_MemFree_bytes", "type": "gauge", "description": "空闲内存（字节）"},
				{"name": "node_memory_MemUsed_bytes", "type": "gauge", "description": "已用内存（字节）"},
				{"name": "node_filesystem_size_bytes", "type": "gauge", "description": "文件系统大小（字节）", "labels": []string{"device", "fstype", "mountpoint"}},
				{"name": "node_filesystem_avail_bytes", "type": "gauge", "description": "文件系统可用空间（字节）", "labels": []string{"device", "fstype", "mountpoint"}},
				{"name": "node_filesystem_used_bytes", "type": "gauge", "description": "文件系统已用空间（字节）", "labels": []string{"device", "fstype", "mountpoint"}},
				{"name": "node_network_receive_bytes_total", "type": "counter", "description": "网络接收字节总数", "labels": []string{"device"}},
				{"name": "node_network_transmit_bytes_total", "type": "counter", "description": "网络发送字节总数", "labels": []string{"device"}},
				{"name": "node_load1", "type": "gauge", "description": "1分钟负载平均值"},
				{"name": "node_load5", "type": "gauge", "description": "5分钟负载平均值"},
				{"name": "node_load15", "type": "gauge", "description": "15分钟负载平均值"},
				{"name": "node_disk_read_bytes_total", "type": "counter", "description": "磁盘读取字节总数", "labels": []string{"device"}},
				{"name": "node_disk_written_bytes_total", "type": "counter", "description": "磁盘写入字节总数", "labels": []string{"device"}},
			},
		}
		metricsMap["enhanced"] = enhancedMetrics
	}

	// 历史缓存（如果启用）
	if historyCache := s.metricsCollector.GetHistoryCache(); historyCache != nil {
		metricsMap["history"] = map[string]interface{}{
			"description": "指标历史数据缓存",
			"enabled":     true,
			"note":        "使用 /api/v1/metrics/history 端点查询历史数据",
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// metricsConfigHandler 查询指标采集配置
func (s *Server) metricsConfigHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"config":    map[string]interface{}{},
	}

	configMap := response["config"].(map[string]interface{})

	if s.metricsCollector == nil {
		configMap["error"] = "Metrics collector not available"
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	// 获取增强型收集器配置
	enhancedCollectorInterface := s.metricsCollector.GetEnhancedCollector()
	if enhancedCollectorInterface != nil {
		// 类型断言为 *metrics.EnhancedMetricsCollector
		if ec, ok := enhancedCollectorInterface.(*metrics.EnhancedMetricsCollector); ok {
			enhancedConfig := map[string]interface{}{
				"enabled": true,
			}

			// 获取配置
			config := ec.GetConfig()
			enhancedConfig["only_core"] = config.OnlyCore
			if len(config.EnabledCollectors) > 0 {
				enhancedConfig["enabled_collectors"] = config.EnabledCollectors
			}
			if len(config.ExcludeCollectors) > 0 {
				enhancedConfig["exclude_collectors"] = config.ExcludeCollectors
			}

			// 获取实际启用的 collectors
			collectors := ec.GetEnabledCollectors()
			if len(collectors) > 0 {
				enhancedConfig["active_collectors"] = collectors
				enhancedConfig["active_collectors_count"] = len(collectors)
			}

			configMap["enhanced"] = enhancedConfig
		} else {
			// 如果类型断言失败，尝试通过 JSON 序列化获取信息
			enhancedConfig := map[string]interface{}{
				"enabled": true,
				"note":    fmt.Sprintf("Enhanced collector type: %T, cannot access config directly", enhancedCollectorInterface),
			}
			configMap["enhanced"] = enhancedConfig
		}
	} else {
		configMap["enhanced"] = map[string]interface{}{
			"enabled": false,
			"note":    "Enhanced collector is not enabled or not available",
		}
	}

	// 添加策略配置信息（如果可用）
	if s.strategySyncer != nil && s.cfg != nil {
		strategyConfig := map[string]interface{}{
			"enabled": s.cfg.Metrics.StrategyEnabled,
			"source":  s.cfg.Metrics.StrategySource,
		}

		if s.cfg.Metrics.StrategyEnabled {
			// 获取最后同步时间
			lastSyncTime := s.strategySyncer.GetLastSyncTime()
			if !lastSyncTime.IsZero() {
				strategyConfig["last_sync"] = lastSyncTime.Format(time.RFC3339)
				strategyConfig["sync_status"] = "synced"
			} else {
				strategyConfig["sync_status"] = "pending" // 尚未同步
				strategyConfig["note"] = "Strategy syncer is enabled but no sync has occurred yet. This may be normal on first startup."
			}

			// 获取策略版本号
			version := s.strategySyncer.GetLastVersion()
			if version > 0 {
				strategyConfig["version"] = fmt.Sprintf("%d", version)
			}

			// 获取策略管理器
			strategyManager := s.strategySyncer.GetStrategyManager()
			if strategyManager != nil {
				// 获取策略版本（从策略管理器）
				if strategyVersion := strategyManager.GetStrategyVersion(); strategyVersion > 0 {
					strategyConfig["strategy_version"] = fmt.Sprintf("%d", strategyVersion)
				}

				// 获取生效的策略规则
				effectiveRules := strategyManager.GetEffectiveRules()
				if len(effectiveRules) > 0 {
					rules := make([]map[string]interface{}, 0, len(effectiveRules))
					for _, rule := range effectiveRules {
						ruleMap := map[string]interface{}{
							"name":     rule.Name,
							"priority": string(rule.Priority),
							"enabled":  rule.Enabled,
						}
						if rule.Interval != nil {
							ruleMap["interval"] = *rule.Interval
						}
						rules = append(rules, ruleMap)
					}
					strategyConfig["effective_rules"] = rules
					strategyConfig["effective_rules_count"] = len(rules)
				}

				// 获取全局策略信息
				globalStrategy := strategyManager.GetGlobalStrategy()
				if globalStrategy != nil {
					strategyConfig["global_strategy"] = map[string]interface{}{
						"id":               globalStrategy.ID,
						"default_priority": string(globalStrategy.DefaultPriority),
						"default_interval": globalStrategy.DefaultInterval,
						"version":          fmt.Sprintf("%d", globalStrategy.Version),
						"rules_count":      len(globalStrategy.MetricRules),
					}
				}

				// 获取实例策略信息
				instanceStrategy := strategyManager.GetInstanceStrategy()
				if instanceStrategy != nil {
					strategyConfig["instance_strategy"] = map[string]interface{}{
						"id":             instanceStrategy.ID,
						"agent_code":     instanceStrategy.AgentCode,
						"inherit_global": instanceStrategy.InheritGlobal,
						"version":        fmt.Sprintf("%d", instanceStrategy.Version),
						"rules_count":    len(instanceStrategy.MetricRules),
					}
				}
			}
		}

		configMap["strategy"] = strategyConfig
	} else {
		configMap["strategy"] = map[string]interface{}{
			"enabled": false,
			"note":    "Strategy syncer not available",
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// strategyRulesHandler 查询策略规则和匹配的指标
func (s *Server) strategyRulesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"rules":     []map[string]interface{}{},
		"metrics":   []map[string]interface{}{},
	}

	if s.strategySyncer == nil || s.cfg == nil || !s.cfg.Metrics.StrategyEnabled {
		response["error"] = "Strategy is not enabled or not available"
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	// 获取策略管理器
	strategyManager := s.strategySyncer.GetStrategyManager()
	if strategyManager == nil {
		response["error"] = "Strategy manager is not available"
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	// 获取生效的策略规则
	effectiveRules := strategyManager.GetEffectiveRules()

	// 获取全局策略和实例策略信息（用于调试和显示）
	globalStrategy := strategyManager.GetGlobalStrategy()
	instanceStrategy := strategyManager.GetInstanceStrategy()

	// 添加策略状态信息（用于调试）
	strategyStatus := map[string]interface{}{
		"global_strategy_exists":   globalStrategy != nil,
		"instance_strategy_exists": instanceStrategy != nil,
		"effective_rules_count":    len(effectiveRules),
	}
	if globalStrategy != nil {
		strategyStatus["global_rules_count"] = len(globalStrategy.MetricRules)
		strategyStatus["default_priority"] = string(globalStrategy.DefaultPriority)
		strategyStatus["default_interval"] = globalStrategy.DefaultInterval
	}
	if instanceStrategy != nil {
		strategyStatus["instance_rules_count"] = len(instanceStrategy.MetricRules)
		strategyStatus["inherit_global"] = instanceStrategy.InheritGlobal
	}
	response["strategy_status"] = strategyStatus

	rulesList := make([]map[string]interface{}, 0, len(effectiveRules))
	metricsList := make([]map[string]interface{}, 0)

	// 指标前缀列表（用于根据规则推断指标）
	metricPrefixes := []string{
		"node_cpu_", "node_memory_", "node_load", "node_filesystem_", "node_diskstats_",
		"node_network_", "node_netstat_", "node_sockstat_", "node_textfile_", "node_time_",
		"node_uname_", "node_os_", "node_hwmon_", "node_edac_", "node_interrupts_",
		"node_ksmd_", "node_logind_", "node_mdstat_", "node_meminfo_numa_", "node_nfs_",
		"node_nfsd_", "node_ntp_", "node_perf_", "node_powersupply_", "node_pressure_",
		"node_rapl_", "node_runit_", "node_schedstat_", "node_selinux_", "node_softnet_",
		"node_stat_", "node_supervisord_", "node_systemd_", "node_tcpstat_", "node_timex_",
		"node_udp_queues_", "node_unified_", "node_vmstat_", "node_wifi_", "node_xfs_",
		"node_zfs_", "node_zoneinfo_",
	}

	// 处理每个规则
	for _, rule := range effectiveRules {
		ruleMap := map[string]interface{}{
			"name":     rule.Name,
			"priority": string(rule.Priority),
			"enabled":  rule.Enabled,
		}
		if rule.Interval != nil {
			ruleMap["interval"] = *rule.Interval
		}

		// 根据规则匹配指标
		matchedMetrics := []string{}
		pattern := rule.Name

		// 如果规则包含通配符，匹配所有符合的指标前缀
		if strings.Contains(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			for _, metricPrefix := range metricPrefixes {
				if strings.HasPrefix(metricPrefix, prefix) || strings.HasPrefix(prefix, metricPrefix) {
					matchedMetrics = append(matchedMetrics, metricPrefix+"*")
				}
			}
		} else {
			// 精确匹配：检查规则名称是否匹配某个指标前缀
			for _, metricPrefix := range metricPrefixes {
				if strings.HasPrefix(pattern, metricPrefix) {
					matchedMetrics = append(matchedMetrics, metricPrefix+"*")
					break
				}
			}
			// 如果没有匹配到前缀，可能是精确指标名
			if len(matchedMetrics) == 0 {
				matchedMetrics = append(matchedMetrics, pattern)
			}
		}

		ruleMap["matched_metrics"] = matchedMetrics
		ruleMap["matched_count"] = len(matchedMetrics)
		rulesList = append(rulesList, ruleMap)

		// 添加到指标列表（去重）
		for _, metric := range matchedMetrics {
			found := false
			for _, existing := range metricsList {
				if existing["name"] == metric {
					found = true
					break
				}
			}
			if !found {
				metricsList = append(metricsList, map[string]interface{}{
					"name":     metric,
					"enabled":  rule.Enabled,
					"priority": string(rule.Priority),
					"rule":     rule.Name,
				})
			}
		}
	}

	// 如果没有规则，使用默认策略
	if len(effectiveRules) == 0 {
		if globalStrategy != nil {
			response["default_priority"] = string(globalStrategy.DefaultPriority)
			response["default_interval"] = globalStrategy.DefaultInterval
			response["note"] = "No specific rules configured, using default strategy for all metrics"

			// 如果没有规则，说明所有指标都使用默认策略
			// 列出所有可能的指标前缀，使用默认策略
			for _, metricPrefix := range metricPrefixes {
				metricsList = append(metricsList, map[string]interface{}{
					"name":     metricPrefix + "*",
					"enabled":  true,
					"priority": string(globalStrategy.DefaultPriority),
					"interval": globalStrategy.DefaultInterval,
					"rule":     "default",
				})
			}
		} else {
			response["note"] = "No strategy rules found. Please configure metric collection rules in the Controller."
		}
	}

	response["rules"] = rulesList
	response["rules_count"] = len(rulesList)
	response["metrics"] = metricsList
	response["metrics_count"] = len(metricsList)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetGRPCServer 获取 gRPC 服务器实例
func (s *Server) GetGRPCServer() *grpc.Server {
	return s.grpcServer
}

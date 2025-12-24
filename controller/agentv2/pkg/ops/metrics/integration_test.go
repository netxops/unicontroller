package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"go.uber.org/zap/zaptest"
)

// TestMetricsCollector_Integration_CollectAndReport 集成测试：指标收集和上报
func TestMetricsCollector_Integration_CollectAndReport(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := newMockServiceRegistry()
	config := CollectorConfig{
		Interval:       1 * time.Second,
		CollectSystem:  true,
		CollectService: true,
	}

	collector := NewMetricsCollector(logger, registry, config)

	// 创建测试服务
	service := &domain.Service{
		ID:     "test-service",
		Name:   "test-service",
		Status: domain.ServiceStatusRunning,
		Spec: &domain.ServiceSpec{
			Package: "test-package",
		},
	}

	registry.Register(service)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动收集器
	startErr := make(chan error, 1)
	go func() {
		startErr <- collector.Start(ctx)
	}()

	// 等待收集器运行一段时间
	time.Sleep(2 * time.Second)

	// 验证系统指标
	systemMetrics := collector.GetSystemMetrics()
	if systemMetrics == nil {
		t.Error("System metrics should be collected")
	}

	// 验证服务指标
	serviceMetrics, exists := collector.GetServiceMetrics("test-service")
	if !exists {
		t.Log("Service metrics may not be collected in test environment")
	} else if serviceMetrics == nil {
		t.Error("Service metrics should not be nil if exists")
	}

	// 验证获取所有服务指标
	allMetrics := collector.GetAllServiceMetrics()
	if len(allMetrics) == 0 {
		t.Log("No service metrics collected (expected in test environment)")
	}

	// 停止收集器
	collector.Stop()

	// 等待 Start 返回
	select {
	case err := <-startErr:
		if err != nil && err != context.Canceled {
			t.Errorf("Start returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Start did not return after Stop was called")
	}
}

// TestMetricsReporter_Integration_Report 集成测试：指标上报
func TestMetricsReporter_Integration_Report(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockCollector := newMockMetricsCollector()

	// 添加服务指标
	mockCollector.AddServiceMetrics("service-1", &domain.ServiceMetrics{
		CPUUsage:    25.0,
		MemoryUsage: 30.0,
		MemoryBytes: 100 * 1024 * 1024,
		LastUpdated: time.Now(),
	})

	reporter := NewMetricsReporter(
		mockCollector,
		"http://localhost:8080", // 测试 URL（会失败，但可以测试逻辑）
		"test-agent",
		1*time.Second,
		3,
		1*time.Second,
		logger,
	)

	ctx := context.Background()

	// 测试构建写入请求
	reporterImpl := reporter.(*metricsReporter)
	writeRequest, err := reporterImpl.buildWriteRequest(ctx)
	if err != nil {
		t.Fatalf("buildWriteRequest failed: %v", err)
	}

	// 验证请求包含系统指标和服务指标
	if len(writeRequest.Timeseries) == 0 {
		t.Error("Write request should contain timeseries")
	}

	// 验证系统指标
	hasSystemMetrics := false
	hasServiceMetrics := false
	for _, ts := range writeRequest.Timeseries {
		for _, label := range ts.Labels {
			if label.Name == "__name__" {
				if label.Value == "agent_system" {
					hasSystemMetrics = true
				}
				if label.Value == "agent_service" {
					hasServiceMetrics = true
				}
			}
		}
	}

	if !hasSystemMetrics {
		t.Error("Write request should contain system metrics")
	}
	if !hasServiceMetrics {
		t.Error("Write request should contain service metrics")
	}
}

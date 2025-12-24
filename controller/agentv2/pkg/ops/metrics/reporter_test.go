package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"go.uber.org/zap/zaptest"
)

// mockMetricsCollector 模拟指标收集器
type mockMetricsCollector struct {
	systemMetrics  *domain.SystemMetrics
	serviceMetrics map[string]*domain.ServiceMetrics
}

func newMockMetricsCollector() *mockMetricsCollector {
	return &mockMetricsCollector{
		systemMetrics: &domain.SystemMetrics{
			CPUUsage:    50.0,
			MemoryUsage: 60.0,
			MemoryTotal: 1024 * 1024 * 1024, // 1GB
			MemoryFree:  400 * 1024 * 1024,  // 400MB
			DiskUsage:   70.0,
			DiskTotal:   100 * 1024 * 1024 * 1024, // 100GB
			DiskFree:    30 * 1024 * 1024 * 1024,  // 30GB
			NetworkIn:   1000 * 1024,              // 1MB
			NetworkOut:  500 * 1024,               // 500KB
			LoadAvg1:    1.5,
			LoadAvg5:    1.2,
			LoadAvg15:   1.0,
			LastUpdated: time.Now(),
		},
		serviceMetrics: make(map[string]*domain.ServiceMetrics),
	}
}

func (m *mockMetricsCollector) CollectSystemMetrics(ctx context.Context) (*domain.SystemMetrics, error) {
	return m.systemMetrics, nil
}

func (m *mockMetricsCollector) CollectServiceMetrics(ctx context.Context, serviceID string) (*domain.ServiceMetrics, error) {
	metrics, exists := m.serviceMetrics[serviceID]
	if !exists {
		return nil, nil
	}
	return metrics, nil
}

func (m *mockMetricsCollector) Start(ctx context.Context) error {
	return nil
}

func (m *mockMetricsCollector) Stop() error {
	return nil
}

func (m *mockMetricsCollector) GetSystemMetrics() *domain.SystemMetrics {
	return m.systemMetrics
}

func (m *mockMetricsCollector) GetServiceMetrics(serviceID string) (*domain.ServiceMetrics, bool) {
	metrics, exists := m.serviceMetrics[serviceID]
	return metrics, exists
}

func (m *mockMetricsCollector) GetAllServiceMetrics() map[string]*domain.ServiceMetrics {
	result := make(map[string]*domain.ServiceMetrics, len(m.serviceMetrics))
	for k, v := range m.serviceMetrics {
		result[k] = v
	}
	return result
}

func (m *mockMetricsCollector) GetEnhancedCollector() *EnhancedMetricsCollector {
	// Mock 实现：返回 nil，因为测试不需要增强型收集器
	return nil
}

func (m *mockMetricsCollector) UpdateEnhancedConfig(config EnhancedCollectorConfig) error {
	// Mock 实现：什么都不做
	return nil
}

func (m *mockMetricsCollector) AddServiceMetrics(serviceID string, metrics *domain.ServiceMetrics) {
	m.serviceMetrics[serviceID] = metrics
}

func TestMetricsReporter_BuildWriteRequest_SystemMetrics(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockCollector := newMockMetricsCollector()

	reporter := NewMetricsReporter(
		mockCollector,
		"http://localhost:8080",
		"test-agent",
		10*time.Second,
		3,
		1*time.Second,
		logger,
	).(*metricsReporter)

	ctx := context.Background()
	writeRequest, err := reporter.buildWriteRequest(ctx)
	if err != nil {
		t.Fatalf("Failed to build write request: %v", err)
	}

	if len(writeRequest.Timeseries) == 0 {
		t.Error("Write request should contain timeseries")
	}

	// 验证系统指标被包含
	foundSystemMetrics := false
	for _, ts := range writeRequest.Timeseries {
		for _, label := range ts.Labels {
			if label.Name == "__name__" && label.Value == "agent_system" {
				foundSystemMetrics = true
				break
			}
		}
		if foundSystemMetrics {
			break
		}
	}

	if !foundSystemMetrics {
		t.Error("System metrics should be included in write request")
	}
}

func TestMetricsReporter_BuildWriteRequest_ServiceMetrics(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockCollector := newMockMetricsCollector()

	// 添加服务指标
	mockCollector.AddServiceMetrics("service-1", &domain.ServiceMetrics{
		CPUUsage:     25.0,
		MemoryUsage:  30.0,
		MemoryBytes:  100 * 1024 * 1024, // 100MB
		DiskUsage:    10.0,
		NetworkIn:    500 * 1024, // 500KB
		NetworkOut:   200 * 1024, // 200KB
		RequestCount: 1000,
		ErrorCount:   10,
		ResponseTime: time.Duration(50) * time.Millisecond,
		LastUpdated:  time.Now(),
	})

	mockCollector.AddServiceMetrics("service-2", &domain.ServiceMetrics{
		CPUUsage:     15.0,
		MemoryUsage:  20.0,
		MemoryBytes:  50 * 1024 * 1024, // 50MB
		DiskUsage:    5.0,
		NetworkIn:    300 * 1024, // 300KB
		NetworkOut:   100 * 1024, // 100KB
		RequestCount: 500,
		ErrorCount:   5,
		ResponseTime: time.Duration(30) * time.Millisecond,
		LastUpdated:  time.Now(),
	})

	reporter := NewMetricsReporter(
		mockCollector,
		"http://localhost:8080",
		"test-agent",
		10*time.Second,
		3,
		1*time.Second,
		logger,
	).(*metricsReporter)

	ctx := context.Background()
	writeRequest, err := reporter.buildWriteRequest(ctx)
	if err != nil {
		t.Fatalf("Failed to build write request: %v", err)
	}

	// 验证服务指标被包含
	serviceMetricsCount := 0
	for _, ts := range writeRequest.Timeseries {
		for _, label := range ts.Labels {
			if label.Name == "__name__" && label.Value == "agent_service" {
				serviceMetricsCount++
				break
			}
		}
	}

	// 每个服务有多个指标（CPU、内存、磁盘、网络等），所以总数应该大于服务数
	if serviceMetricsCount == 0 {
		t.Error("Service metrics should be included in write request")
	}

	// 验证两个服务的指标都被包含
	service1Found := false
	service2Found := false
	for _, ts := range writeRequest.Timeseries {
		for _, label := range ts.Labels {
			if label.Name == "service_id" && label.Value == "service-1" {
				service1Found = true
			}
			if label.Name == "service_id" && label.Value == "service-2" {
				service2Found = true
			}
		}
	}

	if !service1Found {
		t.Error("Service 1 metrics should be included")
	}
	if !service2Found {
		t.Error("Service 2 metrics should be included")
	}
}

func TestMetricsReporter_ConvertServiceMetrics(t *testing.T) {
	logger := zaptest.NewLogger(t)
	reporter := NewMetricsReporter(
		newMockMetricsCollector(),
		"http://localhost:8080",
		"test-agent",
		10*time.Second,
		3,
		1*time.Second,
		logger,
	).(*metricsReporter)

	serviceMetrics := &domain.ServiceMetrics{
		CPUUsage:     25.0,
		MemoryUsage:  30.0,
		MemoryBytes:  100 * 1024 * 1024, // 100MB
		DiskUsage:    10.0,
		NetworkIn:    500 * 1024, // 500KB
		NetworkOut:   200 * 1024, // 200KB
		RequestCount: 1000,
		ErrorCount:   10,
		ResponseTime: time.Duration(50) * time.Millisecond,
		LastUpdated:  time.Now(),
	}

	timeseries := reporter.convertServiceMetrics("test-service", serviceMetrics)

	if len(timeseries) == 0 {
		t.Error("ConvertServiceMetrics should return timeseries")
	}

	// 验证所有指标都被转换
	expectedMetrics := []string{
		"cpu_usage",
		"memory_usage",
		"memory_bytes",
		"disk_usage",
		"network_in_bytes",
		"network_out_bytes",
		"request_count",
		"error_count",
		"response_time_ms",
	}

	foundMetrics := make(map[string]bool)
	for _, ts := range timeseries {
		for _, label := range ts.Labels {
			if label.Name == "metric" {
				foundMetrics[label.Value] = true
				break
			}
		}
	}

	for _, expected := range expectedMetrics {
		if !foundMetrics[expected] {
			t.Errorf("Expected metric %s not found in timeseries", expected)
		}
	}

	// 验证标签
	for _, ts := range timeseries {
		hasServiceID := false
		hasAgentCode := false
		for _, label := range ts.Labels {
			if label.Name == "service_id" && label.Value == "test-service" {
				hasServiceID = true
			}
			if label.Name == "agent_code" && label.Value == "test-agent" {
				hasAgentCode = true
			}
		}
		if !hasServiceID {
			t.Error("Timeseries should have service_id label")
		}
		if !hasAgentCode {
			t.Error("Timeseries should have agent_code label")
		}
	}
}

func TestMetricsReporter_Start_Stop(t *testing.T) {
	logger := zaptest.NewLogger(t)
	reporter := NewMetricsReporter(
		newMockMetricsCollector(),
		"http://localhost:8080",
		"test-agent",
		100*time.Millisecond, // 使用较短的间隔以便测试
		3,
		1*time.Second,
		logger,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 测试启动（在 goroutine 中运行，因为 Start 是阻塞的）
	startErr := make(chan error, 1)
	go func() {
		startErr <- reporter.Start(ctx)
	}()

	// 等待一小段时间让上报器运行
	time.Sleep(200 * time.Millisecond)

	// 测试停止
	err := reporter.Stop()
	if err != nil {
		t.Fatalf("Failed to stop metrics reporter: %v", err)
	}

	// 等待 Start 返回
	select {
	case err := <-startErr:
		if err != nil {
			t.Errorf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Start did not return after Stop was called")
	}
}

func TestMetricsReporter_Report_NoMetrics(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockCollector := &mockMetricsCollector{
		systemMetrics:  nil,                                     // 没有系统指标
		serviceMetrics: make(map[string]*domain.ServiceMetrics), // 没有服务指标
	}

	reporter := NewMetricsReporter(
		mockCollector,
		"http://localhost:8080",
		"test-agent",
		10*time.Second,
		3,
		1*time.Second,
		logger,
	)

	ctx := context.Background()
	// 当没有指标时，Report 应该返回 nil（不报错）
	err := reporter.Report(ctx)
	if err != nil {
		t.Errorf("Report should not return error when there are no metrics: %v", err)
	}
}

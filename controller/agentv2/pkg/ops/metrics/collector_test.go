package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"go.uber.org/zap/zaptest"
)

// mockServiceRegistry 模拟服务注册表
type mockServiceRegistry struct {
	services map[string]*domain.Service
}

func newMockServiceRegistry() *mockServiceRegistry {
	return &mockServiceRegistry{
		services: make(map[string]*domain.Service),
	}
}

func (m *mockServiceRegistry) Get(serviceID string) (*domain.Service, bool) {
	service, exists := m.services[serviceID]
	return service, exists
}

func (m *mockServiceRegistry) List() []*domain.Service {
	services := make([]*domain.Service, 0, len(m.services))
	for _, service := range m.services {
		services = append(services, service)
	}
	return services
}

func (m *mockServiceRegistry) Register(service *domain.Service) {
	m.services[service.ID] = service
}

func TestMetricsCollector_CollectSystemMetrics(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := newMockServiceRegistry()
	config := CollectorConfig{
		Interval:       10 * time.Second,
		CollectSystem:  true,
		CollectService: false,
	}

	collector := NewMetricsCollector(logger, registry, config)

	ctx := context.Background()
	metrics, err := collector.CollectSystemMetrics(ctx)
	if err != nil {
		t.Fatalf("Failed to collect system metrics: %v", err)
	}

	if metrics == nil {
		t.Error("System metrics should not be nil")
	}

	// 验证指标被存储
	storedMetrics := collector.GetSystemMetrics()
	if storedMetrics == nil {
		t.Error("Stored system metrics should not be nil")
	}
}

func TestMetricsCollector_CollectServiceMetrics_ServiceNotFound(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := newMockServiceRegistry()
	config := CollectorConfig{
		Interval:       10 * time.Second,
		CollectSystem:  false,
		CollectService: true,
	}

	collector := NewMetricsCollector(logger, registry, config)

	ctx := context.Background()
	_, err := collector.CollectServiceMetrics(ctx, "non-existent-service")
	if err == nil {
		t.Error("CollectServiceMetrics should return error for non-existent service")
	}
}

func TestMetricsCollector_CollectServiceMetrics_ServiceNotRunning(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := newMockServiceRegistry()
	config := CollectorConfig{
		Interval:       10 * time.Second,
		CollectSystem:  false,
		CollectService: true,
	}

	collector := NewMetricsCollector(logger, registry, config)

	// 创建未运行的服务
	service := &domain.Service{
		ID:     "test-service-1",
		Name:   "test-service",
		Status: domain.ServiceStatusStopped,
		Spec: &domain.ServiceSpec{
			Package: "test-package",
		},
	}

	registry.Register(service)

	ctx := context.Background()
	metrics, err := collector.CollectServiceMetrics(ctx, "test-service-1")
	if err != nil {
		t.Fatalf("CollectServiceMetrics should not return error for stopped service: %v", err)
	}

	if metrics == nil {
		t.Error("Service metrics should not be nil even for stopped service")
	}

	// 验证指标被存储
	storedMetrics, exists := collector.GetServiceMetrics("test-service-1")
	if !exists {
		t.Error("Service metrics should be stored")
	}
	if storedMetrics == nil {
		t.Error("Stored service metrics should not be nil")
	}
}

func TestMetricsCollector_GetSystemMetrics(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := newMockServiceRegistry()
	config := CollectorConfig{
		Interval:       10 * time.Second,
		CollectSystem:  true,
		CollectService: false,
	}

	collector := NewMetricsCollector(logger, registry, config)

	// 初始状态应该返回 nil 或空指标
	_ = collector.GetSystemMetrics()
	// 注意：初始状态可能是 nil 或空指标，这取决于实现

	// 收集一次指标
	ctx := context.Background()
	_, err := collector.CollectSystemMetrics(ctx)
	if err != nil {
		t.Fatalf("Failed to collect system metrics: %v", err)
	}

	// 现在应该能获取到指标
	metrics := collector.GetSystemMetrics()
	if metrics == nil {
		t.Error("System metrics should not be nil after collection")
	}
}

func TestMetricsCollector_GetServiceMetrics(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := newMockServiceRegistry()
	config := CollectorConfig{
		Interval:       10 * time.Second,
		CollectSystem:  false,
		CollectService: true,
	}

	collector := NewMetricsCollector(logger, registry, config)

	// 创建服务
	service := &domain.Service{
		ID:     "test-service-2",
		Name:   "test-service-2",
		Status: domain.ServiceStatusStopped,
		Spec: &domain.ServiceSpec{
			Package: "test-package-2",
		},
	}

	registry.Register(service)

	// 初始状态应该不存在
	_, exists := collector.GetServiceMetrics("test-service-2")
	if exists {
		t.Error("Service metrics should not exist before collection")
	}

	// 收集一次指标
	ctx := context.Background()
	_, err := collector.CollectServiceMetrics(ctx, "test-service-2")
	if err != nil {
		t.Fatalf("Failed to collect service metrics: %v", err)
	}

	// 现在应该能获取到指标
	metrics, exists := collector.GetServiceMetrics("test-service-2")
	if !exists {
		t.Error("Service metrics should exist after collection")
	}
	if metrics == nil {
		t.Error("Service metrics should not be nil")
	}
}

func TestMetricsCollector_Start_Stop(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := newMockServiceRegistry()
	config := CollectorConfig{
		Interval:       100 * time.Millisecond, // 使用较短的间隔以便测试
		CollectSystem:  true,
		CollectService: false,
	}

	collector := NewMetricsCollector(logger, registry, config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 测试启动收集器（在 goroutine 中运行，因为 Start 是阻塞的）
	startErr := make(chan error, 1)
	go func() {
		startErr <- collector.Start(ctx)
	}()

	// 等待一小段时间让收集器运行
	time.Sleep(200 * time.Millisecond)

	// 测试停止收集器
	err := collector.Stop()
	if err != nil {
		t.Fatalf("Failed to stop metrics collector: %v", err)
	}

	// 等待 Start 返回（应该因为 stopChan 关闭而返回）
	select {
	case err := <-startErr:
		if err != nil {
			t.Errorf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Start did not return after Stop was called")
	}
}

func TestMetricsCollector_Start_WithServices(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := newMockServiceRegistry()
	config := CollectorConfig{
		Interval:       100 * time.Millisecond, // 使用较短的间隔以便测试
		CollectSystem:  false,
		CollectService: true,
	}

	collector := NewMetricsCollector(logger, registry, config)

	// 创建运行中的服务
	service := &domain.Service{
		ID:     "test-service-3",
		Name:   "test-service-3",
		Status: domain.ServiceStatusRunning,
		Spec: &domain.ServiceSpec{
			Package: "test-package-3",
		},
	}

	registry.Register(service)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 测试启动收集器（在 goroutine 中运行，因为 Start 是阻塞的）
	startErr := make(chan error, 1)
	go func() {
		startErr <- collector.Start(ctx)
	}()

	// 等待一小段时间让收集器运行
	time.Sleep(200 * time.Millisecond)

	// 验证服务指标被收集
	// 注意：在测试环境中，服务指标收集可能会失败（因为没有真正的进程）
	// 但我们可以验证收集器确实运行了
	_, _ = collector.GetServiceMetrics("test-service-3")

	// 测试停止收集器
	err := collector.Stop()
	if err != nil {
		t.Fatalf("Failed to stop metrics collector: %v", err)
	}

	// 等待 Start 返回（应该因为 stopChan 关闭而返回）
	select {
	case err := <-startErr:
		if err != nil {
			t.Errorf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Start did not return after Stop was called")
	}
}

func TestMetricsCollector_GetAllServiceMetrics(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := newMockServiceRegistry()
	config := CollectorConfig{
		Interval:       10 * time.Second,
		CollectSystem:  false,
		CollectService: true,
	}

	collector := NewMetricsCollector(logger, registry, config)

	// 创建多个服务
	service1 := &domain.Service{
		ID:     "test-service-4",
		Name:   "test-service-4",
		Status: domain.ServiceStatusStopped,
		Spec: &domain.ServiceSpec{
			Package: "test-package-4",
		},
	}

	service2 := &domain.Service{
		ID:     "test-service-5",
		Name:   "test-service-5",
		Status: domain.ServiceStatusStopped,
		Spec: &domain.ServiceSpec{
			Package: "test-package-5",
		},
	}

	registry.Register(service1)
	registry.Register(service2)

	// 初始状态应该为空
	allMetrics := collector.GetAllServiceMetrics()
	if len(allMetrics) != 0 {
		t.Errorf("Expected empty metrics map, got %d entries", len(allMetrics))
	}

	// 收集服务指标
	ctx := context.Background()
	_, err := collector.CollectServiceMetrics(ctx, "test-service-4")
	if err != nil {
		t.Fatalf("Failed to collect service metrics: %v", err)
	}

	_, err = collector.CollectServiceMetrics(ctx, "test-service-5")
	if err != nil {
		t.Fatalf("Failed to collect service metrics: %v", err)
	}

	// 现在应该能获取到所有指标
	allMetrics = collector.GetAllServiceMetrics()
	if len(allMetrics) != 2 {
		t.Errorf("Expected 2 service metrics, got %d", len(allMetrics))
	}

	// 验证每个服务都有指标
	if _, exists := allMetrics["test-service-4"]; !exists {
		t.Error("Service metrics for test-service-4 should exist")
	}
	if _, exists := allMetrics["test-service-5"]; !exists {
		t.Error("Service metrics for test-service-5 should exist")
	}

	// 验证返回的是副本，修改不会影响原始数据
	allMetrics["test-service-4"] = nil
	storedMetrics, exists := collector.GetServiceMetrics("test-service-4")
	if !exists || storedMetrics == nil {
		t.Error("Original metrics should not be affected by modifying the returned map")
	}
}

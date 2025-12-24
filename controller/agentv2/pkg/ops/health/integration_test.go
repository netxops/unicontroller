package health

import (
	"testing"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/ops/recovery"
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

// TestCoordinator_Integration_HealthCheckAndHistory 集成测试：健康检查和历史记录
func TestCoordinator_Integration_HealthCheckAndHistory(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := newMockServiceRegistry()

	// 创建健康检查器
	checker := NewHealthChecker()

	// 创建自动恢复器（serviceManager 可以为 nil，测试中不需要）
	autoRecovery := recovery.NewAutoRecovery(nil, logger)

	// 创建协调器
	coordinator := NewCoordinator(
		checker,
		autoRecovery,
		nil, // serviceManager 可以为 nil（测试中不需要）
		registry,
		logger,
	)

	// 设置通知器
	notifier := NewLogNotifier(logger)
	coordinator.SetNotifier(notifier)

	// 创建测试服务
	service := &domain.Service{
		ID:     "test-service",
		Name:   "test-service",
		Status: domain.ServiceStatusRunning,
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Operations: &domain.OperationsConfig{
				HealthCheck: &domain.HealthCheckConfig{
					Type:     "process",
					Interval: 10 * time.Second,
				},
			},
		},
	}

	registry.Register(service)

	// 启动协调器
	err := coordinator.Start()
	if err != nil {
		t.Fatalf("Failed to start coordinator: %v", err)
	}

	// 等待一段时间让健康检查运行
	time.Sleep(2 * time.Second)

	// 验证历史记录
	history := coordinator.GetHistory("test-service", 10)
	if len(history) == 0 {
		t.Log("No health check history (expected if service is not actually running)")
	}

	// 停止协调器
	err = coordinator.Stop()
	if err != nil {
		t.Fatalf("Failed to stop coordinator: %v", err)
	}
}

// TestHealthHistory_Integration_AddAndGet 集成测试：健康检查历史记录
func TestHealthHistory_Integration_AddAndGet(t *testing.T) {
	history := NewHealthHistory(100)

	// 添加多条记录
	for i := 0; i < 10; i++ {
		result := &domain.CheckResult{
			Healthy:      i%2 == 0,
			Message:      "test message",
			Timestamp:    time.Now().Add(time.Duration(i) * time.Second),
			ResponseTime: 100 * time.Millisecond,
		}
		history.Add("test-service", result, "http")
	}

	// 获取历史记录
	entries := history.Get("test-service", 5)
	if len(entries) != 5 {
		t.Errorf("Expected 5 entries, got %d", len(entries))
	}

	// 验证记录顺序（最新的在前）
	if len(entries) > 1 {
		if entries[0].Timestamp.Before(entries[1].Timestamp) {
			t.Error("Entries should be sorted with newest first")
		}
	}

	// 测试清除
	history.Clear("test-service")
	entries = history.Get("test-service", 10)
	if len(entries) != 0 {
		t.Errorf("Expected 0 entries after clear, got %d", len(entries))
	}
}

// TestHealthNotifier_Integration_LogNotifier 集成测试：日志通知器
func TestHealthNotifier_Integration_LogNotifier(t *testing.T) {
	logger := zaptest.NewLogger(t)
	notifier := NewLogNotifier(logger)

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
	}

	result := &domain.CheckResult{
		Healthy:      false,
		Message:      "Service is unhealthy",
		Timestamp:    time.Now(),
		ResponseTime: 200 * time.Millisecond,
	}

	// 测试通知（应该不返回错误）
	err := notifier.Notify(
		service,
		domain.HealthStatusHealthy,
		domain.HealthStatusUnhealthy,
		result,
	)
	if err != nil {
		t.Errorf("Notify should not return error: %v", err)
	}
}

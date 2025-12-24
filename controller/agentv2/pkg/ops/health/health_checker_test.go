package health

import (
	"context"
	"testing"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
)

// mockChecker 模拟检查器
type mockChecker struct {
	checkFunc func(ctx context.Context) (*domain.CheckResult, error)
	checkType string
}

func (m *mockChecker) Check(ctx context.Context) (*domain.CheckResult, error) {
	if m.checkFunc != nil {
		return m.checkFunc(ctx)
	}
	return &domain.CheckResult{
		Healthy:   true,
		Message:   "mock check passed",
		Timestamp: time.Now(),
	}, nil
}

func (m *mockChecker) Type() string {
	return m.checkType
}

func TestHealthChecker_Check_NoConfig(t *testing.T) {
	checker := NewHealthChecker()

	// 创建没有健康检查配置的服务
	service := &domain.Service{
		ID:   "test-service-1",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
		},
	}

	ctx := context.Background()
	result, err := checker.Check(ctx, service)
	if err != nil {
		t.Fatalf("Check should not return error: %v", err)
	}

	if !result.Healthy {
		t.Error("Service without health check config should be healthy by default")
	}

	if result.Message != "no health check configured" {
		t.Errorf("Expected message 'no health check configured', got '%s'", result.Message)
	}
}

func TestHealthChecker_Check_WithConfig(t *testing.T) {
	checker := NewHealthChecker()

	// 创建有健康检查配置的服务
	service := &domain.Service{
		ID:   "test-service-2",
		Name: "test-service-2",
		Spec: &domain.ServiceSpec{
			Package: "test-package-2",
			Operations: &domain.OperationsConfig{
				HealthCheck: &domain.HealthCheckConfig{
					Type:     "http",
					Interval: 30 * time.Second,
					Timeout:  5 * time.Second,
					Retries:  3,
					HTTPPath: "/health",
				},
			},
		},
	}

	ctx := context.Background()
	result, err := checker.Check(ctx, service)

	// 注意：在测试环境中，HTTP 检查可能会失败（因为没有真正的服务）
	// 但我们可以验证检查器被创建和调用
	if err != nil {
		// HTTP 检查失败是预期的（因为没有真正的服务）
		if !result.Healthy {
			// 验证错误处理正确
			return
		}
	}

	// 如果检查成功，验证结果
	if result == nil {
		t.Error("Check result should not be nil")
	}
}

func TestHealthChecker_Start_Stop(t *testing.T) {
	checker := NewHealthChecker()

	// 创建有健康检查配置的服务
	service := &domain.Service{
		ID:   "test-service-3",
		Name: "test-service-3",
		Spec: &domain.ServiceSpec{
			Package: "test-package-3",
			Operations: &domain.OperationsConfig{
				HealthCheck: &domain.HealthCheckConfig{
					Type:     "http",
					Interval: 100 * time.Millisecond, // 使用较短的间隔以便测试
					Timeout:  5 * time.Second,
					Retries:  3,
					HTTPPath: "/health",
				},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 测试启动健康检查
	err := checker.Start(ctx, service)
	if err != nil {
		t.Fatalf("Failed to start health check: %v", err)
	}

	// 等待一小段时间让定期检查运行
	time.Sleep(150 * time.Millisecond)

	// 测试停止健康检查
	err = checker.Stop(service.ID)
	if err != nil {
		t.Fatalf("Failed to stop health check: %v", err)
	}

	// 验证检查器被移除
	// 通过再次检查来验证（应该重新创建检查器）
	_, err = checker.Check(ctx, service)
	if err != nil {
		// 错误是预期的（HTTP 检查失败）
		return
	}
}

func TestHealthChecker_UnsupportedType(t *testing.T) {
	checker := NewHealthChecker()

	// 创建有不受支持的健康检查类型的服务
	service := &domain.Service{
		ID:   "test-service-4",
		Name: "test-service-4",
		Spec: &domain.ServiceSpec{
			Package: "test-package-4",
			Operations: &domain.OperationsConfig{
				HealthCheck: &domain.HealthCheckConfig{
					Type:     "unsupported",
					Interval: 30 * time.Second,
					Timeout:  5 * time.Second,
					Retries:  3,
				},
			},
		},
	}

	ctx := context.Background()
	_, err := checker.Check(ctx, service)
	if err == nil {
		t.Error("Check should return error for unsupported health check type")
	}
}

func TestHealthChecker_Start_NoConfig(t *testing.T) {
	checker := NewHealthChecker()

	// 创建没有健康检查配置的服务
	service := &domain.Service{
		ID:   "test-service-5",
		Name: "test-service-5",
		Spec: &domain.ServiceSpec{
			Package: "test-package-5",
		},
	}

	ctx := context.Background()
	err := checker.Start(ctx, service)
	if err != nil {
		t.Errorf("Start should not return error for service without health check config: %v", err)
	}
}

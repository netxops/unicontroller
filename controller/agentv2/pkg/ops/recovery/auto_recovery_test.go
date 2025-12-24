package recovery

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"go.uber.org/zap/zaptest"
)

// mockServiceManager 模拟服务管理器
type mockServiceManager struct {
	restartFunc func(ctx context.Context, serviceID string) error
}

func (m *mockServiceManager) Start(ctx context.Context, serviceID string) error {
	return nil
}

func (m *mockServiceManager) Stop(ctx context.Context, serviceID string) error {
	return nil
}

func (m *mockServiceManager) Restart(ctx context.Context, serviceID string) error {
	if m.restartFunc != nil {
		return m.restartFunc(ctx, serviceID)
	}
	return nil
}

func (m *mockServiceManager) GetStatus(ctx context.Context, serviceID string) (*domain.Service, error) {
	return nil, nil
}

func (m *mockServiceManager) ListServices(ctx context.Context) ([]*domain.Service, error) {
	return nil, nil
}

func (m *mockServiceManager) RegisterService(service *domain.Service) error {
	return nil
}

func (m *mockServiceManager) UnregisterService(serviceID string) error {
	return nil
}

func TestAutoRecovery_HandleUnhealthy_NoConfig(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockManager := &mockServiceManager{}
	recovery := NewAutoRecovery(mockManager, logger)

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			// 没有 Operations 配置
		},
	}

	ctx := context.Background()
	err := recovery.HandleUnhealthy(ctx, service)
	if err != nil {
		t.Errorf("Expected no error when no auto-recovery config, got: %v", err)
	}
}

func TestAutoRecovery_HandleUnhealthy_Disabled(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockManager := &mockServiceManager{}
	recovery := NewAutoRecovery(mockManager, logger)

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Operations: &domain.OperationsConfig{
				AutoRecovery: &domain.AutoRecoveryConfig{
					Enabled: false,
				},
			},
		},
	}

	ctx := context.Background()
	err := recovery.HandleUnhealthy(ctx, service)
	if err != nil {
		t.Errorf("Expected no error when auto-recovery disabled, got: %v", err)
	}
}

func TestAutoRecovery_HandleUnhealthy_MaxRestartsExceeded(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockManager := &mockServiceManager{}
	recovery := NewAutoRecovery(mockManager, logger)

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Operations: &domain.OperationsConfig{
				AutoRecovery: &domain.AutoRecoveryConfig{
					Enabled:     true,
					MaxRestarts: 2,
				},
			},
		},
	}

	ctx := context.Background()

	// 第一次重启
	err := recovery.HandleUnhealthy(ctx, service)
	if err != nil {
		t.Errorf("Expected no error on first restart, got: %v", err)
	}

	// 第二次重启
	err = recovery.HandleUnhealthy(ctx, service)
	if err != nil {
		t.Errorf("Expected no error on second restart, got: %v", err)
	}

	// 第三次重启应该失败（超过最大次数）
	err = recovery.HandleUnhealthy(ctx, service)
	if err == nil {
		t.Error("Expected error when max restarts exceeded, got nil")
	}
}

func TestAutoRecovery_HandleUnhealthy_BackoffPeriod(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockManager := &mockServiceManager{}
	recovery := NewAutoRecovery(mockManager, logger)

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Operations: &domain.OperationsConfig{
				AutoRecovery: &domain.AutoRecoveryConfig{
					Enabled:      true,
					MaxRestarts:  10,
					RestartDelay: 100 * time.Millisecond,
				},
			},
		},
	}

	ctx := context.Background()

	// 第一次重启
	err := recovery.HandleUnhealthy(ctx, service)
	if err != nil {
		t.Errorf("Expected no error on first restart, got: %v", err)
	}

	// 立即再次尝试重启（应该在退避期内）
	err = recovery.HandleUnhealthy(ctx, service)
	if err != nil {
		t.Errorf("Expected no error during backoff period (should be skipped), got: %v", err)
	}

	// 等待退避期结束
	time.Sleep(150 * time.Millisecond)

	// 现在应该可以重启了
	err = recovery.HandleUnhealthy(ctx, service)
	if err != nil {
		t.Errorf("Expected no error after backoff period, got: %v", err)
	}
}

func TestAutoRecovery_HandleUnhealthy_Success(t *testing.T) {
	logger := zaptest.NewLogger(t)
	restartCalled := false
	mockManager := &mockServiceManager{
		restartFunc: func(ctx context.Context, serviceID string) error {
			restartCalled = true
			if serviceID != "test-service" {
				t.Errorf("Expected serviceID 'test-service', got: %s", serviceID)
			}
			return nil
		},
	}
	recovery := NewAutoRecovery(mockManager, logger)

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Operations: &domain.OperationsConfig{
				AutoRecovery: &domain.AutoRecoveryConfig{
					Enabled:      true,
					MaxRestarts:  10,
					RestartDelay: 10 * time.Millisecond,
				},
			},
		},
	}

	ctx := context.Background()
	err := recovery.HandleUnhealthy(ctx, service)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if !restartCalled {
		t.Error("Expected Restart to be called, but it wasn't")
	}

	// 验证恢复状态
	state, exists := recovery.GetRecoveryState("test-service")
	if !exists {
		t.Error("Expected recovery state to exist")
	}
	if state.RestartCount != 1 {
		t.Errorf("Expected restart count 1, got: %d", state.RestartCount)
	}
}

func TestAutoRecovery_HandleUnhealthy_RestartError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockManager := &mockServiceManager{
		restartFunc: func(ctx context.Context, serviceID string) error {
			return fmt.Errorf("service not found")
		},
	}
	recovery := NewAutoRecovery(mockManager, logger)

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Operations: &domain.OperationsConfig{
				AutoRecovery: &domain.AutoRecoveryConfig{
					Enabled:      true,
					MaxRestarts:  10,
					RestartDelay: 10 * time.Millisecond,
				},
			},
		},
	}

	ctx := context.Background()
	err := recovery.HandleUnhealthy(ctx, service)
	if err == nil {
		t.Error("Expected error when restart fails, got nil")
	}
}

func TestAutoRecovery_ResetRecoveryState(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockManager := &mockServiceManager{}
	recovery := NewAutoRecovery(mockManager, logger)

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Operations: &domain.OperationsConfig{
				AutoRecovery: &domain.AutoRecoveryConfig{
					Enabled:      true,
					MaxRestarts:  10,
					RestartDelay: 10 * time.Millisecond,
				},
			},
		},
	}

	ctx := context.Background()

	// 触发一次重启以创建恢复状态
	recovery.HandleUnhealthy(ctx, service)

	// 验证状态存在
	_, exists := recovery.GetRecoveryState("test-service")
	if !exists {
		t.Fatal("Expected recovery state to exist")
	}

	// 模拟时间过去 6 分钟（超过 5 分钟阈值）
	// 由于我们无法直接修改 LastRestart 时间，我们需要等待
	// 但在测试中，我们可以直接测试逻辑
	// 注意：实际实现中，ResetRecoveryState 会检查时间差
	// 这里我们测试状态存在的情况
	recovery.ResetRecoveryState("test-service")

	// 如果时间未超过 5 分钟，状态应该仍然存在
	// 如果超过，状态会被删除
	_, existsAfter := recovery.GetRecoveryState("test-service")
	// 由于时间未超过 5 分钟，状态应该仍然存在
	if !existsAfter {
		t.Error("Expected recovery state to still exist (time not exceeded)")
	}
}

func TestAutoRecovery_GetRecoveryState(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockManager := &mockServiceManager{}
	recovery := NewAutoRecovery(mockManager, logger)

	// 获取不存在的状态
	_, exists := recovery.GetRecoveryState("non-existent")
	if exists {
		t.Error("Expected no recovery state for non-existent service")
	}

	service := &domain.Service{
		ID:   "test-service",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Operations: &domain.OperationsConfig{
				AutoRecovery: &domain.AutoRecoveryConfig{
					Enabled:      true,
					MaxRestarts:  10,
					RestartDelay: 10 * time.Millisecond,
				},
			},
		},
	}

	ctx := context.Background()
	recovery.HandleUnhealthy(ctx, service)

	// 获取存在的状态
	state, exists := recovery.GetRecoveryState("test-service")
	if !exists {
		t.Error("Expected recovery state to exist")
	}
	if state == nil {
		t.Error("Expected non-nil recovery state")
	}
	if state.ServiceID != "test-service" {
		t.Errorf("Expected serviceID 'test-service', got: %s", state.ServiceID)
	}
	if state.RestartCount != 1 {
		t.Errorf("Expected restart count 1, got: %d", state.RestartCount)
	}
}

func TestAutoRecovery_CalculateBackoff(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockManager := &mockServiceManager{}
	recovery := NewAutoRecovery(mockManager, logger)

	// 测试指数退避
	currentDelay := 100 * time.Millisecond
	factor := 2.0
	maxBackoff := 1 * time.Second

	newDelay := recovery.calculateBackoff(currentDelay, factor, maxBackoff)
	expected := 200 * time.Millisecond
	if newDelay != expected {
		t.Errorf("Expected delay %v, got: %v", expected, newDelay)
	}

	// 测试超过最大退避时间
	currentDelay = 600 * time.Millisecond
	newDelay = recovery.calculateBackoff(currentDelay, factor, maxBackoff)
	if newDelay != maxBackoff {
		t.Errorf("Expected delay %v (max), got: %v", maxBackoff, newDelay)
	}

	// 测试边界情况：当前延迟等于最大退避时间
	currentDelay = maxBackoff
	newDelay = recovery.calculateBackoff(currentDelay, factor, maxBackoff)
	if newDelay != maxBackoff {
		t.Errorf("Expected delay %v (max), got: %v", maxBackoff, newDelay)
	}
}

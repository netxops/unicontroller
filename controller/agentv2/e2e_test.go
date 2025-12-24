package agentv2

import (
	"context"
	"testing"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/service"
	"go.uber.org/zap/zaptest"
)

// TestE2E_ServiceLifecycle 端到端测试：服务完整生命周期
func TestE2E_ServiceLifecycle(t *testing.T) {
	registry := service.NewServiceRegistry()
	dependencyMgr := service.NewDependencyManager(registry)

	// 创建服务
	service1 := &domain.Service{
		ID:   "e2e-service-1",
		Name: "e2e-service-1",
		Spec: &domain.ServiceSpec{
			Package: "e2e-package-1",
			Operations: &domain.OperationsConfig{
				Dependencies: []string{},
			},
		},
		Status: domain.ServiceStatusStopped,
	}

	service2 := &domain.Service{
		ID:   "e2e-service-2",
		Name: "e2e-service-2",
		Spec: &domain.ServiceSpec{
			Package: "e2e-package-2",
			Operations: &domain.OperationsConfig{
				Dependencies: []string{"e2e-service-1"},
			},
		},
		Status: domain.ServiceStatusStopped,
	}

	registry.Register(service1)
	registry.Register(service2)

	// 测试依赖解析
	sorted, err := dependencyMgr.ResolveDependencies([]string{"e2e-service-2", "e2e-service-1"})
	if err != nil {
		t.Fatalf("Failed to resolve dependencies: %v", err)
	}

	// 验证顺序
	if len(sorted) != 2 {
		t.Fatalf("Expected 2 services, got %d", len(sorted))
	}
	if sorted[0] != "e2e-service-1" {
		t.Errorf("Expected e2e-service-1 first, got %s", sorted[0])
	}
	if sorted[1] != "e2e-service-2" {
		t.Errorf("Expected e2e-service-2 second, got %s", sorted[1])
	}

	// 测试依赖验证
	err = dependencyMgr.ValidateDependencies(service2)
	if err != nil {
		t.Errorf("Dependencies should be valid: %v", err)
	}

	// 测试获取依赖项
	dependents := dependencyMgr.GetDependents("e2e-service-1")
	if len(dependents) != 1 {
		t.Errorf("Expected 1 dependent, got %d", len(dependents))
	}
	if len(dependents) > 0 && dependents[0].ID != "e2e-service-2" {
		t.Errorf("Expected dependent 'e2e-service-2', got '%s'", dependents[0].ID)
	}
}

// TestE2E_ServiceDiscoveryAndRegistration 端到端测试：服务发现和注册
func TestE2E_ServiceDiscoveryAndRegistration(t *testing.T) {
	registry := service.NewServiceRegistry()

	// 创建临时工作目录
	tmpDir := t.TempDir()

	// 注意：这里需要实际创建文件，但为了测试简化，我们只测试发现逻辑
	logger := zaptest.NewLogger(t)
	discovery := service.NewServiceDiscovery(tmpDir, 10*time.Second, registry, logger)

	ctx := context.Background()
	services, err := discovery.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	// 验证发现结果（可能是空的，因为目录是空的）
	_ = services

	// 测试启动和停止发现器
	startErr := make(chan error, 1)
	go func() {
		startErr <- discovery.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	err = discovery.Stop()
	if err != nil {
		t.Fatalf("Failed to stop discovery: %v", err)
	}

	select {
	case err := <-startErr:
		if err != nil && err != context.Canceled {
			t.Errorf("Start returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Start did not return after Stop was called")
	}
}

// TestE2E_DependencyResolution 端到端测试：复杂依赖解析
func TestE2E_DependencyResolution(t *testing.T) {
	registry := service.NewServiceRegistry()
	manager := service.NewDependencyManager(registry)

	// 创建复杂的依赖关系
	// service-a (无依赖)
	// service-b (依赖 service-a)
	// service-c (依赖 service-a, service-b)
	// service-d (依赖 service-c)

	serviceA := &domain.Service{
		ID:   "service-a",
		Name: "service-a",
		Spec: &domain.ServiceSpec{
			Package: "package-a",
			Operations: &domain.OperationsConfig{
				Dependencies: []string{},
			},
		},
	}

	serviceB := &domain.Service{
		ID:   "service-b",
		Name: "service-b",
		Spec: &domain.ServiceSpec{
			Package: "package-b",
			Operations: &domain.OperationsConfig{
				Dependencies: []string{"service-a"},
			},
		},
	}

	serviceC := &domain.Service{
		ID:   "service-c",
		Name: "service-c",
		Spec: &domain.ServiceSpec{
			Package: "package-c",
			Operations: &domain.OperationsConfig{
				Dependencies: []string{"service-a", "service-b"},
			},
		},
	}

	serviceD := &domain.Service{
		ID:   "service-d",
		Name: "service-d",
		Spec: &domain.ServiceSpec{
			Package: "package-d",
			Operations: &domain.OperationsConfig{
				Dependencies: []string{"service-c"},
			},
		},
	}

	registry.Register(serviceA)
	registry.Register(serviceB)
	registry.Register(serviceC)
	registry.Register(serviceD)

	// 测试依赖解析（任意顺序输入）
	sorted, err := manager.ResolveDependencies([]string{"service-d", "service-c", "service-b", "service-a"})
	if err != nil {
		t.Fatalf("Failed to resolve dependencies: %v", err)
	}

	// 验证顺序：service-a 应该在 service-b 之前，service-b 应该在 service-c 之前，service-c 应该在 service-d 之前
	indexA := -1
	indexB := -1
	indexC := -1
	indexD := -1
	for i, id := range sorted {
		switch id {
		case "service-a":
			indexA = i
		case "service-b":
			indexB = i
		case "service-c":
			indexC = i
		case "service-d":
			indexD = i
		}
	}

	if indexA == -1 || indexB == -1 || indexC == -1 || indexD == -1 {
		t.Fatalf("All services should be in sorted list. Got: %v", sorted)
	}

	if indexA >= indexB || indexB >= indexC || indexC >= indexD {
		t.Errorf("Services should be sorted by dependency order. Got order: %v", sorted)
	}
}

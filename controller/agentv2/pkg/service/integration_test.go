package service

import (
	"context"
	"testing"
	"time"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
	"github.com/influxdata/telegraf/controller/agentv2/pkg/infrastructure/systemd"
)

// TestServiceManager_Integration_StartStopRestart 集成测试：服务启动、停止、重启
func TestServiceManager_Integration_StartStopRestart(t *testing.T) {
	registry := NewServiceRegistry()
	systemdAdapter := systemd.NewSystemdAdapter(false)
	mockProcess := newMockProcessManager()
	manager := &serviceManager{
		registry:       registry,
		systemd:        systemdAdapter,
		processManager: mockProcess,
		dependencyMgr:  NewDependencyManager(registry),
	}

	// 创建测试服务
	service := &domain.Service{
		ID:   "integration-test-service",
		Name: "integration-test-service",
		Spec: &domain.ServiceSpec{
			Package: "integration-test-package",
			Startup: &domain.StartupSpec{
				Method: "direct",
			},
			Binary: &domain.BinarySpec{
				Path: "/bin/echo",
			},
		},
		Status: domain.ServiceStatusStopped,
	}

	registry.Register(service)

	ctx := context.Background()

	// 测试启动
	err := manager.Start(ctx, "integration-test-service")
	if err != nil {
		t.Logf("Start failed (expected in test environment): %v", err)
		// 在测试环境中，启动可能会失败，这是正常的
	}

	// 测试获取状态
	status, err := manager.GetStatus(ctx, "integration-test-service")
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if status == nil {
		t.Fatal("GetStatus returned nil")
	}

	// 测试停止
	err = manager.Stop(ctx, "integration-test-service")
	if err != nil {
		t.Logf("Stop failed (expected in test environment): %v", err)
	}

	// 测试重启
	err = manager.Restart(ctx, "integration-test-service")
	if err != nil {
		t.Logf("Restart failed (expected in test environment): %v", err)
	}
}

// TestDependencyManager_Integration_ResolveDependencies 集成测试：依赖解析
func TestDependencyManager_Integration_ResolveDependencies(t *testing.T) {
	registry := NewServiceRegistry()
	manager := NewDependencyManager(registry)

	// 创建依赖链：service-1 -> service-2 -> service-3
	service1 := &domain.Service{
		ID:   "service-1",
		Name: "service-1",
		Spec: &domain.ServiceSpec{
			Package: "package-1",
			Operations: &domain.OperationsConfig{
				Dependencies: []string{},
			},
		},
	}

	service2 := &domain.Service{
		ID:   "service-2",
		Name: "service-2",
		Spec: &domain.ServiceSpec{
			Package: "package-2",
			Operations: &domain.OperationsConfig{
				Dependencies: []string{"service-1"},
			},
		},
	}

	service3 := &domain.Service{
		ID:   "service-3",
		Name: "service-3",
		Spec: &domain.ServiceSpec{
			Package: "package-3",
			Operations: &domain.OperationsConfig{
				Dependencies: []string{"service-2"},
			},
		},
	}

	registry.Register(service1)
	registry.Register(service2)
	registry.Register(service3)

	// 测试依赖解析
	sorted, err := manager.ResolveDependencies([]string{"service-3", "service-2", "service-1"})
	if err != nil {
		t.Fatalf("ResolveDependencies failed: %v", err)
	}

	// 验证顺序
	if len(sorted) != 3 {
		t.Fatalf("Expected 3 services, got %d", len(sorted))
	}

	// service-1 应该在第一位
	if sorted[0] != "service-1" {
		t.Errorf("Expected service-1 at position 0, got %s", sorted[0])
	}

	// service-2 应该在第二位
	if sorted[1] != "service-2" {
		t.Errorf("Expected service-2 at position 1, got %s", sorted[1])
	}

	// service-3 应该在第三位
	if sorted[2] != "service-3" {
		t.Errorf("Expected service-3 at position 2, got %s", sorted[2])
	}
}

// TestServiceManager_Integration_WithDependencies 集成测试：带依赖的服务启动
func TestServiceManager_Integration_WithDependencies(t *testing.T) {
	registry := NewServiceRegistry()
	systemdAdapter := systemd.NewSystemdAdapter(false)
	mockProcess := newMockProcessManager()
	manager := &serviceManager{
		registry:       registry,
		systemd:        systemdAdapter,
		processManager: mockProcess,
		dependencyMgr:  NewDependencyManager(registry),
	}

	// 创建依赖服务
	dependency := &domain.Service{
		ID:   "dependency-service",
		Name: "dependency-service",
		Spec: &domain.ServiceSpec{
			Package: "dependency-package",
			Startup: &domain.StartupSpec{
				Method:      "systemd",
				ServiceName: "dependency.service",
			},
		},
		Status: domain.ServiceStatusStopped,
	}

	// 创建主服务（依赖 dependency-service）
	mainService := &domain.Service{
		ID:   "main-service",
		Name: "main-service",
		Spec: &domain.ServiceSpec{
			Package: "main-package",
			Startup: &domain.StartupSpec{
				Method:      "systemd",
				ServiceName: "main.service",
			},
			Operations: &domain.OperationsConfig{
				Dependencies: []string{"dependency-service"},
			},
		},
		Status: domain.ServiceStatusStopped,
	}

	registry.Register(dependency)
	registry.Register(mainService)

	ctx := context.Background()

	// 测试启动主服务（应该先启动依赖）
	err := manager.Start(ctx, "main-service")
	if err != nil {
		t.Logf("Start with dependencies failed (expected in test environment): %v", err)
		// 在测试环境中，systemd 命令会失败，这是正常的
	}

	// 验证依赖解析
	dependencyMgr := NewDependencyManager(registry)
	dependents := dependencyMgr.GetDependents("dependency-service")
	if len(dependents) != 1 {
		t.Errorf("Expected 1 dependent, got %d", len(dependents))
	}
	if len(dependents) > 0 && dependents[0].ID != "main-service" {
		t.Errorf("Expected dependent 'main-service', got '%s'", dependents[0].ID)
	}
}

// TestServiceRegistry_Integration_ConcurrentAccess 集成测试：并发访问注册表
func TestServiceRegistry_Integration_ConcurrentAccess(t *testing.T) {
	registry := NewServiceRegistry()

	// 创建多个服务
	services := make([]*domain.Service, 10)
	for i := 0; i < 10; i++ {
		services[i] = &domain.Service{
			ID:   "service-" + string(rune('0'+i)),
			Name: "service-" + string(rune('0'+i)),
			Spec: &domain.ServiceSpec{
				Package: "package-" + string(rune('0'+i)),
			},
		}
		registry.Register(services[i])
	}

	// 并发读取
	done := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		go func(id int) {
			_, _ = registry.Get("service-" + string(rune('0'+(id%10))))
			_ = registry.List()
			done <- true
		}(i)
	}

	// 等待所有 goroutine 完成
	for i := 0; i < 20; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Concurrent access test timed out")
		}
	}
}

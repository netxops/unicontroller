package service

import (
	"testing"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
)

func TestDependencyManager(t *testing.T) {
	registry := NewServiceRegistry()
	manager := NewDependencyManager(registry)

	// 创建测试服务
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
		t.Fatalf("Failed to resolve dependencies: %v", err)
	}

	// 验证顺序：service-1 应该在 service-2 之前，service-2 应该在 service-3 之前
	index1 := -1
	index2 := -1
	index3 := -1
	for i, id := range sorted {
		if id == "service-1" {
			index1 = i
		}
		if id == "service-2" {
			index2 = i
		}
		if id == "service-3" {
			index3 = i
		}
	}

	if index1 == -1 || index2 == -1 || index3 == -1 {
		t.Fatalf("All services should be in sorted list. Got: %v", sorted)
	}

	if index1 >= index2 || index2 >= index3 {
		t.Errorf("Services should be sorted by dependency order. Got order: %v (service-1 at %d, service-2 at %d, service-3 at %d)", sorted, index1, index2, index3)
	}

	// 测试依赖验证
	err = manager.ValidateDependencies(service2)
	if err != nil {
		t.Errorf("Dependencies should be valid: %v", err)
	}

	// 测试获取依赖项
	dependents := manager.GetDependents("service-1")
	if len(dependents) != 1 {
		t.Errorf("Expected 1 dependent, got %d", len(dependents))
	}
	if dependents[0].ID != "service-2" {
		t.Errorf("Expected dependent 'service-2', got '%s'", dependents[0].ID)
	}

	// 测试 service-2 的依赖项应该是 service-3
	dependents2 := manager.GetDependents("service-2")
	if len(dependents2) != 1 {
		t.Errorf("Expected 1 dependent for service-2, got %d", len(dependents2))
	}
	if dependents2[0].ID != "service-3" {
		t.Errorf("Expected dependent 'service-3', got '%s'", dependents2[0].ID)
	}
}

// TestDependencyManager_CircularDependency 测试循环依赖检测
func TestDependencyManager_CircularDependency(t *testing.T) {
	registry := NewServiceRegistry()
	manager := NewDependencyManager(registry)

	// 创建循环依赖：service-1 -> service-2 -> service-3 -> service-1
	service1 := &domain.Service{
		ID:   "service-1",
		Name: "service-1",
		Spec: &domain.ServiceSpec{
			Package: "package-1",
			Operations: &domain.OperationsConfig{
				Dependencies: []string{"service-3"},
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

	// 应该检测到循环依赖
	_, err := manager.ResolveDependencies([]string{"service-1", "service-2", "service-3"})
	if err == nil {
		t.Error("Expected error for circular dependency, got nil")
	}
	if err != nil && err.Error() == "" {
		t.Error("Expected error message for circular dependency")
	}
}

// TestDependencyManager_EmptyDependencies 测试空依赖列表
func TestDependencyManager_EmptyDependencies(t *testing.T) {
	registry := NewServiceRegistry()
	manager := NewDependencyManager(registry)

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

	registry.Register(service1)

	// 测试空依赖列表
	sorted, err := manager.ResolveDependencies([]string{"service-1"})
	if err != nil {
		t.Fatalf("Failed to resolve dependencies: %v", err)
	}
	if len(sorted) != 1 || sorted[0] != "service-1" {
		t.Errorf("Expected [service-1], got %v", sorted)
	}
}

// TestDependencyManager_MultipleDependencies 测试多个依赖
func TestDependencyManager_MultipleDependencies(t *testing.T) {
	registry := NewServiceRegistry()
	manager := NewDependencyManager(registry)

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
				Dependencies: []string{},
			},
		},
	}

	service3 := &domain.Service{
		ID:   "service-3",
		Name: "service-3",
		Spec: &domain.ServiceSpec{
			Package: "package-3",
			Operations: &domain.OperationsConfig{
				Dependencies: []string{"service-1", "service-2"},
			},
		},
	}

	registry.Register(service1)
	registry.Register(service2)
	registry.Register(service3)

	sorted, err := manager.ResolveDependencies([]string{"service-3", "service-1", "service-2"})
	if err != nil {
		t.Fatalf("Failed to resolve dependencies: %v", err)
	}

	// service-1 和 service-2 应该在 service-3 之前
	index1 := -1
	index2 := -1
	index3 := -1
	for i, id := range sorted {
		if id == "service-1" {
			index1 = i
		}
		if id == "service-2" {
			index2 = i
		}
		if id == "service-3" {
			index3 = i
		}
	}

	if index1 == -1 || index2 == -1 || index3 == -1 {
		t.Fatalf("All services should be in sorted list. Got: %v", sorted)
	}

	if index1 >= index3 || index2 >= index3 {
		t.Errorf("service-1 and service-2 should be before service-3. Got order: %v", sorted)
	}
}

// TestDependencyManager_ServiceNotFound 测试服务不存在的情况
func TestDependencyManager_ServiceNotFound(t *testing.T) {
	registry := NewServiceRegistry()
	manager := NewDependencyManager(registry)

	_, err := manager.ResolveDependencies([]string{"non-existent-service"})
	if err == nil {
		t.Error("Expected error for non-existent service, got nil")
	}
}

// TestDependencyManager_DependencyNotFound 测试依赖服务不存在的情况
func TestDependencyManager_DependencyNotFound(t *testing.T) {
	registry := NewServiceRegistry()
	manager := NewDependencyManager(registry)

	service1 := &domain.Service{
		ID:   "service-1",
		Name: "service-1",
		Spec: &domain.ServiceSpec{
			Package: "package-1",
			Operations: &domain.OperationsConfig{
				Dependencies: []string{"non-existent-dependency"},
			},
		},
	}

	registry.Register(service1)

	_, err := manager.ResolveDependencies([]string{"service-1"})
	if err == nil {
		t.Error("Expected error for non-existent dependency, got nil")
	}
}

// TestDependencyManager_ValidateDependencies 测试依赖验证
func TestDependencyManager_ValidateDependencies(t *testing.T) {
	registry := NewServiceRegistry()
	manager := NewDependencyManager(registry)

	service1 := &domain.Service{
		ID:   "service-1",
		Name: "service-1",
		Spec: &domain.ServiceSpec{
			Package: "package-1",
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

	registry.Register(service1)
	registry.Register(service2)

	// 验证有效的依赖
	err := manager.ValidateDependencies(service2)
	if err != nil {
		t.Errorf("Expected no error for valid dependencies, got %v", err)
	}

	// 验证不存在的依赖
	service3 := &domain.Service{
		ID:   "service-3",
		Name: "service-3",
		Spec: &domain.ServiceSpec{
			Package: "package-3",
			Operations: &domain.OperationsConfig{
				Dependencies: []string{"non-existent"},
			},
		},
	}

	err = manager.ValidateDependencies(service3)
	if err == nil {
		t.Error("Expected error for non-existent dependency, got nil")
	}

	// 验证没有 Operations 配置的服务
	service4 := &domain.Service{
		ID:   "service-4",
		Name: "service-4",
		Spec: &domain.ServiceSpec{
			Package: "package-4",
		},
	}

	err = manager.ValidateDependencies(service4)
	if err != nil {
		t.Errorf("Expected no error for service without Operations, got %v", err)
	}
}

// TestDependencyManager_GetDependents 测试获取依赖项
func TestDependencyManager_GetDependents(t *testing.T) {
	registry := NewServiceRegistry()
	manager := NewDependencyManager(registry)

	service1 := &domain.Service{
		ID:   "service-1",
		Name: "service-1",
		Spec: &domain.ServiceSpec{
			Package: "package-1",
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
				Dependencies: []string{"service-1"},
			},
		},
	}

	registry.Register(service1)
	registry.Register(service2)
	registry.Register(service3)

	// 测试获取多个依赖项
	dependents := manager.GetDependents("service-1")
	if len(dependents) != 2 {
		t.Errorf("Expected 2 dependents, got %d", len(dependents))
	}

	// 验证依赖项包含 service-2 和 service-3
	found2 := false
	found3 := false
	for _, dep := range dependents {
		if dep.ID == "service-2" {
			found2 = true
		}
		if dep.ID == "service-3" {
			found3 = true
		}
	}
	if !found2 {
		t.Error("Expected to find service-2 in dependents")
	}
	if !found3 {
		t.Error("Expected to find service-3 in dependents")
	}

	// 测试不存在的服务
	dependents = manager.GetDependents("non-existent")
	if len(dependents) != 0 {
		t.Errorf("Expected 0 dependents for non-existent service, got %d", len(dependents))
	}
}

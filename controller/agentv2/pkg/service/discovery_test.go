package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestServiceDiscovery_Discover_EmptyWorkspace(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	registry := NewServiceRegistry()

	discovery := NewServiceDiscovery(tmpDir, 10*time.Second, registry, logger)

	ctx := context.Background()
	services, err := discovery.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover should not return error for empty workspace: %v", err)
	}

	if len(services) != 0 {
		t.Errorf("Expected 0 services in empty workspace, got %d", len(services))
	}
}

func TestServiceDiscovery_Discover_NonExistentWorkspace(t *testing.T) {
	logger := zaptest.NewLogger(t)
	nonExistentDir := "/non/existent/directory"
	registry := NewServiceRegistry()

	discovery := NewServiceDiscovery(nonExistentDir, 10*time.Second, registry, logger)

	ctx := context.Background()
	services, err := discovery.Discover(ctx)
	// 应该不返回错误，而是返回空列表（因为会尝试创建目录）
	if err != nil {
		t.Fatalf("Discover should handle non-existent workspace gracefully: %v", err)
	}

	if len(services) != 0 {
		t.Errorf("Expected 0 services for non-existent workspace, got %d", len(services))
	}
}

func TestServiceDiscovery_Discover_ValidPackageJSON(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	registry := NewServiceRegistry()

	// 创建服务目录
	serviceDir := filepath.Join(tmpDir, "test-service")
	if err := os.MkdirAll(serviceDir, 0755); err != nil {
		t.Fatalf("Failed to create service directory: %v", err)
	}

	// 创建 package.json 文件
	packageJSON := map[string]interface{}{
		"package":     "test-package",
		"version":     "1.0.0",
		"description": "Test service",
		"binary": map[string]interface{}{
			"name": "test-binary",
			"path": "/usr/bin/test-binary",
		},
		"startup": map[string]interface{}{
			"method":       "direct",
			"service_name": "",
			"args":         []string{"--port", "8080"},
		},
	}

	packageJSONPath := filepath.Join(serviceDir, "package.json")
	file, err := os.Create(packageJSONPath)
	if err != nil {
		t.Fatalf("Failed to create package.json: %v", err)
	}

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(packageJSON); err != nil {
		t.Fatalf("Failed to encode package.json: %v", err)
	}
	file.Close()

	discovery := NewServiceDiscovery(tmpDir, 10*time.Second, registry, logger)

	ctx := context.Background()
	services, err := discovery.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover should not return error: %v", err)
	}

	if len(services) != 1 {
		t.Fatalf("Expected 1 service, got %d", len(services))
	}

	service := services[0]
	if service.ID != "test-package" {
		t.Errorf("Expected service ID 'test-package', got '%s'", service.ID)
	}
	if service.Name != "test-package" {
		t.Errorf("Expected service name 'test-package', got '%s'", service.Name)
	}
	if service.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", service.Version)
	}
}

func TestServiceDiscovery_Discover_InvalidPackageJSON(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	registry := NewServiceRegistry()

	// 创建服务目录
	serviceDir := filepath.Join(tmpDir, "test-service")
	if err := os.MkdirAll(serviceDir, 0755); err != nil {
		t.Fatalf("Failed to create service directory: %v", err)
	}

	// 创建无效的 package.json 文件
	packageJSONPath := filepath.Join(serviceDir, "package.json")
	if err := os.WriteFile(packageJSONPath, []byte("invalid json"), 0644); err != nil {
		t.Fatalf("Failed to create invalid package.json: %v", err)
	}

	discovery := NewServiceDiscovery(tmpDir, 10*time.Second, registry, logger)

	ctx := context.Background()
	services, err := discovery.Discover(ctx)
	// 应该不返回错误，而是跳过无效文件
	if err != nil {
		t.Fatalf("Discover should handle invalid JSON gracefully: %v", err)
	}

	if len(services) != 0 {
		t.Errorf("Expected 0 services for invalid package.json, got %d", len(services))
	}
}

func TestServiceDiscovery_Discover_MultipleServices(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	registry := NewServiceRegistry()

	// 创建多个服务目录
	for i := 1; i <= 3; i++ {
		serviceDir := filepath.Join(tmpDir, "service-"+string(rune('0'+i)))
		if err := os.MkdirAll(serviceDir, 0755); err != nil {
			t.Fatalf("Failed to create service directory: %v", err)
		}

		packageJSON := map[string]interface{}{
			"package": "service-" + string(rune('0'+i)),
			"version": "1.0.0",
			"startup": map[string]interface{}{
				"method": "direct",
			},
		}

		packageJSONPath := filepath.Join(serviceDir, "package.json")
		file, err := os.Create(packageJSONPath)
		if err != nil {
			t.Fatalf("Failed to create package.json: %v", err)
		}

		encoder := json.NewEncoder(file)
		if err := encoder.Encode(packageJSON); err != nil {
			t.Fatalf("Failed to encode package.json: %v", err)
		}
		file.Close()
	}

	discovery := NewServiceDiscovery(tmpDir, 10*time.Second, registry, logger)

	ctx := context.Background()
	services, err := discovery.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover should not return error: %v", err)
	}

	if len(services) != 3 {
		t.Errorf("Expected 3 services, got %d", len(services))
	}
}

func TestServiceDiscovery_Start_Stop(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	registry := NewServiceRegistry()

	discovery := NewServiceDiscovery(tmpDir, 100*time.Millisecond, registry, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 测试启动（在 goroutine 中运行，因为 Start 是阻塞的）
	startErr := make(chan error, 1)
	go func() {
		startErr <- discovery.Start(ctx)
	}()

	// 等待一小段时间让发现器运行
	time.Sleep(200 * time.Millisecond)

	// 测试停止
	err := discovery.Stop()
	if err != nil {
		t.Fatalf("Failed to stop service discovery: %v", err)
	}

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

func TestServiceDiscovery_DiscoverAndRegister(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	registry := NewServiceRegistry()

	// 创建服务目录和 package.json
	serviceDir := filepath.Join(tmpDir, "test-service")
	if err := os.MkdirAll(serviceDir, 0755); err != nil {
		t.Fatalf("Failed to create service directory: %v", err)
	}

	packageJSON := map[string]interface{}{
		"package": "test-package",
		"version": "1.0.0",
		"startup": map[string]interface{}{
			"method": "direct",
		},
	}

	packageJSONPath := filepath.Join(serviceDir, "package.json")
	file, err := os.Create(packageJSONPath)
	if err != nil {
		t.Fatalf("Failed to create package.json: %v", err)
	}

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(packageJSON); err != nil {
		t.Fatalf("Failed to encode package.json: %v", err)
	}
	file.Close()

	discovery := NewServiceDiscovery(tmpDir, 10*time.Second, registry, logger)

	ctx := context.Background()
	services, err := discovery.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	// 手动注册服务（模拟 discoverAndRegister 的行为）
	for _, service := range services {
		registry.Register(service)
	}

	// 验证服务已注册
	registered, exists := registry.Get("test-package")
	if !exists {
		t.Error("Service should be registered")
	}
	if registered == nil {
		t.Error("Registered service should not be nil")
	}
	if registered.ID != "test-package" {
		t.Errorf("Expected service ID 'test-package', got '%s'", registered.ID)
	}
}

func TestServiceDiscovery_ParsePackageJSON_WithDependencies(t *testing.T) {
	logger := zaptest.NewLogger(t)
	tmpDir := t.TempDir()
	registry := NewServiceRegistry()

	// 创建带依赖的服务
	serviceDir := filepath.Join(tmpDir, "test-service")
	if err := os.MkdirAll(serviceDir, 0755); err != nil {
		t.Fatalf("Failed to create service directory: %v", err)
	}

	packageJSON := map[string]interface{}{
		"package": "test-package",
		"version": "1.0.0",
		"startup": map[string]interface{}{
			"method": "direct",
		},
		"dependencies": []map[string]string{
			{"package": "dependency-1"},
			{"package": "dependency-2"},
		},
	}

	packageJSONPath := filepath.Join(serviceDir, "package.json")
	file, err := os.Create(packageJSONPath)
	if err != nil {
		t.Fatalf("Failed to create package.json: %v", err)
	}

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(packageJSON); err != nil {
		t.Fatalf("Failed to encode package.json: %v", err)
	}
	file.Close()

	discovery := NewServiceDiscovery(tmpDir, 10*time.Second, registry, logger)

	ctx := context.Background()
	services, err := discovery.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if len(services) != 1 {
		t.Fatalf("Expected 1 service, got %d", len(services))
	}

	service := services[0]
	if service.Spec.Operations == nil {
		t.Error("Service should have Operations config")
		return
	}

	if len(service.Spec.Operations.Dependencies) != 2 {
		t.Errorf("Expected 2 dependencies, got %d", len(service.Spec.Operations.Dependencies))
	}

	if service.Spec.Operations.Dependencies[0] != "dependency-1" {
		t.Errorf("Expected first dependency 'dependency-1', got '%s'", service.Spec.Operations.Dependencies[0])
	}
	if service.Spec.Operations.Dependencies[1] != "dependency-2" {
		t.Errorf("Expected second dependency 'dependency-2', got '%s'", service.Spec.Operations.Dependencies[1])
	}
}


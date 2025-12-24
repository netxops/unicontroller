package service

import (
	"testing"

	"github.com/influxdata/telegraf/controller/agentv2/pkg/domain"
)

func TestServiceRegistry(t *testing.T) {
	registry := NewServiceRegistry()

	// 测试注册服务
	service := &domain.Service{
		ID:   "test-service-1",
		Name: "test-service",
		Spec: &domain.ServiceSpec{
			Package: "test-package",
			Version: "1.0.0",
		},
		Status: domain.ServiceStatusStopped,
	}

	registry.Register(service)

	// 测试获取服务
	retrieved, exists := registry.Get("test-service-1")
	if !exists {
		t.Fatal("Service should exist")
	}
	if retrieved.ID != "test-service-1" {
		t.Errorf("Expected service ID 'test-service-1', got '%s'", retrieved.ID)
	}

	// 测试按名称获取
	retrievedByName, exists := registry.GetByName("test-service")
	if !exists {
		t.Fatal("Service should exist by name")
	}
	if retrievedByName.Name != "test-service" {
		t.Errorf("Expected service name 'test-service', got '%s'", retrievedByName.Name)
	}

	// 测试列出服务
	services := registry.List()
	if len(services) != 1 {
		t.Errorf("Expected 1 service, got %d", len(services))
	}

	// 测试注销服务
	registry.Unregister("test-service-1")
	_, exists = registry.Get("test-service-1")
	if exists {
		t.Fatal("Service should not exist after unregister")
	}

	// 测试计数
	count := registry.Count()
	if count != 0 {
		t.Errorf("Expected 0 services, got %d", count)
	}
}

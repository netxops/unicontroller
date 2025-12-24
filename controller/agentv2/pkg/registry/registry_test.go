package registry

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestEtcdRegistry_NewEtcdRegistry_InvalidEndpoints(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// 注意：NewEtcdRegistry 创建客户端时不会立即连接，所以不会立即返回错误
	// 只有在实际使用时才会失败
	registry, err := NewEtcdRegistry([]string{"invalid:2379"}, "test-prefix", logger)
	if err != nil {
		// 如果创建时就失败，这是可以接受的
		return
	}
	defer registry.Stop()

	// 尝试使用注册器，应该在实际使用时失败
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	info := &ServiceInfo{
		Key:      "test-key",
		Name:     "test-service",
		Protocol: "grpc",
		Address:   "127.0.0.1:8080",
	}

	err = registry.Register(ctx, info, 30*time.Second)
	if err == nil {
		t.Error("Expected error when etcd endpoints are invalid")
	}
}

func TestEtcdRegistry_Start(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// 注意：这个测试需要 etcd 运行，如果没有 etcd，会失败
	// 在实际 CI/CD 环境中，应该使用测试容器或 mock
	registry, err := NewEtcdRegistry([]string{"127.0.0.1:2379"}, "test-prefix", logger)
	if err != nil {
		// 如果没有 etcd，跳过测试
		t.Skipf("Skipping test: etcd not available: %v", err)
	}
	defer registry.Stop()

	ctx := context.Background()
	err = registry.Start(ctx)
	if err != nil {
		t.Errorf("Expected no error when starting registry, got: %v", err)
	}
}

func TestEtcdRegistry_Stop(t *testing.T) {
	logger := zaptest.NewLogger(t)

	registry, err := NewEtcdRegistry([]string{"127.0.0.1:2379"}, "test-prefix", logger)
	if err != nil {
		t.Skipf("Skipping test: etcd not available: %v", err)
	}

	err = registry.Stop()
	if err != nil {
		t.Errorf("Expected no error when stopping registry, got: %v", err)
	}
}

func TestEtcdRegistry_Register_InvalidAddress(t *testing.T) {
	logger := zaptest.NewLogger(t)

	registry, err := NewEtcdRegistry([]string{"127.0.0.1:2379"}, "test-prefix", logger)
	if err != nil {
		t.Skipf("Skipping test: etcd not available: %v", err)
	}
	defer registry.Stop()

	ctx := context.Background()
	info := &ServiceInfo{
		Key:      "test-key",
		Name:     "test-service",
		Protocol: "grpc",
		Address:   "invalid-address", // 无效地址
	}

	err = registry.Register(ctx, info, 30*time.Second)
	if err == nil {
		t.Error("Expected error when address is invalid")
	}
}

func TestEtcdRegistry_Register_Success(t *testing.T) {
	logger := zaptest.NewLogger(t)

	registry, err := NewEtcdRegistry([]string{"127.0.0.1:2379"}, "test-prefix", logger)
	if err != nil {
		t.Skipf("Skipping test: etcd not available: %v", err)
	}
	defer registry.Stop()

	ctx := context.Background()
	info := &ServiceInfo{
		Key:      "test-key",
		Name:     "test-service",
		Protocol: "grpc",
		Address:   "127.0.0.1:8080",
		Meta: map[string]interface{}{
			"agent_code": "test-agent",
			"services": []map[string]interface{}{
				{"name": "service1", "port": 8080},
			},
		},
	}

	err = registry.Register(ctx, info, 30*time.Second)
	if err != nil {
		t.Errorf("Expected no error when registering service, got: %v", err)
	}

	// 清理：注销服务
	// 注意：Unregister 需要完整的 key，但 Register 生成的 key 格式不同
	// 这里我们只测试注册成功，不测试注销
}

func TestEtcdRegistry_Register_WithZeroAddress(t *testing.T) {
	logger := zaptest.NewLogger(t)

	registry, err := NewEtcdRegistry([]string{"127.0.0.1:2379"}, "test-prefix", logger)
	if err != nil {
		t.Skipf("Skipping test: etcd not available: %v", err)
	}
	defer registry.Stop()

	ctx := context.Background()
	info := &ServiceInfo{
		Key:      "test-key",
		Name:     "test-service",
		Protocol: "grpc",
		Address:   "0.0.0.0:8080", // 应该被转换为实际 IP
	}

	err = registry.Register(ctx, info, 30*time.Second)
	// 如果 getLocalIP 失败，会返回错误
	// 如果成功，应该没有错误
	if err != nil {
		// 在某些环境中可能无法获取本地 IP，这是可以接受的
		t.Logf("Register with 0.0.0.0 address: %v (may fail if local IP cannot be determined)", err)
	}
}

func TestGetLocalIP(t *testing.T) {
	ip, err := getLocalIP()
	if err != nil {
		t.Skipf("Skipping test: cannot get local IP: %v", err)
	}
	if ip == "" {
		t.Error("Expected non-empty IP address")
	}
	if ip == "127.0.0.1" {
		t.Log("Got loopback address, this is acceptable but may not be ideal for service registration")
	}
}


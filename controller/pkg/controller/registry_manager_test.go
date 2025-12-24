package controller

import (
	"context"
	"testing"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryManager(t *testing.T) {
	cleanupTestDataResourceManager(t)

	config, err := ProvideConfig("../../deploy/controller.yaml")
	require.NoError(t, err)

	// 创建 KeyManager
	km, err := ProvideKeyManager(config)
	require.NoError(t, err)

	// 创建 ResourceManager
	rm, err := ProvideResourceManager(km, config)
	require.NoError(t, err)
	defer rm.Stop()

	// 启动 ResourceManager
	err = rm.Start()
	require.NoError(t, err)

	// 创建etcdclient
	etcdClient, err := ProvideEtcdClient(config)
	require.NoError(t, err)
	defer etcdClient.Close()

	nm, err := ProvideNacosManager(config)
	require.NoError(t, err)

	// 创建ContainerManager
	cm, err := ProvideConfigManager(km, etcdClient, config, nm)
	require.NoError(t, err)
	err = cm.Start()
	defer cm.Stop()
	require.NoError(t, err)

	// 测试 RegisterService
	service := &models.ServiceInfo{
		Key:     "test-service-1",
		Name:    "TestService",
		Address: "localhost:8080",
	}

	mongoClient, err := ProvideDBClient(config)
	require.NoError(t, err)

	// 创建RegistryManager
	registryManager, err := ProvideRegistryManager(km, cm, mongoClient)
	require.NoError(t, err)
	err = registryManager.Start()
	require.NoError(t, err)
	defer registryManager.Stop()

	err = registryManager.RegisterService(service, time.Minute*1)
	assert.NoError(t, err)

	// 测试 GetService
	retrievedService, err := registryManager.GetService("test-service-1")
	assert.NoError(t, err)
	assert.Equal(t, service, retrievedService)

	// 测试 ListServices
	services := registryManager.ListServices()
	assert.Len(t, services, 1)
	assert.Equal(t, service, services[0])

	// 测试 UpdateServiceConfig
	newConfig := map[string]interface{}{
		"key": "value",
	}
	err = registryManager.UpdateServiceConfig("test-service-1", newConfig)
	assert.NoError(t, err)

	// 测试 WatchServices
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	eventChan, err := registryManager.WatchServices(ctx)
	require.NoError(t, err)

	// 使用 channel 来同步 goroutine
	done := make(chan bool)

	go func() {
		defer close(done)
		time.Sleep(2 * time.Second)
		t.Log("Unregistering service")
		err := registryManager.UnregisterService("test-service-1")
		assert.NoError(t, err)
		t.Log("Service unregistered")
	}()

	t.Log("Waiting for unregister event")
	select {
	case event := <-eventChan:
		t.Log("Received event")
		assert.Equal(t, models.ServiceEventTypeUnregistered, event.Type)
		assert.Equal(t, "test-service-1", event.Service.Key)
	case <-time.After(20 * time.Second):
		t.Fatal("Timeout waiting for unregister event")
	}

	// 等待 unregister 操作完成
	<-done

	// 验证服务已被删除
	_, err = registryManager.GetService("test-service-1")
	assert.Error(t, err)

	// 清理资源
	t.Log("Cleaning up resources")
	err = registryManager.Stop()
	assert.NoError(t, err)
	// err = configManager.Stop()
	// assert.NoError(t, err)

	t.Log("Test completed")

}

package sdk

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	controllerAddress = "http://192.168.100.122:8081"
	username          = "your_username"
	password          = "your_password"

	etcdEndpoint = "192.168.100.122:2379"
	testBase     = "test"
	testArea     = "area"
)

func TestClient_GetControllerStatus(t *testing.T) {
	client := NewClient(controllerAddress, username, password)
	status, err := client.GetControllerStatus()

	assert.NoError(t, err)
	assert.NotNil(t, status)
	// Add more specific assertions based on the actual response structure
}

func TestClient_GetDeployment(t *testing.T) {
	client := NewClient(controllerAddress, username, password)

	deployment, err := client.GetDeployment("abc-123-1008")

	assert.NoError(t, err)
	assert.NotNil(t, deployment)
	assert.Equal(t, "abc-123-1008", deployment.ID)
}

func TestClient_ListAgents(t *testing.T) {
	client := NewClient(controllerAddress, username, password)
	response, err := client.ListAgents(map[string]string{"id": "agent1"}, 1, 10)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	// Add more specific assertions based on the actual response
}

// func TestClient_GetPackageInstallStatus(t *testing.T) {
// 	client := NewClient(controllerAddress, username, password)
// 	status, err := client.GetPackageInstallStatus("service-123-464")

//		assert.NoError(t, err)
//		assert.NotNil(t, status)
//		// Add more specific assertions based on the actual response
//	}
func TestConfigDriver(t *testing.T) {
	endpoints := []string{etcdEndpoint}
	cd := NewConfigDriver(testBase, testArea, endpoints)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("PutAndGetConfig", func(t *testing.T) {
		t.Logf("Starting PutAndGetConfig test")
		err := cd.PutConfig(ctx, map[string]interface{}{
			"key1": "value1",
			"key2": 42,
		}, "test", "config")
		require.NoError(t, err)
		t.Logf("PutConfig completed successfully")

		config, err := cd.GetConfig(ctx, "test", "config")
		require.NoError(t, err)
		t.Logf("GetConfig completed successfully, retrieved config: %+v", config)

		assert.Equal(t, "value1", config["key1"])
		assert.Equal(t, float64(42), config["key2"])
		t.Logf("Assertions passed for PutAndGetConfig")
	})

	t.Run("GetNonExistentConfig", func(t *testing.T) {
		t.Logf("Starting GetNonExistentConfig test")
		config, err := cd.GetConfig(ctx, "non", "existent")
		require.NoError(t, err)
		t.Logf("GetConfig for non-existent key completed, retrieved config: %+v", config)
		assert.Empty(t, config)
		t.Logf("Assertion passed for GetNonExistentConfig")
	})

	t.Run("Enable", func(t *testing.T) {
		t.Logf("Starting Enable test")
		err := cd.Enable(ctx, true, "test", "enable")
		require.NoError(t, err)
		t.Logf("Enable(true) completed successfully")

		config, err := cd.GetConfig(ctx, "test", "enable")
		require.NoError(t, err)
		t.Logf("GetConfig after Enable(true) completed, retrieved config: %+v", config)
		assert.Equal(t, true, config["enabled"])

		err = cd.Enable(ctx, false, "test", "enable")
		require.NoError(t, err)
		t.Logf("Enable(false) completed successfully")

		config, err = cd.GetConfig(ctx, "test", "enable")
		require.NoError(t, err)
		t.Logf("GetConfig after Enable(false) completed, retrieved config: %+v", config)
		assert.Equal(t, false, config["enabled"])
		t.Logf("Assertions passed for Enable test")
	})
	t.Run("PutComplexConfig", func(t *testing.T) {
		t.Logf("Starting PutComplexConfig test")
		complexConfig := map[string]interface{}{
			"string": "value",
			"number": float64(42), // 使用 float64 而不是 int
			"bool":   true,
			"array":  []interface{}{"item1", "item2"}, // 使用 []interface{} 而不是 []string
			"object": map[string]interface{}{
				"nested": "value",
			},
		}

		err := cd.PutConfig(ctx, complexConfig, "test", "complex")
		require.NoError(t, err)
		t.Logf("PutConfig for complex config completed successfully")

		retrievedConfig, err := cd.GetConfig(ctx, "test", "complex")
		require.NoError(t, err)
		t.Logf("GetConfig for complex config completed, retrieved config: %+v", retrievedConfig)

		assert.Equal(t, complexConfig, retrievedConfig)
		t.Logf("Assertion passed for PutComplexConfig")
	})

	// 清理测试数据
	t.Cleanup(func() {
		t.Logf("Starting cleanup")
		cli, err := clientv3.New(clientv3.Config{
			Endpoints:   endpoints,
			DialTimeout: 5 * time.Second,
		})
		if err != nil {
			t.Logf("Failed to create etcd client for cleanup: %v", err)
			return
		}
		defer cli.Close()

		_, err = cli.Delete(context.Background(), cd.Add(testBase, testArea).Separator("/").String(), clientv3.WithPrefix())
		if err != nil {
			t.Logf("Failed to clean up test data: %v", err)
		} else {
			t.Logf("Cleanup completed successfully")
		}
	})
}

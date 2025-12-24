package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestConfigManager(t *testing.T) {
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

	resourceType := models.ResourceTypeTelegraf
	resourceID := "test-telegraf"

	t.Run("CRUD Operations", func(t *testing.T) {
		// 测试更新配置
		t.Run("UpdateConfig", func(t *testing.T) {
			config := map[string]interface{}{
				"key1": "value1",
				"key2": 42,
			}
			err := cm.UpdateConfig(resourceType, resourceID, config)
			require.NoError(t, err)
			t.Log("Config updated successfully")
		})

		// 测试获取配置
		t.Run("GetConfig", func(t *testing.T) {
			config, err := cm.GetConfig(resourceType, resourceID)
			require.NoError(t, err)
			assert.Equal(t, "value1", config["key1"])
			assert.Equal(t, float64(42), config["key2"])
			t.Log("Config retrieved successfully")
		})

		// 测试列出配置
		t.Run("ListConfigs", func(t *testing.T) {
			configs, err := cm.ListConfigKeys(resourceType)
			require.NoError(t, err)
			assert.NotEmpty(t, configs)
			assert.Contains(t, configs, fmt.Sprintf("%s.%s.%s", cm.KeyManager.config.FunctionArea, resourceType, resourceID))
			t.Log("Configs listed successfully")
		})

		t.Run("ContainerName", func(t *testing.T) {
			// 测试 Telegraf 资源类型
			telegrafContainerName, err := cm.ContainerName(models.ResourceTypeTelegraf)
			require.NoError(t, err)
			assert.NotEmpty(t, telegrafContainerName)
			t.Logf("Telegraf container name: %s", telegrafContainerName)

			// // 测试 Agent 资源类型
			// agentContainerName, err := cm.ContainerName(models.ResourceTypeAgent)
			// require.NoError(t, err)
			// assert.NotEmpty(t, agentContainerName)
			// t.Logf("Agent container name: %s", agentContainerName)

			// 测试未知资源类型
			unknownResourceType := models.ResourceType("unknown")
			_, err = cm.ContainerName(unknownResourceType)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "no container name found for resource type")
		})

		// 测试删除配置
		t.Run("DeleteConfig", func(t *testing.T) {
			err := cm.DeleteConfig(resourceType, resourceID)
			require.NoError(t, err)

			_, err = cm.GetConfig(resourceType, resourceID)
			assert.Error(t, err)
			t.Log("Config deleted successfully")
		})

		t.Run("Stop", func(t *testing.T) {
			key, _ := rm.KeyManager.GenerateResourceKey(string(models.ResourceTypeEtcd), "test-etcd")
			err := rm.StopResource(key)
			assert.NoError(t, err)

			// 等待一段时间确保服务停止
			time.Sleep(2 * time.Second)

			status, err := rm.GetResourceInfo(key)
			assert.NoError(t, err)
			assert.Equal(t, "exited", status.Status)
		})

		t.Log("ConfigManager stopped")
	})
}

func cleanupExistingEtcdContainer(t *testing.T) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cli.Close()

	containers, err := cli.ContainerList(ctx, container.ListOptions{All: true})
	require.NoError(t, err)

	for _, c := range containers {
		for _, name := range c.Names {
			if name == "/test-etcd" {
				err := cli.ContainerRemove(ctx, c.ID, container.RemoveOptions{Force: true})
				require.NoError(t, err)
				t.Log("Removed existing test-etcd container")
				return
			}
		}
	}
}

func startEtcdContainer(t *testing.T, rm *ResourceManager, containerName string) (string, error) {
	config := map[string]interface{}{
		"image":   "quay.io/coreos/etcd:v3.5.0",
		"command": "/usr/local/bin/etcd --advertise-client-urls http://0.0.0.0:2379 --listen-client-urls http://0.0.0.0:2379",
		"ports": map[string]interface{}{
			"2379/tcp": 2379,
		},
		"environment": []string{
			"ETCD_NAME=test-etcd",
			"ETCD_DATA_DIR=/etcd-data",
		},
		"volumes": map[string]interface{}{
			"/tmp/etcd-data": map[string]interface{}{
				"bind": "/etcd-data",
				"mode": "rw",
			},
		},
	}

	key, err := rm.CreateResource(models.ResourceTypeEtcd, containerName, config, true)
	if err != nil {
		return "", fmt.Errorf("failed to create etcd container: %v", err)
	}

	// 等待容器启动
	time.Sleep(5 * time.Second)

	return key, nil
}

func stopAndRemoveContainer(t *testing.T, rm *ResourceManager, key string) {
	err := rm.DeleteResource(key)
	require.NoError(t, err, "Failed to stop and remove etcd container")
}

func waitForEtcdReady(t *testing.T) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	retries := 0
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for etcd to be ready after %d retries", retries)
		default:
			client, err := clientv3.New(clientv3.Config{
				Endpoints:   []string{"localhost:2379"},
				DialTimeout: 2 * time.Second,
			})
			if err == nil {
				defer client.Close()
				_, err = client.Put(ctx, "test-key", "test-value")
				if err == nil {
					t.Logf("etcd is ready after %d retries", retries)
					return nil
				}
			}
			retries++
			t.Logf("Waiting for etcd to be ready (retry %d): %v", retries, err)
			time.Sleep(2 * time.Second)
		}
	}
}
func cleanupTestData(t *testing.T, cm *ConfigManager) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 删除所有以 "/configs/" 开头的键
	resp, err := cm.EtcdClient.Delete(ctx, "/configs/", clientv3.WithPrefix())
	require.NoError(t, err, "Failed to clean up test data")
	t.Logf("Cleaned up %d keys", resp.Deleted)
}

func printDockerInfo(t *testing.T) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cli.Close()

	info, err := cli.Info(ctx)
	require.NoError(t, err)
	t.Logf("Docker version: %s", info.ServerVersion)
	t.Logf("Total memory: %d", info.MemTotal)
	t.Logf("NCPU: %d", info.NCPU)
}

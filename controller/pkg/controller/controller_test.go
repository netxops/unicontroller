package controller

import (
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestController(t *testing.T) {
	// 清理测试数据
	cleanupTestDataResourceManager(t)
	// 初始化 Controller
	configPath := "../../deploy/controller.yaml"
	controller, err := InitializeControllerComponents(configPath)
	require.NoError(t, err)
	require.NotNil(t, controller)

	// 测试 Start 方法
	t.Run("Start", func(t *testing.T) {
		err := controller.Start()
		assert.NoError(t, err)
	})

	// 测试 CreateResource 方法
	t.Run("CreateResource", func(t *testing.T) {
		resourceType := models.ResourceTypeContainer
		resourceID := "test-nginx"
		config := map[string]interface{}{
			"key":   "value",
			"image": "nginx:latest",
		}
		err := controller.CreateResource(resourceType, resourceID, config)
		assert.NoError(t, err)
	})

	// 测试 GetConfig 方法
	t.Run("GetConfig", func(t *testing.T) {
		resourceType := models.ResourceTypeContainer
		resourceID := "test-nginx"
		config, err := controller.GetConfig(resourceType, resourceID)
		assert.NoError(t, err)
		assert.NotNil(t, config)
		assert.Equal(t, "value", config["key"])
	})

	// 测试 UpdateConfig 方法
	t.Run("UpdateConfig", func(t *testing.T) {
		resourceType := models.ResourceTypeContainer
		resourceID := "test-nginx"
		newConfig := map[string]interface{}{
			"key": "new-value",
		}
		err := controller.UpdateConfig(resourceType, resourceID, newConfig)
		assert.NoError(t, err)

		// 验证更新是否成功
		updatedConfig, err := controller.GetConfig(resourceType, resourceID)
		assert.NoError(t, err)
		assert.Equal(t, "new-value", updatedConfig["key"])
	})

	// 测试 ListConfigs 方法
	t.Run("ListConfigs", func(t *testing.T) {
		resourceType := models.ResourceTypeContainer
		configs, err := controller.ListConfigs(resourceType)
		assert.NoError(t, err)
		assert.Contains(t, configs, "test-nginx")
	})

	// 测试 GetResourceStatus 方法
	t.Run("GetResourceStatus", func(t *testing.T) {
		resourceType := models.ResourceTypeContainer
		resourceID := "test-nginx"
		status, err := controller.GetResourceStatus(resourceType, resourceID)
		assert.NoError(t, err)
		assert.NotEmpty(t, status)
	})

	// 测试 DeleteResource 方法
	t.Run("DeleteResource", func(t *testing.T) {
		resourceType := models.ResourceTypeContainer
		resourceID := "test-nginx"
		err := controller.DeleteResource(resourceType, resourceID)
		assert.NoError(t, err)

		// 验证资源是否已被删除
		_, err = controller.GetConfig(resourceType, resourceID)
		assert.Error(t, err)
	})

	// 测试 Stop 方法
	t.Run("Stop", func(t *testing.T) {
		err := controller.Stop()
		assert.NoError(t, err)
	})
}

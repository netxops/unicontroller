// package controller

// import (
// 	"context"
// 	"fmt"
// 	"os/exec"
// 	"testing"
// 	"time"

// 	"github.com/docker/docker/api/types/container"
// 	"github.com/docker/docker/client"
// 	"github.com/influxdata/telegraf/controller/pkg/controller/models"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"
// )

// func TestResourceManager(t *testing.T) {
// 	// 在测试开始前拉取需要的镜像
// 	images := []string{"nginx:latest", "nginx:alpine"}
// 	for _, image := range images {
// 		cmd := exec.Command("docker", "pull", image)
// 		err := cmd.Run()
// 		require.NoError(t, err, "Failed to pull image: "+image)
// 	}

// 	// 创建 Docker 客户端
// 	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
// 	require.NoError(t, err)
// 	defer cli.Close()

// 	// 清理现有的测试容器
// 	containers, err := cli.ContainerList(context.Background(), container.ListOptions{All: true})
// 	require.NoError(t, err)
// 	for _, c := range containers {
// 		if c.Names[0] == "/test-container" {
// 			err := cli.ContainerRemove(context.Background(), c.ID, container.RemoveOptions{Force: true})
// 			require.NoError(t, err)
// 		}
// 	}

// 	// 创建一个新的 ResourceManager
// 	rm, err := NewResourceManager(&Config{
// 		Region: "test_region",
// 	})
// 	require.NoError(t, err)
// 	defer rm.Stop()

// 	// 启动 ResourceManager
// 	err = rm.Start()
// 	require.NoError(t, err)

// 	var resourceKey string

// 	// 测试创建资源
// 	t.Run("CreateResource", func(t *testing.T) {
// 		var err error
// 		resourceKey, err = rm.CreateResource(models.ResourceTypeContainer, "test-container", map[string]interface{}{
// 			"image": "nginx:latest",
// 		}, true)
// 		require.NoError(t, err)
// 		assert.NotEmpty(t, resourceKey)

// 		err = waitForContainerStatus(rm, resourceKey, "running", 10*time.Second)
// 		require.NoError(t, err)

// 		status, err := rm.GetResourceStatus(resourceKey)
// 		require.NoError(t, err)
// 		assert.Equal(t, "running", status)
// 	})

// 	t.Log("Resource created successfully")

// 	// 测试列出所有资源
// 	t.Run("ListAllResources", func(t *testing.T) {
// 		resources := rm.ListAllResources()
// 		assert.NotEmpty(t, resources)
// 	})

// 	// 测试获取所有资源状态
// 	t.Run("GetAllResourcesStatus", func(t *testing.T) {
// 		statuses := rm.GetAllResourcesStatus()
// 		assert.NotEmpty(t, statuses)
// 	})

// 	// 测试停止资源
// 	t.Run("StopResource", func(t *testing.T) {
// 		err := rm.StopResource(resourceKey)
// 		require.NoError(t, err)

// 		err = waitForContainerStatus(rm, resourceKey, "exited", 10*time.Second)
// 		require.NoError(t, err)

// 		status, err := rm.GetResourceStatus(resourceKey)
// 		require.NoError(t, err)
// 		assert.Equal(t, "exited", status)
// 	})

// 	t.Log("Resource stopped successfully")

// 	// 测试启动资源
// 	t.Run("StartResource", func(t *testing.T) {
// 		err := rm.StartResource(resourceKey)
// 		require.NoError(t, err)

// 		err = waitForContainerStatus(rm, resourceKey, "running", 10*time.Second)
// 		require.NoError(t, err)

// 		status, err := rm.GetResourceStatus(resourceKey)
// 		require.NoError(t, err)
// 		assert.Equal(t, "running", status)
// 	})

// 	t.Log("Resource started successfully")

// 	// 测试重启资源
// 	t.Run("RestartResource", func(t *testing.T) {
// 		err := rm.RestartResource(resourceKey)
// 		require.NoError(t, err)

// 		err = waitForContainerStatus(rm, resourceKey, "running", 10*time.Second)
// 		require.NoError(t, err)

// 		status, err := rm.GetResourceStatus(resourceKey)
// 		require.NoError(t, err)
// 		assert.Equal(t, "running", status)
// 	})

// 	t.Log("Resource restarted successfully")

// 	// 测试更新资源
// 	t.Run("UpdateResource", func(t *testing.T) {
// 		// 确保容器正在运行
// 		err := waitForContainerStatus(rm, resourceKey, "running", 30*time.Second)
// 		require.NoError(t, err)

// 		t.Log("Container is running before update")

// 		newID, err := rm.UpdateResource(resourceKey, map[string]interface{}{
// 			"image": "nginx:alpine",
// 		})
// 		require.NoError(t, err)

// 		t.Log("Resource update command sent, new container ID:", newID)

// 		// 使用新的容器 ID 等待状态
// 		err = waitForContainerStatus(rm, resourceKey, "running", 120*time.Second)
// 		require.NoError(t, err)

// 		t.Log("Container is running after update")

// 		info, err := rm.GetResourceInfo(resourceKey)
// 		require.NoError(t, err)
// 		assert.Equal(t, "nginx:alpine", info.Metadata["image"])
// 		assert.Equal(t, newID, info.ID)

// 		// 验证容器正在运行
// 		status, err := rm.GetResourceStatus(resourceKey)
// 		require.NoError(t, err)
// 		assert.Equal(t, "running", status)

// 		t.Log("Resource updated and verified successfully")
// 	})

// 	t.Log("Resource updated successfully")

// 	// 测试删除资源
// 	t.Run("DeleteResource", func(t *testing.T) {
// 		// 确保资源存在
// 		_, err := rm.GetResourceInfo(resourceKey)
// 		require.NoError(t, err)

// 		err = rm.DeleteResource(resourceKey)
// 		require.NoError(t, err)

// 		err = waitForContainerDeletion(rm, resourceKey, 10*time.Second)
// 		require.NoError(t, err)

// 		_, err = rm.GetResourceInfo(resourceKey)
// 		assert.Error(t, err)
// 	})

// 	t.Log("Resource deleted successfully")
// }

// func waitForContainerStatus(rm *ResourceManager, key string, expectedStatus string, timeout time.Duration) error {
// 	start := time.Now()
// 	for {
// 		status, err := rm.GetResourceStatus(key)
// 		if err == nil && status == expectedStatus {
// 			return nil
// 		}
// 		if time.Since(start) > timeout {
// 			return fmt.Errorf("timeout waiting for container status to be %s, current status: %s", expectedStatus, status)
// 		}
// 		time.Sleep(1 * time.Second)
// 	}
// }

// func waitForContainerDeletion(rm *ResourceManager, key string, timeout time.Duration) error {
// 	start := time.Now()
// 	for {
// 		_, err := rm.GetResourceInfo(key)
// 		if err != nil {
// 			return nil // 容器已被删除
// 		}
// 		if time.Since(start) > timeout {
// 			return fmt.Errorf("timeout waiting for container deletion")
// 		}
// 		time.Sleep(1 * time.Second)
// 	}
// }

package controller

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResourceManager(t *testing.T) {
	// 清理数据
	cleanupTestDataResourceManager(t)

	// 在测试开始前拉取需要的镜像
	images := []string{"nginx:latest", "nginx:alpine"}
	for _, image := range images {
		cmd := exec.Command("docker", "pull", image)
		err := cmd.Run()
		require.NoError(t, err, "Failed to pull image: "+image)
	}

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

	var resourceKey string

	// 测试创建资源
	t.Run("CreateResource", func(t *testing.T) {
		var err error
		resourceKey, err = rm.CreateResource(models.ResourceTypeContainer, "test-container", map[string]interface{}{
			"image": "nginx:latest",
		}, true)
		require.NoError(t, err)
		assert.NotEmpty(t, resourceKey)

		err = waitForContainerStatus(rm, resourceKey, "running", 10*time.Second)
		require.NoError(t, err)

		status, err := rm.GetResourceStatus(resourceKey)
		require.NoError(t, err)
		assert.Equal(t, "running", status)
	})

	t.Log("Resource created successfully")

	// 测试列出所有资源
	t.Run("ListAllResources", func(t *testing.T) {
		resources := rm.ListAllResources()
		assert.NotEmpty(t, resources)
	})

	// 测试获取所有资源状态
	t.Run("GetAllResourcesStatus", func(t *testing.T) {
		statuses := rm.GetAllResourcesStatus()
		assert.NotEmpty(t, statuses)
	})

	// 测试停止资源
	t.Run("StopResource", func(t *testing.T) {
		err := rm.StopResource(resourceKey)
		require.NoError(t, err)

		err = waitForContainerStatus(rm, resourceKey, "exited", 10*time.Second)
		require.NoError(t, err)

		status, err := rm.GetResourceStatus(resourceKey)
		require.NoError(t, err)
		assert.Equal(t, "exited", status)
	})

	t.Log("Resource stopped successfully")

	// 测试启动资源
	t.Run("StartResource", func(t *testing.T) {
		err := rm.StartResource(resourceKey)
		require.NoError(t, err)

		err = waitForContainerStatus(rm, resourceKey, "running", 10*time.Second)
		require.NoError(t, err)

		status, err := rm.GetResourceStatus(resourceKey)
		require.NoError(t, err)
		assert.Equal(t, "running", status)
	})

	t.Log("Resource started successfully")

	// 测试重启资源
	t.Run("RestartResource", func(t *testing.T) {
		err := rm.RestartResource(resourceKey)
		require.NoError(t, err)

		err = waitForContainerStatus(rm, resourceKey, "running", 10*time.Second)
		require.NoError(t, err)

		status, err := rm.GetResourceStatus(resourceKey)
		require.NoError(t, err)
		assert.Equal(t, "running", status)
	})

	t.Log("Resource restarted successfully")

	// // 测试更新资源
	// t.Run("UpdateResource", func(t *testing.T) {
	// 	// 确保容器正在运行
	// 	err := waitForContainerStatus(rm, resourceKey, "running", 30*time.Second)
	// 	require.NoError(t, err)

	// 	t.Log("Container is running before update")

	// 	newID, err := rm.UpdateResource(resourceKey, map[string]interface{}{
	// 		"image": "nginx:alpine",
	// 	})
	// 	require.NoError(t, err)

	// 	t.Log("Resource update command sent, new container ID:", newID)

	// 	// 使用新的容器 ID 等待状态
	// 	err = waitForContainerStatus(rm, resourceKey, "running", 120*time.Second)
	// 	require.NoError(t, err)

	// 	t.Log("Container is running after update")

	// 	info, err := rm.GetResourceInfo(resourceKey)
	// 	require.NoError(t, err)
	// 	assert.Equal(t, "nginx:alpine", info.Metadata["image"])
	// 	assert.Equal(t, newID, info.ContainerID)

	// 	// 验证容器正在运行
	// 	status, err := rm.GetResourceStatus(resourceKey)
	// 	require.NoError(t, err)
	// 	assert.Equal(t, "running", status)

	// 	t.Log("Resource updated and verified successfully")
	// })

	// t.Log("Resource updated successfully")

	// 测试删除资源
	t.Run("DeleteResource", func(t *testing.T) {
		_, err := rm.GetResourceInfo(resourceKey)
		require.NoError(t, err)

		err = rm.DeleteResource(resourceKey)
		require.NoError(t, err)

		err = waitForContainerDeletion(rm, resourceKey, 10*time.Second)

		require.NoError(t, err)

		_, err = rm.GetResourceInfo(resourceKey)
		assert.Error(t, err)
	})

	t.Log("Resource deleted successfully")
}

func waitForContainerStatus(rm *ResourceManager, key string, expectedStatus string, timeout time.Duration) error {
	start := time.Now()
	for {
		status, err := rm.GetResourceStatus(key)
		if err == nil && status == expectedStatus {
			return nil
		}
		if err != nil {
			log.Printf("Error getting resource status: %v", err)
		}
		if time.Since(start) > timeout {
			return fmt.Errorf("timeout waiting for container status to be %s, current status: %s, error: %v", expectedStatus, status, err)
		}
		time.Sleep(1 * time.Second)
	}
}

func waitForContainerDeletion(rm *ResourceManager, key string, timeout time.Duration) error {
	start := time.Now()
	for {
		_, err := rm.GetResourceInfo(key)
		if err != nil {
			return nil // 容器已被删除
		}
		if time.Since(start) > timeout {
			return fmt.Errorf("timeout waiting for container deletion")
		}
		time.Sleep(1 * time.Second)
	}
}

func cleanupTestDataResourceManager(t *testing.T) {
	// 创建 Docker 客户端
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cli.Close()

	// 列出所有容器
	containers, err := cli.ContainerList(context.Background(), container.ListOptions{All: true})
	require.NoError(t, err)

	for _, c := range containers {
		if strings.HasPrefix(c.Names[0], "/test-") {
			err := cli.ContainerRemove(context.Background(), c.ID, container.RemoveOptions{Force: true})
			require.NoError(t, err)
			t.Log("Removed existing test container:", c.ID)
		}
	}

	// 如果使用了数据库，可以在这里添加清理数据库的代码
	// 例如：
	// err = global.DB.Exec("DELETE FROM resources WHERE name = ?", "test-container").Error
	// require.NoError(t, err)

	t.Log("Test data cleanup completed")
}

// func retry(attempts int, sleep time.Duration, f func() error) (err error) {
// 	for i := 0; ; i++ {
// 		err = f()
// 		if err == nil {
// 			return
// 		}
// 		if i >= (attempts - 1) {
// 			break
// 		}
// 		time.Sleep(sleep)
// 		log.Printf("retrying after error: %v", err)
// 	}
// 	return fmt.Errorf("after %d attempts, last error: %s", attempts, err)
// }

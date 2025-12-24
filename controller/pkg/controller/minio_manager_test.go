package controller

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/controller/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMinioManager(t *testing.T) {
	cleanupTestDataResourceManager(t)

	config, err := ProvideConfig("../../deploy/controller.yaml")
	require.NoError(t, err)

	t.Logf("Minio Config: %+v", config.Minio)

	km, err := ProvideKeyManager(config)
	require.NoError(t, err)

	rm, err := ProvideResourceManager(km, config)
	require.NoError(t, err)
	t.Cleanup(func() { rm.Stop() })
	err = rm.Start()
	require.NoError(t, err)

	etcdClient, err := ProvideEtcdClient(config)
	require.NoError(t, err)
	t.Cleanup(func() { etcdClient.Close() })

	nm, err := ProvideNacosManager(config)
	require.NoError(t, err)

	cm, err := ProvideConfigManager(km, etcdClient, config, nm)
	require.NoError(t, err)
	err = cm.Start()
	require.NoError(t, err)
	t.Cleanup(func() { cm.Stop() })

	mongoClient, err := ProvideDBClient(config)
	require.NoError(t, err)

	registry, err := ProvideRegistryManager(km, cm, mongoClient)
	require.NoError(t, err)
	err = registry.Start()
	require.NoError(t, err)
	t.Cleanup(func() { registry.Stop() })

	mm, err := ProvideMinioManager(km, cm, registry)
	require.NoError(t, err)
	t.Cleanup(func() { mm.Stop() })

	// 辅助函数：等待服务启动
	waitForService := func(url string, timeout time.Duration) error {
		start := time.Now()
		for time.Since(start) < timeout {
			_, err := http.Get(url)
			if err == nil {
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return fmt.Errorf("service did not start within %v", timeout)
	}

	t.Run("Start", func(t *testing.T) {
		err := mm.Start()
		require.NoError(t, err)

		// 等待一小段时间，确保服务有足够的时间注册
		time.Sleep(50 * time.Second)

		info, err := registry.FirstByName(string(models.ServiceNameMinioProxy))
		require.NoError(t, err)
		assert.Equal(t, string(models.ServiceNameMinioProxy), info.Name)

		// 从服务信息中提取主机和端口
		host, port, err := net.SplitHostPort(info.Address)
		require.NoError(t, err)

		// 构建健康检查 URL
		healthCheckURL := fmt.Sprintf("http://%s:%s/health", host, port)

		err = waitForService(healthCheckURL, 10*time.Second)
		require.NoError(t, err, "Minio proxy did not start in time")

		// 额外的验证
		assert.NotEmpty(t, info.Address, "Service address should not be empty")
		// assert.Equal(t, models.ResourceStatusRunning, info.Status, "Service status should be running")
	})
	t.Run("UploadAndDownloadFile", func(t *testing.T) {
		bucketName := config.Minio.BucketName
		objectName := "test-object"
		content := []byte("Hello, Minio!")

		info, err := registry.FirstByName(string(models.ServiceNameMinioProxy))
		require.NoError(t, err)
		assert.Equal(t, string(models.ServiceNameMinioProxy), info.Name)

		// 上传文件
		req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("http://%s/%s/%s", info.Address, bucketName, objectName), bytes.NewReader(content))
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		t.Logf("Upload response: %s", string(body))
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// 添加延迟确保文件已上传
		time.Sleep(1 * time.Second)

		// 检查文件是否存在
		headReq, err := http.NewRequest(http.MethodHead, fmt.Sprintf("http://%s/%s/%s", info.Address, bucketName, objectName), nil)
		require.NoError(t, err)
		headResp, err := http.DefaultClient.Do(headReq)
		require.NoError(t, err)
		defer headResp.Body.Close()
		assert.Equal(t, http.StatusOK, headResp.StatusCode, "File should exist after upload")

		// 下载文件
		resp, err = http.Get(fmt.Sprintf("http://%s/%s/%s", info.Address, bucketName, objectName))
		require.NoError(t, err)
		defer resp.Body.Close()
		downloadedContent, err := ioutil.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, content, downloadedContent)
	})

	t.Run("DeleteObject", func(t *testing.T) {
		bucketName := config.Minio.BucketName
		objectName := "test-object"

		info, err := registry.FirstByName(string(models.ServiceNameMinioProxy))
		require.NoError(t, err)
		assert.Equal(t, string(models.ServiceNameMinioProxy), info.Name)

		req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("http://%s/%s/%s", info.Address, bucketName, objectName), nil)
		require.NoError(t, err)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		t.Logf("Delete response: %s", string(body))
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)

		// 添加延迟确保删除操作完成
		time.Sleep(1 * time.Second)

		// 验证对象已被删除
		resp, err = http.Get(fmt.Sprintf("http://%s/%s/%s", info.Address, bucketName, objectName))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		if resp.StatusCode != http.StatusNotFound {
			body, _ := ioutil.ReadAll(resp.Body)
			t.Logf("Unexpected response after delete: %s", string(body))
		}
	})

	// t.Run("GetStatus", func(t *testing.T) {
	// 	status, err := mm.GetStatus()
	// 	assert.NoError(t, err)
	// 	assert.Equal(t, models.ResourceStatusRunning, status)
	// })

	t.Run("Stop", func(t *testing.T) {
		err := mm.Stop()
		assert.NoError(t, err)

		time.Sleep(2 * time.Second)

		info, err := registry.FirstByName(string(models.ServiceNameMinioProxy))
		require.NoError(t, err)
		assert.Equal(t, string(models.ServiceNameMinioProxy), info.Name)

		_, err = http.Get(fmt.Sprintf("http://%s/health", info.Address))
		assert.Error(t, err, "Expected error after stopping Minio proxy")
	})
}

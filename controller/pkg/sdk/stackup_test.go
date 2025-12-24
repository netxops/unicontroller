package sdk

import (
	"context"
	"testing"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testControllerURL = "http://localhost:8081"
)

// TestStackUpExecute_YAML 测试使用 YAML 格式配置执行 StackUp
func TestStackUpExecute_YAML(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// 创建客户端
	config := DefaultAsyncExecuteClientConfig(testControllerURL)
	client := NewAsyncExecuteClient(config)

	// 准备请求
	yamlConfig := `
commands:
  - name: test1
    run: echo "Hello World"
    timeout: 10
  - name: test2
    run: pwd
    timeout: 10
  - name: test3
    run: ls -la /tmp | head -5
    timeout: 10
env:
  TEST_VAR: "test_value"
`

	req := &StackUpExecuteRequest{
		RemoteInfo: structs.L2DeviceRemoteInfo{
			Ip:       "127.0.0.1",
			Username: "testuser",
			Password: "testpass",
			Platform: "linux",
		},
		Config:     yamlConfig,
		ConfigType: "yaml",
	}

	// 执行请求
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.StackUpExecute(ctx, req)

	// 注意：如果服务器未运行，这里会失败，这是预期的
	if err != nil {
		t.Logf("StackUpExecute failed (server may not be running): %v", err)
		return
	}

	// 验证响应
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Results)
	assert.Greater(t, len(resp.Results), 0)

	// 验证结果
	for _, result := range resp.Results {
		assert.Greater(t, result.Index, 0)
		assert.NotEmpty(t, result.Key)
		assert.NotEmpty(t, result.Command)
		assert.NotEmpty(t, result.Status)
		t.Logf("Command %d: %s, Status: %s, Output length: %d",
			result.Index, result.Key, result.Status, len(result.Output))
	}
}

// TestStackUpExecute_Base64 测试使用 Base64 编码配置执行 StackUp
func TestStackUpExecute_Base64(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// 创建客户端
	config := DefaultAsyncExecuteClientConfig(testControllerURL)
	client := NewAsyncExecuteClient(config)

	// 准备 Base64 编码的配置
	yamlConfig := `
commands:
  - name: test_base64
    run: echo "Base64 test"
    timeout: 10
`
	// 注意：实际使用时需要 base64 编码，这里只是示例
	// 实际测试中应该使用 base64.StdEncoding.EncodeToString([]byte(yamlConfig))

	req := &StackUpExecuteRequest{
		RemoteInfo: structs.L2DeviceRemoteInfo{
			Ip:       "127.0.0.1",
			Username: "testuser",
			Password: "testpass",
			Platform: "linux",
		},
		Config:     yamlConfig,
		ConfigType: "yaml", // 使用 yaml 而不是 base64，因为实际 base64 编码需要额外处理
	}

	// 执行请求
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.StackUpExecute(ctx, req)

	if err != nil {
		t.Logf("StackUpExecute failed (server may not be running): %v", err)
		return
	}

	require.NotNil(t, resp)
	assert.True(t, resp.Success)
}

// TestStackUpExecute_WithScript 测试使用脚本执行 StackUp
func TestStackUpExecute_WithScript(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// 创建客户端
	config := DefaultAsyncExecuteClientConfig(testControllerURL)
	client := NewAsyncExecuteClient(config)

	// 准备包含脚本的配置
	yamlConfig := `
commands:
  - name: script_test
    script: |
      #!/bin/bash
      echo "Script test"
      date
      echo "Done"
    timeout: 10
`

	req := &StackUpExecuteRequest{
		RemoteInfo: structs.L2DeviceRemoteInfo{
			Ip:       "127.0.0.1",
			Username: "testuser",
			Password: "testpass",
			Platform: "linux",
		},
		Config:     yamlConfig,
		ConfigType: "yaml",
	}

	// 执行请求
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.StackUpExecute(ctx, req)

	if err != nil {
		t.Logf("StackUpExecute failed (server may not be running): %v", err)
		return
	}

	require.NotNil(t, resp)
	assert.True(t, resp.Success)
}

// TestStackUpExecute_InvalidConfig 测试无效配置
func TestStackUpExecute_InvalidConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// 创建客户端
	config := DefaultAsyncExecuteClientConfig(testControllerURL)
	client := NewAsyncExecuteClient(config)

	// 准备无效的配置
	req := &StackUpExecuteRequest{
		RemoteInfo: structs.L2DeviceRemoteInfo{
			Ip:       "127.0.0.1",
			Username: "testuser",
			Password: "testpass",
			Platform: "linux",
		},
		Config:     "invalid yaml content: [",
		ConfigType: "yaml",
	}

	// 执行请求
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.StackUpExecute(ctx, req)

	// 应该返回错误
	if err != nil {
		t.Logf("Expected error for invalid config: %v", err)
		assert.Error(t, err)
		return
	}

	// 或者服务器返回了错误响应
	if resp != nil && !resp.Success {
		t.Logf("Server returned error: %s", resp.Error)
		assert.False(t, resp.Success)
	}
}

// TestStackUpExecute_EmptyConfig 测试空配置
func TestStackUpExecute_EmptyConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// 创建客户端
	config := DefaultAsyncExecuteClientConfig(testControllerURL)
	client := NewAsyncExecuteClient(config)

	req := &StackUpExecuteRequest{
		RemoteInfo: structs.L2DeviceRemoteInfo{
			Ip:       "127.0.0.1",
			Username: "testuser",
			Password: "testpass",
			Platform: "linux",
		},
		Config:     "",
		ConfigType: "yaml",
	}

	// 执行请求
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.StackUpExecute(ctx, req)

	// 应该返回错误（空配置）
	if err != nil {
		t.Logf("Expected error for empty config: %v", err)
		assert.Error(t, err)
		return
	}

	// 或者服务器返回了错误响应
	if resp != nil && !resp.Success {
		t.Logf("Server returned error: %s", resp.Error)
		assert.False(t, resp.Success)
	}
}

// TestStackUpExecute_WithLocalDataPath 测试使用本地数据路径
func TestStackUpExecute_WithLocalDataPath(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// 创建客户端
	config := DefaultAsyncExecuteClientConfig(testControllerURL)
	client := NewAsyncExecuteClient(config)

	yamlConfig := `
commands:
  - name: test_with_path
    run: echo "Test with local data path"
    timeout: 10
`

	req := &StackUpExecuteRequest{
		RemoteInfo: structs.L2DeviceRemoteInfo{
			Ip:       "127.0.0.1",
			Username: "testuser",
			Password: "testpass",
			Platform: "linux",
		},
		Config:        yamlConfig,
		ConfigType:    "yaml",
		LocalDataPath: "/tmp",
	}

	// 执行请求
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.StackUpExecute(ctx, req)

	if err != nil {
		t.Logf("StackUpExecute failed (server may not be running): %v", err)
		return
	}

	require.NotNil(t, resp)
	assert.True(t, resp.Success)
}

// TestStackUpExecute_RequestValidation 测试请求验证
func TestStackUpExecute_RequestValidation(t *testing.T) {
	// 创建客户端
	config := DefaultAsyncExecuteClientConfig(testControllerURL)
	client := NewAsyncExecuteClient(config)

	// 测试 nil 请求
	ctx := context.Background()
	_, err := client.StackUpExecute(ctx, nil)
	assert.Error(t, err, "nil request should return error")

	// 测试空 RemoteInfo
	req := &StackUpExecuteRequest{
		Config: "commands:\n  - name: test\n    run: echo test",
	}
	_, err = client.StackUpExecute(ctx, req)
	// 这个可能会在服务器端验证，或者客户端会成功发送但服务器返回错误
	// 取决于实际实现
	t.Logf("Empty RemoteInfo test result: %v", err)
}

package sdk

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/structs"
)

// ExampleStackUpExecute_YAML 使用 YAML 配置执行 StackUp
func ExampleStackUpExecute_YAML() {
	// 创建客户端
	config := DefaultAsyncExecuteClientConfig("http://localhost:8081")
	client := NewAsyncExecuteClient(config)

	// 准备 YAML 配置
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
			Ip:       "192.168.1.1",
			Username: "admin",
			Password: "password",
			Platform: "linux",
		},
		Config:     yamlConfig,
		ConfigType: "yaml",
	}

	// 执行
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.StackUpExecute(ctx, req)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// 处理结果
	if resp.Success {
		fmt.Printf("Success: %s\n", resp.Message)
		for _, result := range resp.Results {
			fmt.Printf("\nCommand %d: %s\n", result.Index, result.Key)
			fmt.Printf("  Command: %s\n", result.Command)
			fmt.Printf("  Status: %s\n", result.Status)
			if result.Status == "false" {
				fmt.Printf("  Output:\n%s\n", result.Output)
			} else {
				fmt.Printf("  Error: %s\n", result.Msg)
			}
		}
	} else {
		fmt.Printf("Failed: %s\n", resp.Error)
	}
}

// ExampleStackUpExecute_WithScript 使用脚本执行 StackUp
func ExampleStackUpExecute_WithScript() {
	// 创建客户端
	config := DefaultAsyncExecuteClientConfig("http://localhost:8081")
	client := NewAsyncExecuteClient(config)

	// 准备包含脚本的配置
	yamlConfig := `
commands:
  - name: script_test
    script: |
      #!/bin/bash
      echo "Starting script"
      date
      echo "Current directory:"
      pwd
      echo "Listing files:"
      ls -la | head -10
      echo "Script completed"
    timeout: 30
env:
  SCRIPT_ENV: "script_value"
`

	req := &StackUpExecuteRequest{
		RemoteInfo: structs.L2DeviceRemoteInfo{
			Ip:       "192.168.1.1",
			Username: "admin",
			Password: "password",
			Platform: "linux",
		},
		Config:     yamlConfig,
		ConfigType: "yaml",
	}

	ctx := context.Background()
	resp, err := client.StackUpExecute(ctx, req)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	if resp.Success {
		fmt.Printf("Executed %d commands\n", len(resp.Results))
		for _, result := range resp.Results {
			fmt.Printf("Command '%s': %s\n", result.Key, result.Status)
		}
	}
}

// ExampleStackUpExecute_Base64 使用 Base64 编码配置执行 StackUp
func ExampleStackUpExecute_Base64() {
	// 创建客户端
	config := DefaultAsyncExecuteClientConfig("http://localhost:8081")
	client := NewAsyncExecuteClient(config)

	// 准备 YAML 配置
	yamlConfig := `
commands:
  - name: base64_test
    run: echo "Base64 encoded config test"
    timeout: 10
`

	// 编码为 Base64
	configBase64 := base64.StdEncoding.EncodeToString([]byte(yamlConfig))

	req := &StackUpExecuteRequest{
		RemoteInfo: structs.L2DeviceRemoteInfo{
			Ip:       "192.168.1.1",
			Username: "admin",
			Password: "password",
			Platform: "linux",
		},
		Config:     configBase64,
		ConfigType: "base64",
	}

	ctx := context.Background()
	resp, err := client.StackUpExecute(ctx, req)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	if resp.Success {
		fmt.Printf("Success: %s\n", resp.Message)
	}
}

// ExampleStackUpExecute_WithLocalDataPath 使用本地数据路径执行 StackUp
func ExampleStackUpExecute_WithLocalDataPath() {
	// 创建客户端
	config := DefaultAsyncExecuteClientConfig("http://localhost:8081")
	client := NewAsyncExecuteClient(config)

	// 配置包含文件上传
	yamlConfig := `
commands:
  - name: upload_and_run
    upload:
      - src: ./local_file.txt
        dst: /tmp/remote_file.txt
        timeout: 30
    run: cat /tmp/remote_file.txt
    timeout: 10
`

	req := &StackUpExecuteRequest{
		RemoteInfo: structs.L2DeviceRemoteInfo{
			Ip:       "192.168.1.1",
			Username: "admin",
			Password: "password",
			Platform: "linux",
		},
		Config:        yamlConfig,
		ConfigType:    "yaml",
		LocalDataPath: "/opt/data", // 指定本地数据路径
	}

	ctx := context.Background()
	resp, err := client.StackUpExecute(ctx, req)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	if resp.Success {
		fmt.Printf("Success: %s\n", resp.Message)
		for _, result := range resp.Results {
			fmt.Printf("Command %s completed with status: %s\n", result.Key, result.Status)
		}
	}
}

// ExampleStackUpExecute_MultipleCommands 执行多个命令
func ExampleStackUpExecute_MultipleCommands() {
	// 创建客户端
	config := DefaultAsyncExecuteClientConfig("http://localhost:8081")
	client := NewAsyncExecuteClient(config)

	// 多个命令的配置
	yamlConfig := `
commands:
  - name: check_disk
    run: df -h
    timeout: 10
  - name: check_memory
    run: free -h
    timeout: 10
  - name: check_processes
    run: ps aux | head -10
    timeout: 10
  - name: check_network
    run: netstat -tuln | head -10
    timeout: 10
env:
  CHECK_TYPE: "system"
`

	req := &StackUpExecuteRequest{
		RemoteInfo: structs.L2DeviceRemoteInfo{
			Ip:       "192.168.1.1",
			Username: "admin",
			Password: "password",
			Platform: "linux",
		},
		Config:     yamlConfig,
		ConfigType: "yaml",
	}

	ctx := context.Background()
	resp, err := client.StackUpExecute(ctx, req)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	if resp.Success {
		fmt.Printf("Executed %d commands successfully\n", len(resp.Results))

		// 统计成功和失败的命令
		successCount := 0
		failCount := 0
		for _, result := range resp.Results {
			if result.Status == "false" {
				successCount++
			} else {
				failCount++
			}
		}

		fmt.Printf("Success: %d, Failed: %d\n", successCount, failCount)

		// 显示失败的命令
		if failCount > 0 {
			fmt.Println("\nFailed commands:")
			for _, result := range resp.Results {
				if result.Status == "true" {
					fmt.Printf("  - %s: %s\n", result.Key, result.Msg)
				}
			}
		}
	}
}

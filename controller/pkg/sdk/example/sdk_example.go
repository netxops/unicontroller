package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/sdk"
	"github.com/influxdata/telegraf/controller/pkg/structs"
)

// 这是一个使用示例文件，展示如何使用 SDK

func ExampleAsyncExecute() {
	// 创建客户端
	config := sdk.DefaultAsyncExecuteClientConfig("http://localhost:8081")
	client := sdk.NewAsyncExecuteClient(config)

	// 准备请求
	req := &sdk.AsyncExecuteRequest{
		ID: fmt.Sprintf("task-%d", time.Now().Unix()),
		RemoteInfo: structs.L2DeviceRemoteInfo{
			Ip:       "192.168.100.121",
			Username: "jacky",
			Password: "admin@123",
			Catalog:  "SERVER",
		},
		Commands: []string{
			"ls -la",
			"pwd",
		},
		Timeout: 120, // 增加超时时间到 120 秒，避免超时错误
	}

	// 异步执行
	ctx := context.Background()
	resp, err := client.AsyncExecute(ctx, req)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Task submitted: %s, Status: %s\n", resp.TaskID, resp.Status)

	// 稍后查询结果
	time.Sleep(6 * time.Second)
	result, err := client.GetSingleResult(ctx, resp.TaskID, true)
	if err != nil {
		fmt.Printf("Error getting result: %v\n", err)
		return
	}

	fmt.Printf("Task status: %s\n", result.Status)
	if result.IsSuccess() {
		fmt.Printf("Output: %s\n", result.GetCombinedOutput())
	}
}

func ExampleSyncExecute() {
	// 创建客户端
	config := sdk.DefaultAsyncExecuteClientConfig("http://localhost:8081")
	client := sdk.NewAsyncExecuteClient(config)

	// 准备请求
	req := &sdk.AsyncExecuteRequest{
		ID: fmt.Sprintf("task-%d", time.Now().Unix()),
		RemoteInfo: structs.L2DeviceRemoteInfo{
			Ip:       "192.168.100.121",
			Username: "jacky",
			Password: "admin@123",
			Catalog:  "SERVER",
		},
		Commands: []string{
			"ls -la",
			"pwd",
		},
		Timeout: 60,
	}

	// 同步执行（带状态更新回调）
	ctx := context.Background()
	opts := &sdk.SyncExecuteOptions{
		PollInterval:    500 * time.Millisecond, // 每500ms轮询一次
		MaxPollDuration: 2 * time.Minute,        // 最多等待2分钟
		OnStatusUpdate: func(status sdk.TaskStatus, result *sdk.AsyncTaskResult) {
			fmt.Printf("Status update: %s - %s\n", status, result.Message)
		},
	}

	result, err := client.SyncExecute(ctx, req, opts)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		// 如果 result 不为 nil，显示更详细的错误信息
		if result != nil && result.Error != nil {
			fmt.Printf("Error Type: %s\n", result.Error.Type)
			fmt.Printf("Error Message: %s\n", result.Error.Message)
			if result.Error.Details != "" {
				fmt.Printf("Error Details: %s\n", result.Error.Details)
			}
			if result.Error.Code != "" {
				fmt.Printf("Error Code: %s\n", result.Error.Code)
			}
		}
		return
	}

	// 处理结果
	if result.IsSuccess() {
		fmt.Printf("Success! Output:\n%s\n", result.GetCombinedOutput())
	} else {
		fmt.Printf("Failed: %s\n", result.GetCombinedError())
		if result.Error != nil {
			fmt.Printf("Error Type: %s\n", result.Error.Type)
			if result.Error.Details != "" {
				fmt.Printf("Error Details: %s\n", result.Error.Details)
			}
		}
	}
}

func ExampleBatchQuery() {
	// 创建客户端
	config := sdk.DefaultAsyncExecuteClientConfig("http://localhost:8081")
	client := sdk.NewAsyncExecuteClient(config)

	// 批量查询多个任务结果
	ctx := context.Background()
	taskIDs := []string{"task-1", "task-2", "task-3"}

	resp, err := client.GetResult(ctx, taskIDs, true)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// 处理结果
	for taskID, result := range resp.Results {
		fmt.Printf("Task %s: Status=%s\n", taskID, result.Status)
		if result.IsSuccess() {
			fmt.Printf("  Output: %s\n", result.GetCombinedOutput())
		} else {
			fmt.Printf("  Error: %s\n", result.GetCombinedError())
		}
	}

	// 处理错误
	for taskID, errMsg := range resp.Errors {
		fmt.Printf("Task %s error: %s\n", taskID, errMsg)
	}
}

func ExampleScriptExecution() {
	// 创建客户端
	config := sdk.DefaultAsyncExecuteClientConfig("http://localhost:8081")
	client := sdk.NewAsyncExecuteClient(config)

	// 执行脚本
	req := &sdk.AsyncExecuteRequest{
		ID: fmt.Sprintf("task-%d", time.Now().Unix()),
		RemoteInfo: structs.L2DeviceRemoteInfo{
			Ip:       "192.168.100.121",
			Username: "jacky",
			Password: "admin@123",
			Catalog:  "SERVER",
		},
		Script: `#!/bin/bash
echo "Hello from script"
date
ls -la /tmp
`,
		Timeout: 60,
	}

	ctx := context.Background()
	result, err := client.SyncExecute(ctx, req, nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Script execution result: %s\n", result.Status)
	if result.Result != nil {
		fmt.Printf("Exit code: %d\n", result.Result.ExitCode)
		fmt.Printf("Output:\n%s\n", result.Result.Stdout)
	}
}

func ExampleStackUpExecute() {
	// 创建客户端
	config := sdk.DefaultAsyncExecuteClientConfig("http://localhost:8081")
	client := sdk.NewAsyncExecuteClient(config)

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

	req := &sdk.StackUpExecuteRequest{
		RemoteInfo: structs.L2DeviceRemoteInfo{
			Ip:       "192.168.100.121",
			Username: "jacky",
			Password: "admin@123",
			Catalog:  "SERVER",
		},
		Config:     yamlConfig,
		ConfigType: "yaml",
	}

	// 执行
	ctx := context.Background()
	resp, err := client.StackUpExecute(ctx, req)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// 处理结果
	if resp.Success {
		fmt.Printf("Success: %s\n", resp.Message)
		for _, result := range resp.Results {
			fmt.Printf("\nCommand %d: %s\n", result.Index, result.Key)
			fmt.Printf("  Command: %s\n", result.Command)
			fmt.Printf("  Status: %s", result.Status)

			// Status: "false" 表示成功，"true" 表示有错误
			if result.Status == "true" {
				fmt.Printf(" (成功)\n")
				if result.Output != "" {
					fmt.Printf("  Output:\n%s\n", result.Output)
				} else {
					fmt.Printf("  Output: (无输出)\n")
				}
			} else {
				fmt.Printf(" (成功)\n")
				if result.Msg != "" {
					fmt.Printf("  Error Message: %s\n", result.Msg)
				}
				if result.Output != "" {
					fmt.Printf("  Output:\n%s\n", result.Output)
				}
				if result.Msg == "" && result.Output == "" {
					fmt.Printf("  (无错误信息和输出)\n")
				}
			}
		}
	} else {
		fmt.Printf("Failed: %s\n", resp.Error)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run sdk_example.go <example_name>")
		fmt.Println("\nAvailable examples:")
		fmt.Println("  async_execute    - 异步执行命令示例")
		fmt.Println("  sync_execute     - 同步执行命令示例")
		fmt.Println("  batch_query      - 批量查询任务结果示例")
		fmt.Println("  script           - 脚本执行示例")
		fmt.Println("  stackup          - StackUp 执行示例")
		fmt.Println("\nExample:")
		fmt.Println("  go run sdk_example.go async_execute")
		return
	}

	exampleName := os.Args[1]

	switch exampleName {
	case "async_execute":
		fmt.Println("=== 异步执行命令示例 ===")
		ExampleAsyncExecute()
	case "sync_execute":
		fmt.Println("=== 同步执行命令示例 ===")
		ExampleSyncExecute()
	case "batch_query":
		fmt.Println("=== 批量查询任务结果示例 ===")
		ExampleBatchQuery()
	case "script":
		fmt.Println("=== 脚本执行示例 ===")
		ExampleScriptExecution()
	case "stackup":
		fmt.Println("=== StackUp 执行示例 ===")
		ExampleStackUpExecute()
	default:
		fmt.Printf("Unknown example: %s\n", exampleName)
		fmt.Println("Available examples: async_execute, sync_execute, batch_query, script, stackup")
	}
}

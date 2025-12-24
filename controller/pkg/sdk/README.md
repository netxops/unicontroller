# Controller API SDK

这是一个用于调用 Controller API 的 Go SDK，提供了同步和异步两种方式来执行远程命令。

## 功能特性

- ✅ **异步执行**：提交任务后立即返回，不等待结果
- ✅ **同步执行**：提交任务并自动轮询，直到任务完成
- ✅ **批量查询**：支持一次查询多个任务的结果
- ✅ **状态回调**：同步执行时支持状态更新回调
- ✅ **灵活配置**：可自定义超时、轮询间隔等参数
- ✅ **类型安全**：完整的类型定义，编译时检查

## 快速开始

### 1. 创建客户端

```go
import (
    "github.com/influxdata/telegraf/controller/pkg/sdk"
    "time"
)

// 使用默认配置
config := sdk.DefaultAsyncExecuteClientConfig("http://localhost:8081")
client := sdk.NewAsyncExecuteClient(config)

// 或自定义配置
config := &sdk.AsyncExecuteClientConfig{
    BaseURL:         "http://localhost:8081",
    DefaultTimeout:  30 * time.Second,
    PollInterval:    1 * time.Second,
    MaxPollDuration: 5 * time.Minute,
    MaxPollAttempts: 300,
}
client := sdk.NewAsyncExecuteClient(config)
```

### 2. 异步执行（推荐用于长时间运行的任务）

```go
import (
    "context"
    "github.com/influxdata/telegraf/controller/pkg/sdk"
    "github.com/influxdata/telegraf/controller/pkg/structs"
)

req := &sdk.AsyncExecuteRequest{
    ID: "task-123",
    RemoteInfo: structs.L2DeviceRemoteInfo{
        Ip:       "192.168.1.1",
        Username: "admin",
        Password: "password",
        Platform: "linux",
    },
    Commands: []string{
        "ls -la",
        "pwd",
    },
    Timeout: 60,
}

// 提交任务
ctx := context.Background()
resp, err := client.AsyncExecute(ctx, req)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Task ID: %s\n", resp.TaskID)

// 稍后查询结果
result, err := client.GetSingleResult(ctx, resp.TaskID, true)
if err != nil {
    log.Fatal(err)
}

if result.IsSuccess() {
    fmt.Printf("Output: %s\n", result.GetCombinedOutput())
}
```

### 3. 同步执行（推荐用于快速任务）

```go
req := &sdk.AsyncExecuteRequest{
    ID: "task-123",
    RemoteInfo: structs.L2DeviceRemoteInfo{
        Ip:       "192.168.1.1",
        Username: "admin",
        Password: "password",
        Platform: "linux",
    },
    Commands: []string{"ls -la"},
    Timeout: 60,
}

// 同步执行（带状态回调）
opts := &sdk.SyncExecuteOptions{
    PollInterval:    500 * time.Millisecond,
    MaxPollDuration: 2 * time.Minute,
    OnStatusUpdate: func(status sdk.TaskStatus, result *sdk.AsyncTaskResult) {
        fmt.Printf("Status: %s - %s\n", status, result.Message)
    },
}

ctx := context.Background()
result, err := client.SyncExecute(ctx, req, opts)
if err != nil {
    log.Fatal(err)
}

if result.IsSuccess() {
    fmt.Printf("Success! Output:\n%s\n", result.GetCombinedOutput())
} else {
    fmt.Printf("Failed: %s\n", result.GetCombinedError())
}
```

### 4. 批量查询

```go
taskIDs := []string{"task-1", "task-2", "task-3"}
resp, err := client.GetResult(ctx, taskIDs, true)
if err != nil {
    log.Fatal(err)
}

for taskID, result := range resp.Results {
    fmt.Printf("Task %s: %s\n", taskID, result.Status)
}

for taskID, errMsg := range resp.Errors {
    fmt.Printf("Task %s error: %s\n", taskID, errMsg)
}
```

## API 参考

### AsyncExecuteClientConfig

客户端配置结构：

```go
type AsyncExecuteClientConfig struct {
    BaseURL         string        // API 基础 URL
    HTTPClient      *http.Client  // 自定义 HTTP 客户端（可选）
    DefaultTimeout  time.Duration // 默认请求超时时间
    PollInterval    time.Duration // 轮询间隔（同步调用时使用）
    MaxPollDuration time.Duration // 最大轮询时间
    MaxPollAttempts int           // 最大轮询次数
}
```

### AsyncExecuteClient

异步执行客户端：

```go
type AsyncExecuteClient struct {
    // 内部字段
}

// 创建客户端
func NewAsyncExecuteClient(config *AsyncExecuteClientConfig) *AsyncExecuteClient

// 获取默认配置
func DefaultAsyncExecuteClientConfig(baseURL string) *AsyncExecuteClientConfig
```

### AsyncExecuteRequest

异步执行请求：

```go
type AsyncExecuteRequest struct {
    ID         string                  // 任务ID（由客户端提供）
    RemoteInfo structs.L2DeviceRemoteInfo // 设备连接信息
    Commands   []string                // 命令列表（可选）
    Script     string                  // 内联脚本（可选）
    ScriptPath string                  // 文件脚本路径（可选）
    Background bool                    // 是否后台执行
    Timeout    int                     // 超时时间（秒），默认60秒
}
```

**注意**：`Commands`、`Script`、`ScriptPath` 至少需要提供一个。

### AsyncTaskResult

任务结果结构：

```go
type AsyncTaskResult struct {
    Status   TaskStatus      // 任务状态
    TaskInfo TaskInfo        // 任务信息
    StartTime time.Time      // 开始时间
    EndTime   *time.Time     // 结束时间
    Duration  *int64         // 执行时长（毫秒）
    Result   *ExecutionResult // 执行结果（成功时）
    Error    *ErrorDetail     // 错误详情（失败时）
    Message  string           // 状态消息
}
```

### 任务状态

- `TaskStatusPending` - 待执行
- `TaskStatusRunning` - 执行中
- `TaskStatusCompleted` - 已完成
- `TaskStatusFailed` - 执行失败
- `TaskStatusCancelled` - 已取消

## 使用场景

### 场景1：快速命令执行（同步）

```go
result, err := client.SyncExecute(ctx, req, nil)
// 直接获取结果，无需手动轮询
```

### 场景2：长时间任务（异步）

```go
// 提交任务
resp, err := client.AsyncExecute(ctx, req)

// 在后台定期查询
go func() {
    for {
        result, _ := client.GetSingleResult(ctx, resp.TaskID, true)
        if result.Status.IsCompleted() {
            break
        }
        time.Sleep(5 * time.Second)
    }
}()
```

### 场景3：批量任务监控

```go
// 提交多个任务
taskIDs := []string{}
for i := 0; i < 10; i++ {
    req.ID = fmt.Sprintf("task-%d", i)
    resp, _ := client.AsyncExecute(ctx, req)
    taskIDs = append(taskIDs, resp.TaskID)
}

// 批量查询结果
results, _ := client.GetResult(ctx, taskIDs, true)
```

## 错误处理

SDK 会返回详细的错误信息：

```go
result, err := client.SyncExecute(ctx, req, nil)
if err != nil {
    // 检查错误类型
    if strings.Contains(err.Error(), "timeout") {
        // 处理超时
    } else if strings.Contains(err.Error(), "network") {
        // 处理网络错误
    }
    return err
}

// 检查任务是否成功
if !result.IsSuccess() {
    // 获取错误详情
    if result.Error != nil {
        fmt.Printf("Error type: %s, Message: %s\n", 
            result.Error.Type, result.Error.Message)
    }
}
```

## 最佳实践

1. **任务ID生成**：使用唯一ID，建议使用 UUID 或时间戳
2. **超时设置**：根据任务复杂度合理设置超时时间
3. **错误重试**：对于网络错误，可以实现重试逻辑
4. **资源清理**：长时间运行的程序应定期清理已完成的任务结果
5. **并发控制**：避免同时提交过多任务，注意控制并发数

## 其他 SDK 功能

除了异步执行 API，SDK 还提供了其他功能：

### 旧的 Client（用于其他 API）

```go
// 创建客户端（需要用户名和密码）
client := sdk.NewClient("http://localhost:8081", "username", "password")

// 获取控制器状态
status, err := client.GetControllerStatus()

// 创建部署
deployment, err := client.CreateDeployment(req)

// 列出代理
agents, err := client.ListAgents(filter, page, pageSize)
```

### ConfigDriver（用于 etcd 配置管理）

```go
// 创建 ConfigDriver
cd := sdk.NewConfigDriver("agent_config", "DefaultArea", []string{"127.0.0.1:2379"})

// 读取配置
config, err := cd.GetConfig(ctx, "ExampleCode", "uniops-telegraf")

// 写入配置
err := cd.PutConfig(ctx, config, "ExampleCode", "uniops-telegraf")

// 启用/禁用配置
err := cd.Enable(ctx, true, "ExampleCode", "uniops-telegraf")
```

## StackUp 执行接口

StackUp 是一个用于批量执行远程命令的工具，支持通过 YAML 配置文件定义多个命令、脚本和文件上传。

### 基本使用

```go
import (
    "context"
    "github.com/influxdata/telegraf/controller/pkg/sdk"
    "github.com/influxdata/telegraf/controller/pkg/structs"
)

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
    script: |
      #!/bin/bash
      echo "Script test"
      date
env:
  TEST_VAR: "test_value"
`

// 执行 StackUp
req := &sdk.StackUpExecuteRequest{
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
    log.Fatal(err)
}

// 处理结果
if resp.Success {
    fmt.Printf("Success: %s\n", resp.Message)
    for _, result := range resp.Results {
        fmt.Printf("Command %d (%s): Status=%s\n", 
            result.Index, result.Key, result.Status)
        if result.Status == "false" {
            fmt.Printf("  Output: %s\n", result.Output)
        } else {
            fmt.Printf("  Error: %s\n", result.Msg)
        }
    }
}
```

### 配置格式

StackUp 配置文件支持以下功能：

1. **执行命令** (`run`):
```yaml
commands:
  - name: my_command
    run: ls -la /tmp
    timeout: 10
```

2. **执行脚本** (`script`):
```yaml
commands:
  - name: my_script
    script: |
      #!/bin/bash
      echo "Hello"
      date
    timeout: 10
```

3. **上传文件** (`upload`):
```yaml
commands:
  - name: upload_file
    upload:
      - src: /local/path/file.txt
        dst: /remote/path/file.txt
        timeout: 30
```

4. **环境变量** (`env`):
```yaml
env:
  VAR1: "value1"
  VAR2: "value2"
```

### StackUpExecuteRequest

```go
type StackUpExecuteRequest struct {
    RemoteInfo    structs.L2DeviceRemoteInfo // 设备连接信息
    Config        string                     // YAML 配置（或 base64 编码）
    ConfigType    string                     // "yaml" 或 "base64"，默认 "yaml"
    LocalDataPath string                     // 本地数据路径（可选）
}
```

### StackUpExecuteResponse

```go
type StackUpExecuteResponse struct {
    Success bool                   // 是否成功
    Message string                 // 消息
    Results []StackUpCommandResult // 命令执行结果列表
    Error   string                 // 错误信息（如果有）
}

type StackUpCommandResult struct {
    Index   int    // 命令索引（从1开始）
    Command string // 执行的命令
    Key     string // 命令的 key/name
    Output  string // 命令输出
    Msg     string // 消息
    Status  string // 状态："false"=成功, "true"=有错误
}
```

## 示例代码

完整示例请参考：
- `cmd/controller/sdk_example.go` - 异步执行示例
- `pkg/sdk/stackup_test.go` - StackUp 接口测试示例


# 运维管理平台集成指南

## 概述

本文档指导如何在运维管理平台项目中集成和使用 `pkg/platform` 包，实现对分布式 Agent 系统的统一管理。

## 目录结构

```
pkg/platform/
├── models/          # 数据模型
│   ├── controller.go    # Controller 模型
│   ├── agent.go         # Agent 聚合模型
│   ├── device.go        # 设备模型
│   └── deployment.go    # 部署记录模型
├── etcd/            # etcd 客户端集成
│   └── discovery.go     # Controller 发现服务
└── client/          # Controller HTTP API 客户端
    └── controller_client.go
```

## 一、快速开始

### 1.1 导入依赖

在您的运维平台项目中，需要导入以下包：

```go
import (
    "github.com/influxdata/telegraf/controller/pkg/platform/etcd"
    "github.com/influxdata/telegraf/controller/pkg/platform/client"
    "github.com/influxdata/telegraf/controller/pkg/platform/models"
    clientv3 "go.etcd.io/etcd/client/v3"
)
```

### 1.2 初始化 etcd 客户端

```go
import clientv3 "go.etcd.io/etcd/client/v3"

// 创建 etcd 客户端
etcdClient, err := clientv3.New(clientv3.Config{
    Endpoints:   []string{"platform-etcd-1:2379", "platform-etcd-2:2379"},
    DialTimeout: 5 * time.Second,
})
if err != nil {
    log.Fatalf("Failed to create etcd client: %v", err)
}
defer etcdClient.Close()
```

### 1.3 启动 Controller 发现服务

```go
// 创建 Controller 发现服务
discovery := etcd.NewControllerDiscovery(etcdClient, "controllers/")

// 设置回调函数
discovery.SetOnControllerUpdate(func(controller *models.Controller) {
    log.Printf("Controller updated: %s/%s", controller.Area, controller.ID)
    // 更新数据库中的 Controller 信息
    // updateControllerInDB(controller)
})

discovery.SetOnControllerDelete(func(key string) {
    log.Printf("Controller deleted: %s", key)
    // 从数据库中删除 Controller
    // deleteControllerFromDB(key)
})

// 启动发现服务
if err := discovery.Start(); err != nil {
    log.Fatalf("Failed to start controller discovery: %v", err)
}
defer discovery.Stop()
```

## 二、核心功能使用

### 2.1 Controller 管理

#### 2.1.1 获取 Controller 列表

```go
// 获取所有 Controller
controllers := discovery.ListControllers()
for _, ctrl := range controllers {
    log.Printf("Controller: %s, Area: %s, Status: %s", 
        ctrl.ID, ctrl.Area, ctrl.Status)
}

// 获取指定区域的 Controller
areaControllers := discovery.ListControllersByArea("area-1")

// 获取指定区域的在线 Controller
controller, err := discovery.GetControllerByArea("area-1")
if err != nil {
    log.Printf("No online controller found for area-1")
} else {
    log.Printf("Found controller: %s at %s", controller.ID, controller.Address)
}
```

#### 2.1.2 根据 function_area 查找 Controller

```go
func GetControllerForDevice(discovery *etcd.ControllerDiscovery, functionArea string) (*models.Controller, error) {
    controller, err := discovery.GetControllerByArea(functionArea)
    if err != nil {
        return nil, fmt.Errorf("no controller found for area: %s", functionArea)
    }
    
    if controller.Status != models.ControllerStatusOnline {
        return nil, fmt.Errorf("controller for area %s is offline", functionArea)
    }
    
    return controller, nil
}
```

### 2.2 Controller HTTP API 客户端

#### 2.2.1 创建客户端

```go
// 创建 Controller 客户端
// 注意：baseURL 可以包含协议前缀，也可以不包含（会自动补全 http://）
controllerClient := client.NewControllerClient(
    "192.168.1.100:8081",       // Controller 地址（会自动补全为 http://192.168.1.100:8081）
    "area-1",                    // 区域标识
)

// 或者显式指定协议
controllerClient := client.NewControllerClient(
    "http://192.168.1.100:8081", // Controller 地址（带协议前缀）
    "area-1",
)

// 设置超时时间
controllerClient.SetTimeout(30 * time.Second)
```

**重要提示**：如果传入的 baseURL 不包含协议前缀（`http://` 或 `https://`），客户端会自动补全 `http://` 前缀。

#### 2.2.2 查询 Agent 列表

```go
// 获取 Agent 列表（支持过滤和分页）
filters := map[string]string{
    "status": "online",
}
agents, err := controllerClient.ListAgents(ctx, filters, 1, 20)
// 注意：参数名是 pageSize（驼峰命名），不是 page_size
if err != nil {
    log.Printf("Failed to list agents: %v", err)
    return
}

log.Printf("Total agents: %d", agents.Total)
for _, agent := range agents.Agents {
    log.Printf("Agent: %s, Status: %s, Address: %s", 
        agent.ID, agent.Status, agent.Address)
}
```

#### 2.2.3 获取 Agent 详情

```go
// 获取 Agent 详情
agent, err := controllerClient.GetAgent(ctx, "agent-001")
if err != nil {
    log.Printf("Failed to get agent: %v", err)
    return
}

log.Printf("Agent ID: %s", agent.ID)
log.Printf("Agent Address: %s", agent.Address)
log.Printf("Agent Status: %s", agent.Status)
log.Printf("Services: %d", len(agent.Services))
```

#### 2.2.4 获取 Agent 健康状态

```go
// 获取 Agent 整体健康状态
health, err := controllerClient.GetAgentHealth(ctx, "agent-001")
if err != nil {
    log.Printf("Failed to get agent health: %v", err)
    return
}

// health 是 map[string]interface{}，包含健康状态信息
overallStatus := health["overall_status"]
log.Printf("Agent health status: %v", overallStatus)

// 获取指定服务的健康状态
serviceHealth, err := controllerClient.GetServiceHealth(ctx, "agent-001", "my-service")
if err != nil {
    log.Printf("Failed to get service health: %v", err)
    return
}
```

#### 2.2.5 获取指标

```go
// 获取系统指标
systemMetrics, err := controllerClient.GetSystemMetrics(ctx, "agent-001")
if err != nil {
    log.Printf("Failed to get system metrics: %v", err)
    return
}

// 获取服务指标
serviceMetrics, err := controllerClient.GetServiceMetrics(ctx, "agent-001")
if err != nil {
    log.Printf("Failed to get service metrics: %v", err)
    return
}
```

#### 2.2.6 批量操作

```go
// 批量启动服务
batchReq := &models.BatchOperationRequest{
    Agents:   []string{"agent-001", "agent-002"},
    Packages: []string{"service-1", "service-2"},
}

result, err := controllerClient.BatchStart(ctx, batchReq)
if err != nil {
    log.Printf("Failed to batch start: %v", err)
    return
}

log.Printf("Batch start result: Total=%d, Success=%d, Failed=%d", 
    result.Total, result.Success, result.Failed)

// 批量停止服务
stopResult, err := controllerClient.BatchStop(ctx, batchReq)

// 批量重启服务
restartResult, err := controllerClient.BatchRestart(ctx, batchReq)

// 批量更新配置
configReq := &models.BatchConfigRequest{
    Agents:  []string{"agent-001"},
    Package: "service-1",
    Configs: []models.ConfigItem{
        {
            FileName: "config.yaml",
            Content:  "key: value\n",
        },
    },
}
configResult, err := controllerClient.BatchUpdateConfigs(ctx, configReq)
```

## 三、完整集成示例

### 3.1 初始化服务

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/influxdata/telegraf/controller/pkg/platform/etcd"
    "github.com/influxdata/telegraf/controller/pkg/platform/client"
    "github.com/influxdata/telegraf/controller/pkg/platform/models"
    clientv3 "go.etcd.io/etcd/client/v3"
)

type PlatformService struct {
    etcdClient        *clientv3.Client
    discovery         *etcd.ControllerDiscovery
    controllerClients map[string]*client.ControllerClient // area -> client
}

func NewPlatformService(etcdEndpoints []string) (*PlatformService, error) {
    // 初始化 etcd 客户端
    etcdClient, err := clientv3.New(clientv3.Config{
        Endpoints:   etcdEndpoints,
        DialTimeout: 5 * time.Second,
    })
    if err != nil {
        return nil, err
    }

    // 创建 Controller 发现服务
    discovery := etcd.NewControllerDiscovery(etcdClient, "controllers/")
    
    service := &PlatformService{
        etcdClient:        etcdClient,
        discovery:         discovery,
        controllerClients: make(map[string]*client.ControllerClient),
    }

    // 设置 Controller 更新回调
    discovery.SetOnControllerUpdate(func(controller *models.Controller) {
        service.onControllerUpdate(controller)
    })

    discovery.SetOnControllerDelete(func(key string) {
        service.onControllerDelete(key)
    })

    // 启动发现服务
    if err := discovery.Start(); err != nil {
        return nil, err
    }

    return service, nil
}

func (s *PlatformService) onControllerUpdate(controller *models.Controller) {
    // 创建或更新 Controller 客户端
    if controller.Status == models.ControllerStatusOnline {
        client := client.NewControllerClient(controller.Address, controller.Area)
        s.controllerClients[controller.Area] = client
        log.Printf("Controller client created: area=%s, address=%s", 
            controller.Area, controller.Address)
    }
}

func (s *PlatformService) onControllerDelete(key string) {
    // 删除 Controller 客户端
    // 从 key 中提取 area
    // delete(s.controllerClients, area)
}

func (s *PlatformService) GetControllerClient(area string) (*client.ControllerClient, error) {
    client, exists := s.controllerClients[area]
    if !exists {
        return nil, fmt.Errorf("no controller client found for area: %s", area)
    }
    return client, nil
}

func (s *PlatformService) Close() {
    s.discovery.Stop()
    s.etcdClient.Close()
}
```

### 3.2 Agent 聚合服务

```go
type AgentAggregationService struct {
    platformService *PlatformService
}

func (s *AgentAggregationService) GetAllAgents(ctx context.Context) ([]*models.AggregatedAgent, error) {
    controllers := s.platformService.discovery.ListControllers()
    var allAgents []*models.AggregatedAgent

    for _, controller := range controllers {
        if controller.Status != models.ControllerStatusOnline {
            continue
        }

        client, err := s.platformService.GetControllerClient(controller.Area)
        if err != nil {
            log.Printf("Failed to get controller client for area %s: %v", controller.Area, err)
            continue
        }

        // 获取该 Controller 管理的所有 Agent
        agents, err := client.ListAgents(ctx, nil, 1, 1000)
        if err != nil {
            log.Printf("Failed to list agents from controller %s: %v", controller.ID, err)
            continue
        }

        // 转换为聚合 Agent
        for _, agent := range agents.Agents {
            aggregatedAgent := &models.AggregatedAgent{
                ID:            agent.ID,
                AgentCode:     agent.ID, // 假设 ID 就是 AgentCode
                Area:          controller.Area,
                ControllerID:  controller.ID,
                Address:       agent.Address,
                Status:        string(agent.Status),
                HealthStatus:  agent.HealthStatus,
                ServiceCount: len(agent.Services),
                LastHeartbeat: agent.LastHeartbeat,
                Version:       agent.Version,
            }
            allAgents = append(allAgents, aggregatedAgent)
        }
    }

    return allAgents, nil
}

func (s *AgentAggregationService) GetAgentByCode(ctx context.Context, agentCode string) (*models.AggregatedAgent, error) {
    // 1. 从设备表查询设备信息（需要实现设备管理服务）
    // device, err := s.deviceService.GetDeviceByAgentCode(agentCode)
    
    // 2. 根据 function_area 找到对应的 Controller
    // controller, err := s.platformService.discovery.GetControllerByArea(device.FunctionArea)
    
    // 3. 从 Controller 获取 Agent 详细信息
    // client, err := s.platformService.GetControllerClient(controller.Area)
    // agent, err := client.GetAgent(ctx, agentCode)
    
    // 4. 关联设备信息并返回
    // ...
    
    return nil, fmt.Errorf("not implemented")
}
```

### 3.3 跨区域批量操作

```go
func (s *AgentAggregationService) BatchStartAcrossAreas(ctx context.Context, 
    req *models.BatchOperationRequest) (*models.BatchOperationResult, error) {
    
    // 按区域分组 Agent
    areaGroups := make(map[string][]string)
    for _, agentCode := range req.Agents {
        // 根据 AgentCode 查找对应的区域（需要实现设备查询）
        // area := s.getAreaByAgentCode(agentCode)
        // areaGroups[area] = append(areaGroups[area], agentCode)
    }

    // 并发执行
    var wg sync.WaitGroup
    results := make(chan *models.BatchOperationResult, len(areaGroups))

    for area, agents := range areaGroups {
        wg.Add(1)
        go func(area string, agents []string) {
            defer wg.Done()
            
            client, err := s.platformService.GetControllerClient(area)
            if err != nil {
                log.Printf("Failed to get controller client: %v", err)
                return
            }

            batchReq := &models.BatchOperationRequest{
                Agents:   agents,
                Packages: req.Packages,
            }
            
            result, err := client.BatchStart(ctx, batchReq)
            if err != nil {
                log.Printf("Batch start failed for area %s: %v", area, err)
                return
            }
            
            results <- result
        }(area, agents)
    }

    wg.Wait()
    close(results)

    // 聚合结果
    totalResult := &models.BatchOperationResult{
        Results: []models.OperationResult{},
    }
    
    for result := range results {
        totalResult.Total += result.Total
        totalResult.Success += result.Success
        totalResult.Failed += result.Failed
        totalResult.Results = append(totalResult.Results, result.Results...)
    }

    return totalResult, nil
}
```

## 四、数据模型说明

### 4.1 Controller 模型

```go
type Controller struct {
    ID            string                 // Controller 唯一标识
    Area          string                 // 区域标识
    Address       string                 // Controller 地址
    Status        string                 // online, offline
    Version       string                 // Controller 版本
    StartTime     time.Time              // 启动时间
    LastHeartbeat time.Time              // 最后心跳时间
    AgentCount    int                    // 管理的 Agent 数量
    Metadata      map[string]interface{} // 扩展元数据
}
```

### 4.2 Agent 聚合模型

```go
type AggregatedAgent struct {
    ID            string    // Agent ID（通常等于 AgentCode）
    AgentCode     string    // Agent 标识码（由运维平台生成，全局唯一）
    Area          string    // 所属区域
    ControllerID  string    // 管理的 Controller ID
    DeviceID      string    // 关联的设备 ID
    Address       string    // Agent 地址
    Status        string    // Agent 状态
    HealthStatus  string    // 健康状态
    ServiceCount  int       // 管理的服务数量
    LastHeartbeat time.Time // 最后心跳时间
    Version       string    // Agent 版本
    DeployedAt    time.Time // 部署时间
}
```

### 4.3 设备模型

```go
type Device struct {
    ID            string            // 设备唯一标识
    Name          string            // 设备名称
    IP            string            // 设备 IP 地址
    FunctionArea  string            // 功能区域，用于确定 Controller
    Status        string            // 设备状态
    AgentCode     string            // Agent 标识码（由运维平台生成和管理，唯一）
    AgentVersion  string            // Agent 版本
    OS            string            // linux, windows
    Architecture  string            // amd64, arm64
    LoginMethod   string            // ssh, winrm
    LoginDetails  LoginDetails      // 登录凭证
    CreatedAt     time.Time         // 入库时间
    UpdatedAt     time.Time         // 更新时间
    Metadata      map[string]string // 扩展元数据
}
```

## 五、最佳实践

### 5.1 错误处理

```go
// 始终检查错误
agent, err := controllerClient.GetAgent(ctx, agentID)
if err != nil {
    // 区分不同类型的错误
    if strings.Contains(err.Error(), "not found") {
        // Agent 不存在
        return nil, ErrAgentNotFound
    }
    if strings.Contains(err.Error(), "timeout") {
        // 请求超时，可以重试
        return nil, ErrRequestTimeout
    }
    // 其他错误
    return nil, fmt.Errorf("failed to get agent: %w", err)
}
```

### 5.2 连接池管理

```go
// 为每个 Controller 维护一个客户端实例
type ControllerClientPool struct {
    clients map[string]*client.ControllerClient
    mu      sync.RWMutex
}

func (p *ControllerClientPool) GetClient(area string) (*client.ControllerClient, error) {
    p.mu.RLock()
    c, exists := p.clients[area]
    p.mu.RUnlock()
    
    if exists {
        return c, nil
    }
    
    // 创建新客户端
    controller, err := discovery.GetControllerByArea(area)
    if err != nil {
        return nil, err
    }
    
    c = client.NewControllerClient(controller.Address, area)
    
    p.mu.Lock()
    p.clients[area] = c
    p.mu.Unlock()
    
    return c, nil
}
```

### 5.3 缓存策略

```go
// 使用缓存减少对 Controller 的请求
type AgentCache struct {
    cache    map[string]*models.AggregatedAgent
    mu       sync.RWMutex
    ttl      time.Duration
    lastSync time.Time
}

func (c *AgentCache) GetAgent(agentCode string) (*models.AggregatedAgent, error) {
    c.mu.RLock()
    agent, exists := c.cache[agentCode]
    lastSync := c.lastSync
    c.mu.RUnlock()
    
    if exists && time.Since(lastSync) < c.ttl {
        return agent, nil
    }
    
    // 缓存过期，重新获取
    // ...
}
```

### 5.4 并发控制

```go
// 使用 goroutine 池限制并发数
type WorkerPool struct {
    workers chan struct{}
}

func NewWorkerPool(maxWorkers int) *WorkerPool {
    return &WorkerPool{
        workers: make(chan struct{}, maxWorkers),
    }
}

func (p *WorkerPool) Execute(fn func()) {
    p.workers <- struct{}{} // 获取 worker
    go func() {
        defer func() { <-p.workers }() // 释放 worker
        fn()
    }()
}
```

## 六、配置示例

### 6.1 配置文件

```yaml
# platform.yaml
etcd:
  endpoints:
    - "platform-etcd-1:2379"
    - "platform-etcd-2:2379"
  watch_prefix: "controllers/"
  dial_timeout: 5s

controller:
  api_timeout: 30s
  retry_times: 3
  retry_interval: 1s

cache:
  agent_ttl: 300s  # Agent 信息缓存 5 分钟
  controller_ttl: 60s  # Controller 信息缓存 1 分钟

concurrency:
  max_workers: 10  # 最大并发 worker 数
```

## 七、常见问题

### 7.1 参数名错误导致 502 错误

**错误信息**：
```
Controller返回错误状态码 {"url": "http://192.168.0.199:8081/api/v1/agents?page=1&page_size=20", "statusCode": 502}
```

**原因**：Controller API 期望的参数名是 `pageSize`（驼峰命名），而不是 `page_size`（下划线命名）

**解决方案**：
1. **使用 pkg/platform/client**：客户端已正确处理参数名
   ```go
   agents, err := controllerClient.ListAgents(ctx, filters, 1, 20)
   // 内部会自动使用 pageSize 参数
   ```

2. **直接调用 API**：确保使用正确的参数名
   ```go
   // ❌ 错误
   url := "http://controller:8081/api/v1/agents?page=1&page_size=20"
   
   // ✅ 正确
   url := "http://controller:8081/api/v1/agents?page=1&pageSize=20"
   ```

**Controller API 参数说明**：
- `page`：页码（从 1 开始）
- `pageSize`：每页数量（驼峰命名，不是 `page_size`）
- 支持的过滤参数：`id`, `status`, `address`, `hostname`, `area`, `zone`, `version`, `mode`, `group`, `deployment`

### 7.2 Controller 返回 502 错误

**错误信息**：
```
Controller返回错误状态码 {"statusCode": 502, "response": ""}
```

**可能原因**：
1. **参数名错误**：使用了 `page_size` 而不是 `pageSize`（见 7.1）
2. **Controller 服务未启动**：检查 Controller 是否正常运行
3. **网络问题**：检查网络连接和防火墙设置
4. **Controller 内部错误**：查看 Controller 日志

**排查步骤**：
```bash
# 1. 检查 Controller 是否运行
curl http://192.168.0.199:8081/api/v1/status

# 2. 使用正确的参数名测试
curl "http://192.168.0.199:8081/api/v1/agents?page=1&pageSize=20"

# 3. 查看 Controller 日志
tail -f /var/log/controller/controller.log
```

### 7.3 Controller 离线处理

```go
// 检查 Controller 状态
controller, err := discovery.GetControllerByArea(area)
if err != nil {
    // Controller 不存在或离线
    return fmt.Errorf("controller unavailable for area: %s", area)
}

// 定期检查 Controller 健康状态
go func() {
    ticker := time.NewTicker(30 * time.Second)
    for range ticker.C {
        controllers := discovery.ListControllers()
        for _, ctrl := range controllers {
            if ctrl.Status == models.ControllerStatusOffline {
                log.Printf("Controller %s is offline", ctrl.ID)
                // 触发告警或处理逻辑
            }
        }
    }
}()
```

### 7.4 网络分区处理

```go
// 实现重试机制
func withRetry(ctx context.Context, maxRetries int, fn func() error) error {
    var lastErr error
    for i := 0; i < maxRetries; i++ {
        if err := fn(); err != nil {
            lastErr = err
            if i < maxRetries-1 {
                time.Sleep(time.Duration(i+1) * time.Second)
                continue
            }
        } else {
            return nil
        }
    }
    return lastErr
}
```

## 八、API 端点参考

### 8.1 Controller API 端点

| 功能 | 端点 | 方法 | 说明 |
|------|------|------|------|
| Agent 列表 | `/api/v1/agents` | GET | 获取区域内的 Agent 列表 |
| Agent 详情 | `/api/v1/agents/{agent_id}` | GET | 获取 Agent 详细信息 |
| Agent 服务列表 | `/api/v1/agents/{agent_id}/packages` | GET | 获取 Agent 管理的服务 |
| Agent 健康状态 | `/api/v1/agents/{agent_id}/health` | GET | 获取 Agent 健康状态 |
| 服务健康状态 | `/api/v1/agents/{agent_id}/health/{package}` | GET | 获取服务健康状态 |
| 系统指标 | `/api/v1/agents/{agent_id}/metrics/system` | GET | 获取系统指标 |
| 服务指标 | `/api/v1/agents/{agent_id}/metrics/services` | GET | 获取服务指标 |
| 批量启动 | `/api/v1/agents/batch/start` | POST | 批量启动服务 |
| 批量停止 | `/api/v1/agents/batch/stop` | POST | 批量停止服务 |
| 批量重启 | `/api/v1/agents/batch/restart` | POST | 批量重启服务 |
| 批量配置 | `/api/v1/agents/batch/configs` | POST | 批量更新配置 |

## 九、下一步

1. **实现设备管理模块**：设备入库、设备信息管理、设备状态跟踪
2. **实现 Agent 部署服务**：部署流程、状态监控、日志记录
3. **实现 Agent 生命周期管理**：升级、卸载、配置更新
4. **实现监控和告警**：Controller 和 Agent 健康监控
5. **实现缓存机制**：优化查询性能

## 十、参考文档

- [分布式 Agent 关联系统说明文档](../.cursor/plans/分布式_agent_关联系统说明文档_d9e587a6.plan.md)
- Controller API 文档：`pkg/controller/api/agent_api.go`
- Agent 注册机制：`agentv2/INTEGRATION.md`


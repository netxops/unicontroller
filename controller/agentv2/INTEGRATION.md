# Agent V2 与 Controller 集成指南

## 概述

Agent V2 需要与 Controller 配合使用，通过服务注册机制让 Controller 发现并管理 Agent。本文档说明如何配置和使用 Agent V2 与 Controller 的集成。

## 架构关系

```
┌─────────────────┐         ┌─────────────────┐
│   Controller    │◄───────►│      etcd       │
│                 │         │   (服务注册中心)  │
└─────────────────┘         └─────────────────┘
         │                           ▲
         │ gRPC                       │ 服务注册
         │                            │
         ▼                            │
┌─────────────────┐                  │
│   Agent V2      │──────────────────┘
│                 │
│  - Package服务   │
│  - Command服务   │
│  - Health服务    │
│  - Metrics服务   │
└─────────────────┘
```

## 服务注册机制

### 1. Agent V2 向 etcd 注册

Agent V2 需要定期向 etcd 注册自己的服务信息，包括：
- Agent 标识码 (agent-code)
- gRPC 服务地址
- 服务元数据（包含已管理的服务列表）

### 2. Controller 发现 Agent

Controller 从 etcd 或 MongoDB 发现已注册的 Agent，并建立 gRPC 连接。

### 3. Controller 调用 Agent 服务

Controller 通过 gRPC 调用 Agent 的服务接口，使用 `agent-code` 作为标识。

## 配置步骤

### 步骤 1: 配置 Agent V2

编辑 `agentv2/configs/agentv2.yaml`：

```yaml
# Agent 配置
agent:
  code: "agent-001"  # Agent 标识码，必须唯一

# 服务注册配置
registry:
  enabled: true
  etcd_endpoints:
    - "127.0.0.1:2379"  # etcd 地址，必须与 Controller 使用相同的 etcd
  etcd_prefix: "/agents"
  register_interval: 30s
  ttl: 60s

# 服务器配置
server:
  grpc_port: 10380
  http_port: 8080
```

### 步骤 2: 配置 Controller

确保 Controller 的配置中包含 etcd 配置，Controller 会自动发现注册的 Agent。

### 步骤 3: 启动 Agent V2

```bash
cd agentv2/cmd/agentv2
go run main.go -config=../../configs/agentv2.yaml
```

Agent V2 启动后会：
1. 启动 gRPC 服务器
2. 启动 HTTP 服务器（健康检查、指标）
3. 向 etcd 注册服务信息
4. 定期刷新注册信息

## 服务注册实现

Agent V2 已经实现了服务注册功能（`pkg/registry/registry.go`），包括：

### 1. 服务注册信息结构

```go
type ServiceInfo struct {
    Key      string                 // 服务键（agent-code）
    Name     string                 // 服务名称: "agent"
    Protocol string                 // 协议: "grpc"
    Address  string                 // 地址: "ip:port"
    Meta     map[string]interface{} // 元数据
}
```

### 2. 注册到 etcd

Agent V2 会：
- 连接到 etcd
- 创建租约（Lease）
- 定期刷新租约（KeepAlive）
- 在服务信息中包含 agent-code 和已管理的服务列表

### 3. 元数据内容

注册时的元数据包含：
```json
{
  "agent_code": "agent-001",
  "services": [
    {
      "package": "service-1",
      "version": "1.0.0",
      "status": "running"
    }
  ]
}
```

## gRPC 协议兼容性

Agent V2 实现了与原有 Agent 相同的 gRPC 接口，确保与 Controller 的兼容：

### Package 服务

- `Start`: 启动服务
- `Stop`: 停止服务
- `Restart`: 重启服务
- `PackageList`: 列出所有服务
- `GetConfigs`: 获取配置
- `ApplyConfigs`: 应用配置
- `GetRecentLogs`: 获取最近日志

### Command 服务

- `ExecCommand`: 执行命令
- `ExecCommandSignal`: 发送命令信号
- `GetCommandStatus`: 获取命令状态

## 使用流程

### 1. Controller 发现 Agent

Controller 启动后，会从 etcd 或 MongoDB 发现已注册的 Agent。

### 2. Controller 连接 Agent

Controller 通过 gRPC 连接到 Agent，连接时在 metadata 中传递 `agent-code`。

### 3. Controller 管理服务

Controller 可以通过 gRPC 调用 Agent 的服务管理接口：
- 启动/停止/重启服务
- 查询服务状态
- 获取服务配置
- 执行命令

### 4. Agent 上报状态

Agent V2 定期向 etcd 更新服务状态，Controller 可以实时获取 Agent 及其管理的服务状态。

## 验证集成

### 1. 检查 Agent 注册

```bash
# 查看 etcd 中的注册信息
etcdctl get --prefix "/agents"
```

应该能看到类似以下内容：
```
/agents/agent/agent-001
{"key":"agent-001","name":"agent","protocol":"grpc","address":"192.168.1.100:10380","meta":{"agent_code":"agent-001","services":[]}}
```

### 2. 检查 Controller 连接

查看 Controller 日志，确认已发现并连接到 Agent V2。

### 3. 测试服务管理

通过 Controller API 测试服务管理功能：
```bash
# 列出 Agent 管理的服务
curl http://controller:8081/api/v1/agents

# 启动服务
curl -X POST http://controller:8081/api/v1/agents/agent-001/packages/my-service/start
```

## 故障排查

### Agent 未被发现

1. 检查 etcd 连接：确认 Agent V2 能连接到 etcd
2. 检查注册信息：查看 etcd 中是否有 Agent 的注册信息
3. 检查 agent-code：确认 agent-code 配置正确且唯一

### gRPC 连接失败

1. 检查网络连通性：确认 Controller 能访问 Agent 的 gRPC 端口
2. 检查防火墙：确认端口未被防火墙阻止
3. 检查 agent-code：确认 metadata 中的 agent-code 正确

### 服务管理失败

1. 检查服务状态：确认服务已正确注册到 Agent V2
2. 查看 Agent 日志：检查 Agent V2 的日志输出
3. 检查权限：确认 Agent V2 有足够的权限管理服务

## 与原有 Agent 的兼容性

Agent V2 与原有 Agent 可以并行运行：

- **协议兼容**: 使用相同的 gRPC 协议
- **注册兼容**: 使用相同的 etcd 注册机制
- **数据隔离**: 使用不同的 agent-code 区分

## 迁移建议

1. **阶段一**: 并行运行，验证功能
2. **阶段二**: 逐步切换部分服务到 Agent V2
3. **阶段三**: 完全切换到 Agent V2
4. **阶段四**: 保留原 Agent 作为备份（可选）

## 相关文档

- [Controller 升级指南](./CONTROLLER_UPGRADE.md) - Controller 升级到支持 Agent V2 的详细指南
- [Agent 集中化管理指南](./AGENT_CENTRALIZED_MANAGEMENT.md) - 通过 Controller 集中化管理多个 Agent 的指南

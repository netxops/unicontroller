# Agent V2 快速开始指南

## Agent V2 与 Controller 配合使用

### 1. 启动 etcd（如果还没有运行）

```bash
# 使用 Docker 启动 etcd
docker run -d \
  --name etcd \
  -p 2379:2379 \
  -p 2380:2380 \
  quay.io/coreos/etcd:v3.5.0 \
  /usr/local/bin/etcd \
  --name etcd \
  --data-dir /etcd-data \
  --listen-client-urls http://0.0.0.0:2379 \
  --advertise-client-urls http://localhost:2379 \
  --listen-peer-urls http://0.0.0.0:2380 \
  --initial-advertise-peer-urls http://localhost:2380 \
  --initial-cluster etcd=http://localhost:2380
```

### 2. 配置 Agent V2

编辑 `agentv2/configs/agentv2.yaml`：

```yaml
agent:
  code: "agent-001"  # 必须唯一，用于标识此 Agent

registry:
  enabled: true
  etcd_endpoints:
    - "127.0.0.1:2379"
  etcd_prefix: "/agents"
  register_interval: 30s

server:
  grpc_port: 10380
  http_port: 8080
```

### 3. 启动 Agent V2

```bash
cd agentv2/cmd/agentv2
go run main.go -config=../../configs/agentv2.yaml
```

### 4. 启动 Controller

确保 Controller 配置了相同的 etcd 地址，Controller 会自动发现 Agent V2。

### 5. 验证集成

#### 检查 Agent 注册

```bash
# 查看 etcd 中的注册信息
etcdctl get --prefix "/agents"
```

应该能看到类似以下内容：
```
/agents/agent/agent-001
{"key":"agent-001","name":"agent","protocol":"grpc","address":"192.168.1.100:10380","meta":{"agent_code":"agent-001","services":[]}}
```

#### 通过 Controller API 查询

```bash
# 列出所有 Agent
curl http://localhost:8081/api/v1/agents

# 应该能看到 agent-001
```

## 工作流程

1. **Agent V2 启动** → 向 etcd 注册服务信息
2. **Controller 发现** → 从 etcd 读取 Agent 信息
3. **Controller 连接** → 通过 gRPC 连接到 Agent V2
4. **服务管理** → Controller 通过 gRPC 调用 Agent V2 的服务管理接口

## 关键点

- **agent-code**: 必须唯一，用于区分不同的 Agent
- **etcd 地址**: Agent V2 和 Controller 必须使用相同的 etcd
- **gRPC 端口**: 确保端口未被占用，且 Controller 能访问
- **服务注册**: Agent V2 会定期刷新注册信息，保持租约活跃

## 常见问题

### Q: Controller 找不到 Agent V2？

A: 检查以下几点：
1. etcd 是否正常运行
2. Agent V2 的 etcd 配置是否正确
3. 查看 Agent V2 日志，确认注册成功
4. 使用 `etcdctl get --prefix "/agents"` 查看注册信息

### Q: gRPC 连接失败？

A: 检查以下几点：
1. Agent V2 的 gRPC 端口是否正常监听
2. 网络连通性（防火墙、路由等）
3. Controller 日志中的错误信息

### Q: 如何区分 Agent V2 和原 Agent？

A: 通过不同的 agent-code 区分，例如：
- 原 Agent: `agent-001`
- Agent V2: `agentv2-001`

## 下一步

- 查看 [INTEGRATION.md](INTEGRATION.md) 了解详细的集成说明
- 查看 [ARCHITECTURE.md](ARCHITECTURE.md) 了解架构设计
- 查看 [USAGE.md](USAGE.md) 了解使用指南


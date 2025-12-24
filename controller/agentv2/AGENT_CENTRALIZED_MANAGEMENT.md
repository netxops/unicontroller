# Agent 集中化管理指南

## 概述

本文档说明如何通过 Controller 实现对多个 Agent V2 的集中化管理，包括 Agent 发现、状态监控、批量操作和统一配置管理。

## 架构图

```
┌─────────────────────────────────────────────────────────┐
│                    Controller                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ AgentManager │  │ ConfigMgr   │  │ Monitor      │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
└─────────────────────────────────────────────────────────┘
         │                    │                    │
         │ gRPC               │ etcd               │ MongoDB
         │                    │                    │
    ┌────┴────┬───────────────┴───────────────┬────┴────┐
    │         │                               │         │
┌───▼───┐ ┌───▼───┐                     ┌───▼───┐ ┌───▼───┐
│Agent-1│ │Agent-2│      ...            │Agent-N│ │ etcd  │
└───────┘ └───────┘                     └───────┘ └───────┘
```

## 核心功能

### 1. Agent 自动发现

Controller 通过 etcd 自动发现注册的 Agent V2：

- **服务注册**: Agent V2 启动后自动向 etcd 注册
- **状态同步**: Agent V2 定期更新注册信息（心跳）
- **自动发现**: Controller 监听 etcd 变化，自动发现新 Agent
- **状态管理**: Controller 维护 Agent 在线/离线状态

### 2. 统一状态监控

Controller 提供统一的 Agent 状态监控：

- **Agent 列表**: 查看所有 Agent 及其状态
- **服务状态**: 查看每个 Agent 管理的服务状态
- **健康状态**: 查看 Agent 和服务健康状态
- **指标监控**: 查看系统和服务的指标数据

### 3. 批量操作

支持对多个 Agent 执行批量操作：

- **批量启动/停止**: 批量管理服务
- **批量配置更新**: 批量更新服务配置
- **批量部署**: 批量部署新服务
- **批量重启**: 批量重启服务

### 4. 统一配置管理

通过 Controller 统一管理 Agent 配置：

- **配置模板**: 定义配置模板，批量应用
- **配置版本**: 管理配置版本，支持回滚
- **配置分发**: 自动分发配置到指定 Agent
- **配置验证**: 配置更新前验证

## 配置说明

### Controller 配置

```yaml
# deploy/controller.yaml

# Agent 管理配置
agent:
  # 自动发现配置
  discovery:
    enabled: true
    etcd_endpoints:
      - "127.0.0.1:2379"
    etcd_prefix: "/agents"
    watch_interval: 10s
  
  # 连接配置
  connection:
    timeout: 5s
    retry_times: 3
    retry_interval: 1s
  
  # 健康检查配置
  health_check:
    enabled: true
    interval: 30s
    timeout: 5s
  
  # 指标收集配置
  metrics:
    enabled: true
    collect_interval: 60s
    retention: 24h

# MongoDB 配置（Agent 状态存储）
mongodb:
  uri: "mongodb://localhost:27017"
  database: "controller"
  collection: "agents"
```

### Agent V2 配置

```yaml
# agentv2/configs/agentv2.yaml

# Agent 标识
agent:
  code: "agent-001"  # 必须唯一
  name: "Agent-001"
  area: "area-1"     # 区域标识（可选）
  zone: "zone-1"     # 可用区标识（可选）

# 服务注册配置
registry:
  enabled: true
  etcd_endpoints:
    - "127.0.0.1:2379"  # 必须与 Controller 一致
  etcd_prefix: "/agents"
  register_interval: 30s
  ttl: 60s

# 服务器配置
server:
  grpc_port: 10380
  http_port: 8080
  # 如果绑定到 0.0.0.0，Agent 会自动获取本机 IP
  grpc_address: "0.0.0.0:10380"
```

## API 使用

### 1. 列出所有 Agent

```bash
# 获取所有 Agent
curl http://controller:8081/api/v1/agents

# 带过滤条件
curl "http://controller:8081/api/v1/agents?status=online&area=area-1"

# 分页查询
curl "http://controller:8081/api/v1/agents?page=1&pageSize=20"
```

响应示例：
```json
{
  "agents": [
    {
      "id": "agent-001",
      "area_id": "area-1",
      "address": "192.168.1.100:10380",
      "hostname": "server-01",
      "status": "online",
      "version": "v2.0.0",
      "last_heartbeat": "2024-01-01T12:00:00Z",
      "services": [
        {
          "name": "service-1",
          "version": "1.0.0",
          "is_running": true,
          "duration": 3600
        }
      ]
    }
  ],
  "total": 10,
  "page": 1,
  "pageSize": 20
}
```

### 2. 获取 Agent 详情

```bash
curl http://controller:8081/api/v1/agents/agent-001
```

### 3. 获取 Agent 管理的服务

```bash
curl http://controller:8081/api/v1/agents/agent-001/packages
```

### 4. 批量操作服务

```bash
# 批量启动服务
curl -X POST http://controller:8081/api/v1/agents/batch/start \
  -H "Content-Type: application/json" \
  -d '{
    "agents": ["agent-001", "agent-002"],
    "packages": ["service-1", "service-2"]
  }'

# 批量停止服务
curl -X POST http://controller:8081/api/v1/agents/batch/stop \
  -H "Content-Type: application/json" \
  -d '{
    "agents": ["agent-001", "agent-002"],
    "packages": ["service-1"]
  }'
```

### 5. 获取 Agent 健康状态

```bash
# 获取单个 Agent 的健康状态
curl http://controller:8081/api/v1/agents/agent-001/health

# 获取所有 Agent 的健康状态
curl http://controller:8081/api/v1/agents/health
```

### 6. 获取 Agent 指标

```bash
# 获取 Agent 系统指标
curl http://controller:8081/api/v1/agents/agent-001/metrics/system

# 获取 Agent 服务指标
curl http://controller:8081/api/v1/agents/agent-001/metrics/services
```

## 管理场景

### 场景 1: 部署新服务到多个 Agent

```bash
# 1. 准备服务配置
cat > service-config.yaml <<EOF
name: my-service
version: 1.0.0
startup:
  method: direct
  command: /usr/bin/my-service
EOF

# 2. 批量部署
curl -X POST http://controller:8081/api/v1/agents/batch/deploy \
  -H "Content-Type: application/json" \
  -d '{
    "agents": ["agent-001", "agent-002", "agent-003"],
    "package": "my-service",
    "config": "'$(cat service-config.yaml | base64)'"
  }'
```

### 场景 2: 批量更新配置

```bash
# 1. 准备新配置
cat > new-config.yaml <<EOF
database:
  host: new-db.example.com
  port: 5432
EOF

# 2. 批量更新
curl -X POST http://controller:8081/api/v1/agents/batch/configs \
  -H "Content-Type: application/json" \
  -d '{
    "agents": ["agent-001", "agent-002"],
    "package": "my-service",
    "config_file": "config.yaml",
    "content": "'$(cat new-config.yaml | base64)'"
  }'
```

### 场景 3: 监控所有 Agent 状态

```bash
# 1. 获取所有 Agent 状态
AGENTS=$(curl -s http://controller:8081/api/v1/agents | jq -r '.agents[].id')

# 2. 检查每个 Agent 的健康状态
for agent in $AGENTS; do
  echo "Checking $agent..."
  curl -s http://controller:8081/api/v1/agents/$agent/health | jq '.'
done
```

### 场景 4: 批量重启服务

```bash
# 批量重启指定服务
curl -X POST http://controller:8081/api/v1/agents/batch/restart \
  -H "Content-Type: application/json" \
  -d '{
    "agents": ["agent-001", "agent-002"],
    "packages": ["service-1"]
  }'
```

## 监控和告警

### 1. Agent 离线告警

Controller 可以检测 Agent 离线并发送告警：

```yaml
# Controller 配置
alerts:
  agent_offline:
    enabled: true
    threshold: 60s  # Agent 超过 60 秒未心跳则告警
    channels:
      - email
      - webhook
```

### 2. 服务健康告警

监控服务健康状态：

```bash
# 获取不健康的服务
curl http://controller:8081/api/v1/agents/health/unhealthy
```

### 3. 指标监控

集成 Prometheus 监控：

```yaml
# Prometheus 配置
scrape_configs:
  - job_name: 'controller'
    static_configs:
      - targets: ['controller:8081']
    metrics_path: '/metrics'
```

## 最佳实践

### 1. Agent 命名规范

- 使用有意义的 Agent Code：`{area}-{zone}-{hostname}`
- 例如：`area1-zone1-server01`

### 2. 区域和可用区规划

- 使用 `area` 和 `zone` 标识组织 Agent
- 便于批量操作和故障隔离

### 3. 配置管理

- 使用配置模板，避免重复配置
- 版本化管理配置，支持快速回滚
- 配置更新前进行验证

### 4. 监控策略

- 设置合理的健康检查间隔
- 配置告警规则，及时发现问题
- 定期检查 Agent 和服务状态

### 5. 批量操作

- 批量操作前先在小范围测试
- 使用分批执行，避免同时影响所有 Agent
- 操作后验证结果

## 故障排查

### Agent 未被发现

1. **检查 etcd 连接**
   ```bash
   etcdctl endpoint health
   ```

2. **检查 Agent 注册信息**
   ```bash
   etcdctl get --prefix "/agents"
   ```

3. **检查 Agent 配置**
   - 确认 `agent.code` 唯一
   - 确认 `registry.enabled = true`
   - 确认 etcd 地址正确

### Agent 状态异常

1. **检查 Agent 日志**
   ```bash
   tail -f /var/log/agentv2/agentv2.log
   ```

2. **检查网络连通性**
   ```bash
   telnet agent-ip 10380
   ```

3. **检查 Controller 日志**
   ```bash
   tail -f /var/log/controller/controller.log
   ```

### 批量操作失败

1. **检查部分成功情况**
   - 查看操作结果，确认哪些 Agent 成功/失败
   - 针对失败的 Agent 单独处理

2. **检查 Agent 状态**
   - 确认 Agent 在线
   - 确认服务存在

3. **检查权限**
   - 确认 Agent 有足够权限执行操作

## 性能优化

### 1. 连接池管理

Controller 维护与 Agent 的连接池：

```yaml
agent:
  connection:
    pool_size: 10      # 连接池大小
    max_idle: 5       # 最大空闲连接
    idle_timeout: 5m  # 空闲连接超时
```

### 2. 批量操作优化

- 使用并发执行，提高批量操作效率
- 设置合理的超时时间
- 使用异步操作，避免长时间阻塞

### 3. 监控数据优化

- 合理设置指标收集间隔
- 使用数据聚合，减少存储空间
- 定期清理历史数据

## 安全考虑

### 1. 认证和授权

- 使用 TLS 加密 gRPC 连接
- 实现 Agent 认证机制
- 控制 Controller 访问权限

### 2. 网络安全

- 使用防火墙限制访问
- 使用 VPN 或专网连接
- 定期更新安全补丁

### 3. 数据安全

- 加密敏感配置信息
- 定期备份数据
- 审计操作日志

## 总结

通过 Controller 集中化管理 Agent V2，可以实现：

- ✅ 统一的 Agent 发现和状态管理
- ✅ 批量操作，提高管理效率
- ✅ 统一监控和告警
- ✅ 配置集中管理
- ✅ 故障快速定位和处理

建议在生产环境中逐步采用这些功能，提高运维效率。


# Controller 和 Agent 集中化管理测试验证文档

## 概述

本文档提供 Controller 升级后和 Agent V2 集中化管理功能的测试验证步骤，包括功能测试、API 测试和集成测试。

## 前置条件

### 环境准备

1. **etcd 服务运行**
   ```bash
   # 检查 etcd 状态
   etcdctl endpoint health
   ```

2. **MongoDB 服务运行**
   ```bash
   # 检查 MongoDB 连接
   mongosh --eval "db.adminCommand('ping')"
   ```

3. **Agent V2 运行**
   ```bash
   # 启动 Agent V2
   cd agentv2/cmd/agentv2
   go run main.go -config=../../configs/agentv2.yaml
   ```

4. **Controller 运行**
   ```bash
   # 启动 Controller
   cd cmd/controller
   go run main.go -config=../../deploy/controller.yaml
   ```

## 一、Agent V2 测试验证

### 1.1 Agent 注册验证

**测试步骤：**

1. 启动 Agent V2
2. 检查 etcd 中的注册信息

**验证命令：**

```bash
# 查看 etcd 中的 Agent 注册信息
etcdctl get --prefix "grpc://server-agent/"

# 应该看到类似以下内容：
# grpc://server-agent/192.168.1.100:10380
# {"Op":0,"Addr":"192.168.1.100:10380","MetadataX":{...}}
```

**预期结果：**
- Agent 信息已注册到 etcd
- 包含正确的 agent-code 和地址信息
- 包含服务列表信息（如果有服务）

### 1.2 gRPC 服务验证

**测试步骤：**

使用 `grpcurl` 测试 gRPC 服务：

```bash
# 列出所有服务
grpcurl -plaintext localhost:10380 list

# 测试 Package 服务
grpcurl -plaintext -d '{}' localhost:10380 pb.Package/PackageList

# 测试 Health 服务
grpcurl -plaintext -d '{"package":"test-service"}' localhost:10380 pb.Health/GetHealthStatus

# 测试 Metrics 服务
grpcurl -plaintext -d '{}' localhost:10380 pb.Metrics/GetSystemMetrics
```

**预期结果：**
- 所有服务都能正常响应
- 返回正确的数据格式

### 1.3 HTTP 端点验证

**测试步骤：**

```bash
# 健康检查
curl http://localhost:8080/health

# 指标端点
curl http://localhost:8080/metrics
```

**预期结果：**
- 返回 200 状态码
- 健康检查返回 `{"status":"healthy"}`
- 指标端点返回 Prometheus 格式数据

## 二、Controller 测试验证

### 2.1 Agent 自动发现验证

**测试步骤：**

1. 启动 Controller
2. 检查 Controller 日志，确认 Agent 发现

**验证命令：**

```bash
# 查看 Controller 日志
tail -f /var/log/controller/controller.log | grep -i "agent"

# 应该看到类似日志：
# Agent registered/updated agent_id=agent-001 address=192.168.1.100:10380
```

**API 验证：**

```bash
# 列出所有 Agent
curl http://localhost:8081/api/v1/agents

# 预期响应：
# {
#   "agents": [
#     {
#       "id": "agent-001",
#       "address": "192.168.1.100:10380",
#       "status": "online",
#       "version": "v2",
#       ...
#     }
#   ],
#   "total": 1,
#   "page": 1,
#   "pageSize": 10
# }
```

**预期结果：**
- Agent 自动出现在 Agent 列表中
- Agent 状态为 "online"
- 包含正确的地址和版本信息

### 2.2 Agent 详情查询验证

**测试步骤：**

```bash
# 获取 Agent 详情
curl http://localhost:8081/api/v1/agents/agent-001

# 获取 Agent 管理的服务列表
curl http://localhost:8081/api/v1/agents/agent-001/packages
```

**预期结果：**
- 返回完整的 Agent 信息
- 包含服务列表
- 包含健康状态和指标信息（如果已配置）

### 2.3 健康监控验证

**测试步骤：**

```bash
# 获取 Agent 所有服务的健康状态
curl http://localhost:8081/api/v1/agents/agent-001/health

# 获取指定服务的健康状态
curl http://localhost:8081/api/v1/agents/agent-001/health/my-service
```

**预期响应示例：**

```json
{
  "overall_status": "HEALTH_STATUS_HEALTHY",
  "total_services": 2,
  "healthy": 2,
  "unhealthy": 0,
  "degraded": 0,
  "unknown": 0,
  "services": [...]
}
```

**预期结果：**
- 返回正确的健康状态
- 包含服务健康详情
- 支持健康状态过滤

### 2.4 指标查询验证

**测试步骤：**

```bash
# 获取系统指标
curl http://localhost:8081/api/v1/agents/agent-001/metrics/system

# 获取所有服务指标
curl http://localhost:8081/api/v1/agents/agent-001/metrics/services

# 获取指定服务指标
curl "http://localhost:8081/api/v1/agents/agent-001/metrics/services?package=my-service"
```

**预期响应示例：**

```json
{
  "cpu_usage": 25.5,
  "memory_usage": 60.2,
  "memory_total": 8589934592,
  "memory_free": 3435973836,
  "disk_usage": 45.8,
  ...
}
```

**预期结果：**
- 返回系统指标数据
- 返回服务指标数据
- 指标数据格式正确

### 2.5 批量操作验证

#### 2.5.1 批量启动服务

**测试步骤：**

```bash
curl -X POST http://localhost:8081/api/v1/agents/batch/start \
  -H "Content-Type: application/json" \
  -d '{
    "agents": ["agent-001", "agent-002"],
    "packages": ["service-1", "service-2"]
  }'
```

**预期响应：**

```json
{
  "total": 4,
  "success": 4,
  "failed": 0,
  "duration_ms": 1250,
  "results": [
    {
      "agent_code": "agent-001",
      "package": "service-1",
      "success": true,
      "message": "Started successfully"
    },
    ...
  ]
}
```

#### 2.5.2 批量停止服务

**测试步骤：**

```bash
curl -X POST http://localhost:8081/api/v1/agents/batch/stop \
  -H "Content-Type: application/json" \
  -d '{
    "agents": ["agent-001"],
    "packages": ["service-1"]
  }'
```

#### 2.5.3 批量重启服务

**测试步骤：**

```bash
curl -X POST http://localhost:8081/api/v1/agents/batch/restart \
  -H "Content-Type: application/json" \
  -d '{
    "agents": ["agent-001"],
    "packages": ["service-1"]
  }'
```

#### 2.5.4 批量更新配置

**测试步骤：**

```bash
curl -X POST http://localhost:8081/api/v1/agents/batch/configs \
  -H "Content-Type: application/json" \
  -d '{
    "agents": ["agent-001"],
    "package": "my-service",
    "configs": [
      {
        "file_name": "config.yaml",
        "content": "key: new_value\n"
      }
    ]
  }'
```

**预期结果：**
- 批量操作成功执行
- 返回详细的操作结果
- 包含成功/失败统计
- 单个失败不影响其他操作

## 三、集成测试验证

### 3.1 端到端流程测试

**测试场景：Agent 注册 → 发现 → 管理**

1. **启动 Agent V2**
   ```bash
   cd agentv2/cmd/agentv2
   go run main.go -config=../../configs/agentv2.yaml
   ```

2. **验证 Agent 注册**
   ```bash
   etcdctl get --prefix "grpc://server-agent/"
   ```

3. **启动 Controller**
   ```bash
   cd cmd/controller
   go run main.go -config=../../deploy/controller.yaml
   ```

4. **验证 Controller 发现 Agent**
   ```bash
   curl http://localhost:8081/api/v1/agents
   ```

5. **验证服务管理**
   ```bash
   # 启动服务
   curl -X POST http://localhost:8081/api/v1/agents/agent-001/packages/my-service/start
   
   # 查询健康状态
   curl http://localhost:8081/api/v1/agents/agent-001/health/my-service
   
   # 查询指标
   curl http://localhost:8081/api/v1/agents/agent-001/metrics/services?package=my-service
   ```

**预期结果：**
- 整个流程顺畅执行
- 各步骤返回正确结果
- 无错误或异常

### 3.2 多 Agent 场景测试

**测试步骤：**

1. 启动多个 Agent V2（使用不同的 agent-code）
2. 验证 Controller 能发现所有 Agent
3. 验证批量操作能同时操作多个 Agent

```bash
# 启动 Agent 1
AGENT_CODE=agent-001 go run main.go -config=../../configs/agentv2.yaml

# 启动 Agent 2（另一个终端）
AGENT_CODE=agent-002 go run main.go -config=../../configs/agentv2.yaml

# 验证发现
curl http://localhost:8081/api/v1/agents

# 批量操作
curl -X POST http://localhost:8081/api/v1/agents/batch/start \
  -H "Content-Type: application/json" \
  -d '{
    "agents": ["agent-001", "agent-002"],
    "packages": ["service-1"]
  }'
```

**预期结果：**
- 所有 Agent 都被发现
- 批量操作能同时处理多个 Agent
- 操作结果正确汇总

## 四、功能验证清单

### Agent V2 功能验证

- [ ] Agent 能正常启动
- [ ] Agent 能注册到 etcd
- [ ] gRPC 服务正常响应
- [ ] HTTP 端点正常响应
- [ ] 健康检查服务正常
- [ ] 指标服务正常
- [ ] 日志服务正常

### Controller 功能验证

- [ ] Agent 自动发现功能正常
- [ ] Agent 列表查询正常
- [ ] Agent 详情查询正常
- [ ] 服务列表查询正常
- [ ] 健康状态查询正常
- [ ] 指标查询正常
- [ ] 批量启动功能正常
- [ ] 批量停止功能正常
- [ ] 批量重启功能正常
- [ ] 批量配置更新正常

### 集成验证

- [ ] Agent 注册后 Controller 能自动发现
- [ ] Agent 离线后 Controller 能更新状态
- [ ] 批量操作能正确处理多个 Agent
- [ ] 健康监控能实时反映服务状态
- [ ] 指标查询能获取准确数据

## 五、常见问题排查

### 问题 1: Agent 未被 Controller 发现

**排查步骤：**

1. 检查 etcd 连接
   ```bash
   etcdctl endpoint health
   ```

2. 检查 Agent 注册信息
   ```bash
   etcdctl get --prefix "grpc://server-agent/"
   ```

3. 检查 Controller 日志
   ```bash
   tail -f /var/log/controller/controller.log | grep -i "agent\|discovery"
   ```

4. 检查配置一致性
   - Agent 和 Controller 使用相同的 etcd 地址
   - Agent 的 watchPrefix 配置正确

### 问题 2: gRPC 连接失败

**排查步骤：**

1. 检查网络连通性
   ```bash
   telnet agent-ip 10380
   ```

2. 检查防火墙规则
   ```bash
   # Linux
   sudo iptables -L -n | grep 10380
   ```

3. 检查 Agent 是否运行
   ```bash
   ps aux | grep agentv2
   ```

### 问题 3: 批量操作部分失败

**排查步骤：**

1. 查看操作结果详情
   ```json
   {
     "results": [
       {
         "agent_code": "agent-001",
         "package": "service-1",
         "success": false,
         "error": "具体错误信息"
       }
     ]
   }
   ```

2. 检查失败的 Agent 状态
   ```bash
   curl http://localhost:8081/api/v1/agents/agent-001
   ```

3. 检查服务是否存在
   ```bash
   curl http://localhost:8081/api/v1/agents/agent-001/packages
   ```

### 问题 4: 健康状态查询失败

**排查步骤：**

1. 确认 Agent V2 支持 Health 服务
   - 检查 Agent 版本是否为 v2
   - 检查 Health 服务是否已实现

2. 检查 gRPC 连接
   ```bash
   grpcurl -plaintext localhost:10380 list | grep Health
   ```

3. 直接测试 Health 服务
   ```bash
   grpcurl -plaintext -d '{"package":"my-service"}' \
     localhost:10380 pb.Health/GetHealthStatus
   ```

## 六、性能测试

### 6.1 批量操作性能测试

**测试场景：** 对 10 个 Agent 的 5 个服务执行批量启动

```bash
# 准备测试数据
AGENTS='["agent-001","agent-002",...,"agent-010"]'
PACKAGES='["service-1","service-2","service-3","service-4","service-5"]'

# 执行批量操作
time curl -X POST http://localhost:8081/api/v1/agents/batch/start \
  -H "Content-Type: application/json" \
  -d "{\"agents\":$AGENTS,\"packages\":$PACKAGES}"
```

**预期指标：**
- 50 个操作应在 5 秒内完成
- 成功率 > 95%
- 无资源泄漏

### 6.2 并发查询测试

**测试场景：** 同时查询 10 个 Agent 的健康状态

```bash
# 使用并发请求
for i in {1..10}; do
  curl http://localhost:8081/api/v1/agents/agent-00$i/health &
done
wait
```

**预期结果：**
- 所有请求都能正常响应
- 响应时间 < 2 秒
- 无错误

## 七、测试脚本示例

### 7.1 完整测试脚本

```bash
#!/bin/bash

# 测试配置
CONTROLLER_URL="http://localhost:8081"
AGENT_ID="agent-001"

echo "=== 开始测试验证 ==="

# 1. 测试 Agent 列表
echo "1. 测试 Agent 列表..."
curl -s "$CONTROLLER_URL/api/v1/agents" | jq '.agents | length'
if [ $? -eq 0 ]; then
  echo "✓ Agent 列表查询成功"
else
  echo "✗ Agent 列表查询失败"
  exit 1
fi

# 2. 测试 Agent 详情
echo "2. 测试 Agent 详情..."
curl -s "$CONTROLLER_URL/api/v1/agents/$AGENT_ID" | jq '.id'
if [ $? -eq 0 ]; then
  echo "✓ Agent 详情查询成功"
else
  echo "✗ Agent 详情查询失败"
fi

# 3. 测试服务列表
echo "3. 测试服务列表..."
curl -s "$CONTROLLER_URL/api/v1/agents/$AGENT_ID/packages" | jq '.packages | length'
if [ $? -eq 0 ]; then
  echo "✓ 服务列表查询成功"
else
  echo "✗ 服务列表查询失败"
fi

# 4. 测试健康状态
echo "4. 测试健康状态..."
curl -s "$CONTROLLER_URL/api/v1/agents/$AGENT_ID/health" | jq '.overall_status'
if [ $? -eq 0 ]; then
  echo "✓ 健康状态查询成功"
else
  echo "✗ 健康状态查询失败"
fi

# 5. 测试系统指标
echo "5. 测试系统指标..."
curl -s "$CONTROLLER_URL/api/v1/agents/$AGENT_ID/metrics/system" | jq '.cpu_usage'
if [ $? -eq 0 ]; then
  echo "✓ 系统指标查询成功"
else
  echo "✗ 系统指标查询失败"
fi

# 6. 测试批量操作
echo "6. 测试批量操作..."
curl -s -X POST "$CONTROLLER_URL/api/v1/agents/batch/start" \
  -H "Content-Type: application/json" \
  -d '{"agents":["'$AGENT_ID'"],"packages":["test-service"]}' | jq '.success'
if [ $? -eq 0 ]; then
  echo "✓ 批量操作成功"
else
  echo "✗ 批量操作失败"
fi

echo "=== 测试完成 ==="
```

### 7.2 使用说明

```bash
# 赋予执行权限
chmod +x test_verification.sh

# 运行测试
./test_verification.sh
```

## 八、验证结果记录

### 测试环境信息

- **测试日期**: ___________
- **Controller 版本**: ___________
- **Agent V2 版本**: ___________
- **etcd 版本**: ___________
- **MongoDB 版本**: ___________

### 测试结果

| 功能模块 | 测试项 | 状态 | 备注 |
|---------|--------|------|------|
| Agent 注册 | etcd 注册 | ☐ 通过 ☐ 失败 | |
| Agent 注册 | 服务信息 | ☐ 通过 ☐ 失败 | |
| Controller 发现 | 自动发现 | ☐ 通过 ☐ 失败 | |
| Controller 发现 | 状态同步 | ☐ 通过 ☐ 失败 | |
| API 查询 | Agent 列表 | ☐ 通过 ☐ 失败 | |
| API 查询 | Agent 详情 | ☐ 通过 ☐ 失败 | |
| API 查询 | 服务列表 | ☐ 通过 ☐ 失败 | |
| 健康监控 | 健康状态查询 | ☐ 通过 ☐ 失败 | |
| 健康监控 | 健康历史查询 | ☐ 通过 ☐ 失败 | |
| 指标查询 | 系统指标 | ☐ 通过 ☐ 失败 | |
| 指标查询 | 服务指标 | ☐ 通过 ☐ 失败 | |
| 批量操作 | 批量启动 | ☐ 通过 ☐ 失败 | |
| 批量操作 | 批量停止 | ☐ 通过 ☐ 失败 | |
| 批量操作 | 批量重启 | ☐ 通过 ☐ 失败 | |
| 批量操作 | 批量配置 | ☐ 通过 ☐ 失败 | |

### 性能指标

- **Agent 发现延迟**: ___________
- **批量操作耗时**: ___________
- **API 响应时间**: ___________
- **并发处理能力**: ___________

## 九、快速验证命令汇总

```bash
# 1. 检查 Agent 注册
etcdctl get --prefix "grpc://server-agent/"

# 2. 检查 Agent 列表
curl http://localhost:8081/api/v1/agents | jq

# 3. 检查 Agent 详情
curl http://localhost:8081/api/v1/agents/agent-001 | jq

# 4. 检查健康状态
curl http://localhost:8081/api/v1/agents/agent-001/health | jq

# 5. 检查系统指标
curl http://localhost:8081/api/v1/agents/agent-001/metrics/system | jq

# 6. 测试批量操作
curl -X POST http://localhost:8081/api/v1/agents/batch/start \
  -H "Content-Type: application/json" \
  -d '{"agents":["agent-001"],"packages":["test-service"]}' | jq
```

## 十、注意事项

1. **测试前准备**
   - 确保所有服务正常运行
   - 检查网络连通性
   - 备份重要数据

2. **测试环境**
   - 建议在测试环境先验证
   - 避免在生产环境直接测试批量操作

3. **错误处理**
   - 记录所有错误信息
   - 检查日志文件
   - 验证配置正确性

4. **性能考虑**
   - 批量操作有并发限制（默认 10）
   - 大量操作可能需要较长时间
   - 注意资源使用情况

## 总结

完成以上测试验证后，Controller 的 Agent 集中化管理功能应该能够正常工作。如遇到问题，请参考"常见问题排查"部分或查看相关日志文件。

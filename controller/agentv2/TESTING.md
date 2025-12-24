# Agent V2 测试指南

## 集成测试

### 1. 验证 Agent 发现

```bash
# 查询所有 Agent
curl http://localhost:8081/api/v1/agents

# 应该返回：
# {
#   "agents": [{
#     "id": "agent-001",
#     "status": "online",
#     "address": "192.168.0.199:10380",
#     "services": []
#   }],
#   "total": 1
# }
```

### 2. 测试 gRPC 连接

```bash
# 使用 grpcurl 测试连接（需要重启 Agent V2 后生效）
grpcurl -plaintext 192.168.0.199:10380 list

# 应该能看到：
# pb.Package
# pb.Command
# grpc.reflection.v1alpha.ServerReflection

# 查看 Package 服务的方法
grpcurl -plaintext 192.168.0.199:10380 list pb.Package

# 查看 Command 服务的方法
grpcurl -plaintext 192.168.0.199:10380 list pb.Command
```

### 3. 测试服务管理（需要先有服务）

```bash
# 启动服务
curl -X POST http://localhost:8081/api/v1/agents/agent-001/packages/my-service/start

# 停止服务
curl -X POST http://localhost:8081/api/v1/agents/agent-001/packages/my-service/stop

# 重启服务
curl -X POST http://localhost:8081/api/v1/agents/agent-001/packages/my-service/restart

# 获取服务列表
curl http://localhost:8081/api/v1/agents/agent-001/packages
```

### 4. 验证服务注册更新

当 Agent V2 管理服务后，注册信息中的 `services` 数组会自动更新：

```bash
# 查看 etcd 中的注册信息
etcdctl get "grpc://server-agent/192.168.0.199:10380"

# 应该能看到 services 数组包含服务信息
```

### 5. 监控 Agent 状态

```bash
# 定期查询 Agent 状态
watch -n 5 'curl -s http://localhost:8081/api/v1/agents | jq'

# 观察 status 字段是否保持为 "online"
```

## 功能测试

### 健康检查

```bash
# Agent V2 HTTP 健康检查
curl http://192.168.0.199:8080/health

# 应该返回：
# {"status":"healthy"}
```

### 指标收集

```bash
# Agent V2 HTTP 指标端点
curl http://192.168.0.199:8080/metrics

# 应该返回指标数据（如果已实现）
```

## 故障排查

### Agent 状态变为 offline

1. 检查 Agent V2 是否运行
2. 检查 etcd 连接
3. 查看 Agent V2 日志
4. 检查网络连通性

### Controller 无法连接 Agent

1. 验证 gRPC 端口是否开放
2. 检查防火墙规则
3. 测试网络连通性：`telnet 192.168.0.199 10380`

### 服务管理失败

1. 检查 Agent V2 日志
2. 验证服务是否已注册到 Agent V2
3. 检查权限（systemd 操作需要相应权限）

## 性能测试

### 并发请求测试

```bash
# 使用 Apache Bench 测试
ab -n 1000 -c 10 http://localhost:8081/api/v1/agents
```

### 负载测试

```bash
# 使用 wrk 测试
wrk -t4 -c100 -d30s http://localhost:8081/api/v1/agents
```

## 集成验证清单

- [x] Agent V2 成功注册到 etcd
- [x] Controller 能够发现 Agent V2
- [x] Agent 状态显示为 "online"
- [ ] gRPC 连接测试通过
- [ ] 服务管理功能测试通过
- [ ] 健康检查功能正常
- [ ] 指标收集功能正常
- [ ] 日志管理功能正常


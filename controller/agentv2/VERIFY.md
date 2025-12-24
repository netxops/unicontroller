# Agent V2 注册验证指南

## 验证注册信息

### 1. 查看 etcd 中的注册信息

```bash
# 查看所有 Agent 注册信息
etcdctl get --prefix "/agents"

# 查看特定 Agent 的注册信息
etcdctl get "/agents/agent/agent-001"
```

### 2. 验证注册信息格式

注册信息应该包含以下字段：

```json
{
  "Key": "agent-001",           // Agent 标识码
  "Name": "agent",              // 服务名称
  "Protocol": "grpc",           // 协议类型
  "Address": "192.168.0.199:10380",  // gRPC 服务地址
  "Meta": {
    "agent_code": "agent-001",  // Agent 标识码（用于 Controller 识别）
    "services": []              // 当前管理的服务列表
  }
}
```

### 3. 验证 Controller 发现

#### 方法 1: 查看 Controller 日志

Controller 启动后，应该能看到类似以下日志：

```
[INFO] Discovered agent: agent-001
[INFO] Connected to agent: agent-001 at 192.168.0.199:10380
```

#### 方法 2: 通过 Controller API 查询

```bash
# 列出所有 Agent
curl http://localhost:8081/api/v1/agents

# 应该能看到 agent-001 的信息
```

#### 方法 3: 检查 etcd 租约状态

```bash
# 查看租约信息（需要 etcd 版本支持）
etcdctl lease list
```

### 4. 验证服务注册更新

当 Agent V2 管理服务后，`services` 数组会自动更新：

```json
{
  "Meta": {
    "agent_code": "agent-001",
    "services": [
      {
        "package": "my-service",
        "version": "1.0.0",
        "status": "running"
      }
    ]
  }
}
```

### 5. 常见问题排查

#### 问题 1: Controller 找不到 Agent

**检查项：**
- [ ] etcd 是否正常运行
- [ ] Agent V2 和 Controller 是否使用相同的 etcd 地址
- [ ] 网络连通性（Controller 能否访问 Agent 的 gRPC 端口）
- [ ] agent-code 是否唯一

**解决方法：**
```bash
# 检查 etcd 连接
etcdctl endpoint health

# 检查注册信息是否存在
etcdctl get --prefix "/agents"
```

#### 问题 2: 注册信息中的 Address 不正确

**原因：** Agent V2 自动获取本机 IP，如果获取失败会使用默认值。

**解决方法：**
- 检查网络接口配置
- 手动指定 IP 地址（需要修改代码或配置）

#### 问题 3: 租约过期

**检查项：**
- [ ] Agent V2 是否正常运行
- [ ] etcd 连接是否正常
- [ ] keep-alive 是否正常工作

**解决方法：**
```bash
# 查看 Agent V2 日志
# 应该能看到定期注册的日志

# 检查 etcd 中的注册信息是否定期更新
watch -n 1 'etcdctl get "/agents/agent/agent-001"'
```

### 6. 测试 gRPC 连接

```bash
# 使用 grpcurl 测试连接
grpcurl -plaintext 192.168.0.199:10380 list

# 应该能看到注册的服务：
# pb.Package
# pb.Command
```

### 7. 验证服务管理

当通过 Controller 管理服务后，可以验证：

```bash
# 通过 Controller API 启动服务
curl -X POST http://localhost:8081/api/v1/agents/agent-001/packages/my-service/start

# 检查注册信息中的 services 数组是否更新
etcdctl get "/agents/agent/agent-001"
```

## 预期行为

1. **启动时注册**: Agent V2 启动后立即向 etcd 注册
2. **定期刷新**: 每 30 秒（可配置）刷新注册信息
3. **自动更新**: 当服务状态变化时，注册信息中的 `services` 数组自动更新
4. **租约续期**: 通过 keep-alive 机制保持租约活跃（TTL: 60 秒）

## 监控建议

建议监控以下指标：

1. **注册成功率**: Agent V2 日志中的注册成功/失败次数
2. **租约状态**: etcd 中的租约是否正常续期
3. **服务列表更新**: `services` 数组是否及时反映服务状态
4. **Controller 连接**: Controller 是否能正常连接到 Agent V2


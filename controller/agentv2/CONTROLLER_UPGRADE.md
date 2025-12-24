# Controller 升级指南

## 概述

本文档提供 Controller 升级到支持 Agent V2 的详细指南，包括兼容性说明、升级步骤、配置变更和验证方法。

## 升级前准备

### 1. 检查当前版本

确认当前 Controller 版本和支持的功能：

```bash
# 查看 Controller 版本
curl http://controller:8081/api/v1/version

# 查看支持的 Agent 版本
curl http://controller:8081/api/v1/agents/versions
```

### 2. 备份配置和数据

升级前务必备份：

```bash
# 备份 Controller 配置
cp deploy/controller.yaml deploy/controller.yaml.backup

# 备份 MongoDB 数据（如果使用）
mongodump --db controller --out /backup/controller-$(date +%Y%m%d)

# 备份 etcd 数据（如果使用）
etcdctl snapshot save /backup/etcd-$(date +%Y%m%d).db
```

### 3. 检查依赖服务

确保以下服务正常运行：

- **etcd**: 服务注册中心
- **MongoDB**: Agent 状态存储（如果使用）
- **网络连通性**: Controller 能访问所有 Agent

## 兼容性说明

### Agent V2 兼容性

Agent V2 与原有 Agent 完全兼容：

| 功能 | 原有 Agent | Agent V2 | 兼容性 |
|------|-----------|----------|--------|
| gRPC 协议 | ✅ | ✅ | 完全兼容 |
| 服务注册 | ✅ | ✅ | 完全兼容 |
| Package 服务 | ✅ | ✅ | 完全兼容 |
| Command 服务 | ✅ | ✅ | 完全兼容 |
| Health 服务 | ❌ | ✅ | Agent V2 新增 |
| Metrics 服务 | ❌ | ✅ | Agent V2 新增 |

### 协议兼容性

Agent V2 实现了与原有 Agent 相同的 gRPC 接口：

- **Package 服务**: `Start`, `Stop`, `Restart`, `PackageList`, `GetConfigs`, `ApplyConfigs`, `GetRecentLogs`, `StreamLogs`, `QueryLogs`
- **Command 服务**: `ExecCommand`, `ExecCommandSignal`, `GetCommandStatus`
- **Health 服务**: `GetHealthStatus`, `ListHealthStatuses`, `GetHealthHistory` (Agent V2 新增)
- **Metrics 服务**: `GetSystemMetrics`, `GetServiceMetrics`, `ListServiceMetrics` (Agent V2 新增)

## 升级步骤

### 步骤 1: 更新 Controller 代码

```bash
# 拉取最新代码
git pull origin main

# 检查是否有新的依赖
go mod tidy

# 编译 Controller
cd pkg/controller
go build -o controller
```

### 步骤 2: 更新配置

#### 2.1 检查 etcd 配置

确保 Controller 配置中的 etcd 地址与 Agent V2 一致：

```yaml
# deploy/controller.yaml
etcd:
  endpoints:
    - "127.0.0.1:2379"  # 必须与 Agent V2 配置一致
  prefix: "/agents"      # 服务注册前缀
  timeout: 5s
```

#### 2.2 更新 Agent 管理配置

如果 Controller 支持 Agent V2 的新功能，更新相关配置：

```yaml
# deploy/controller.yaml
agent:
  # Agent V2 支持的新功能
  enable_health_service: true   # 启用健康检查服务
  enable_metrics_service: true  # 启用指标服务
  health_check_interval: 30s    # 健康检查间隔
  metrics_collect_interval: 60s # 指标收集间隔
```

### 步骤 3: 停止 Controller

```bash
# 优雅停止 Controller
systemctl stop controller
# 或
pkill -TERM controller
```

### 步骤 4: 部署新版本

```bash
# 备份旧版本
cp controller controller.old

# 部署新版本
cp pkg/controller/controller /usr/local/bin/controller

# 设置权限
chmod +x /usr/local/bin/controller
```

### 步骤 5: 启动 Controller

```bash
# 启动 Controller
systemctl start controller
# 或
/usr/local/bin/controller -config=deploy/controller.yaml
```

### 步骤 6: 验证升级

#### 6.1 检查 Controller 状态

```bash
# 检查 Controller 是否正常运行
curl http://localhost:8081/health

# 检查版本
curl http://localhost:8081/api/v1/version
```

#### 6.2 检查 Agent 发现

```bash
# 列出所有 Agent
curl http://localhost:8081/api/v1/agents

# 检查 Agent V2 是否被发现
curl http://localhost:8081/api/v1/agents?version=v2
```

#### 6.3 测试 Agent 连接

```bash
# 测试与 Agent V2 的 gRPC 连接
grpcurl -plaintext -d '{"package":"test-service"}' \
  localhost:8081 \
  pb.Package/PackageList
```

## 新功能使用

### 1. 健康检查服务

Agent V2 提供了新的健康检查服务，Controller 可以使用：

```go
// 获取服务健康状态
healthClient := pb.NewHealthClient(conn)
status, err := healthClient.GetHealthStatus(ctx, &pb.GetHealthStatusReq{
    Package: "my-service",
})
```

### 2. 指标服务

Agent V2 提供了指标查询服务：

```go
// 获取系统指标
metricsClient := pb.NewMetricsClient(conn)
systemMetrics, err := metricsClient.GetSystemMetrics(ctx, &emptypb.Empty{})
```

### 3. 日志流式传输

Agent V2 支持日志流式传输：

```go
// 流式获取日志
packageClient := pb.NewPackageClient(conn)
stream, err := packageClient.StreamLogs(ctx, &pb.StreamLogsReq{
    Package:   "my-service",
    TailLines: 100,
    Follow:    true,
})
```

## 回滚方案

如果升级后出现问题，可以快速回滚：

### 1. 停止新版本

```bash
systemctl stop controller
```

### 2. 恢复旧版本

```bash
cp controller.old /usr/local/bin/controller
```

### 3. 恢复配置

```bash
cp deploy/controller.yaml.backup deploy/controller.yaml
```

### 4. 启动旧版本

```bash
systemctl start controller
```

## 常见问题

### Q1: Controller 无法发现 Agent V2

**原因**: etcd 配置不一致或网络问题

**解决方案**:
1. 检查 etcd 地址配置是否一致
2. 检查网络连通性
3. 查看 etcd 中的注册信息：`etcdctl get --prefix "/agents"`

### Q2: gRPC 连接失败

**原因**: Agent V2 的 gRPC 端口未开放或地址错误

**解决方案**:
1. 检查 Agent V2 的 gRPC 端口配置
2. 检查防火墙规则
3. 验证 Agent V2 是否正常启动

### Q3: 新功能不可用

**原因**: Agent V2 版本过旧或配置未启用

**解决方案**:
1. 确认 Agent V2 版本支持新功能
2. 检查 Controller 配置是否启用新功能
3. 查看 Agent V2 日志确认功能已启用

## 升级检查清单

- [ ] 备份配置和数据
- [ ] 检查依赖服务状态
- [ ] 更新 Controller 代码
- [ ] 更新配置文件
- [ ] 停止旧版本 Controller
- [ ] 部署新版本 Controller
- [ ] 启动新版本 Controller
- [ ] 验证 Controller 状态
- [ ] 验证 Agent 发现
- [ ] 测试基本功能
- [ ] 测试新功能（如适用）
- [ ] 监控系统运行状态

## 后续优化

升级完成后，建议：

1. **监控系统**: 设置监控告警，及时发现异常
2. **性能优化**: 根据实际使用情况调整配置参数
3. **文档更新**: 更新团队文档，记录升级过程和注意事项
4. **培训**: 组织团队培训，熟悉新功能的使用方法

## 技术支持

如遇到问题，请：

1. 查看 Controller 日志：`/var/log/controller/controller.log`
2. 查看 Agent V2 日志：`/var/log/agentv2/agentv2.log`
3. 检查 etcd 状态：`etcdctl endpoint health`
4. 联系技术支持团队


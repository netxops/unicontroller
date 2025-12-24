# Agent V2 gRPC 测试指南

## 启用反射 API

Agent V2 已经启用了 gRPC 反射 API，可以使用 `grpcurl` 等工具进行测试。

## 安装 grpcurl

```bash
# macOS
brew install grpcurl

# 或使用 Go 安装
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```

## 基本测试

### 1. 列出所有服务

```bash
grpcurl -plaintext 192.168.0.199:10380 list
```

应该看到：
```
pb.Command
pb.Package
grpc.reflection.v1alpha.ServerReflection
```

### 2. 查看服务的方法

```bash
# 查看 Package 服务的方法
grpcurl -plaintext 192.168.0.199:10380 list pb.Package

# 应该看到：
# pb.Package.Start
# pb.Package.Stop
# pb.Package.Restart
# pb.Package.PackageList
# pb.Package.GetConfigs
# pb.Package.ApplyConfigs
# pb.Package.GetRecentLogs

# 查看 Command 服务的方法
grpcurl -plaintext 192.168.0.199:10380 list pb.Command

# 应该看到：
# pb.Command.ExecCommand
# pb.Command.ExecCommandSignal
# pb.Command.GetCommandStatus
```

### 3. 查看方法详情

```bash
# 查看 PackageList 方法的详细信息
grpcurl -plaintext 192.168.0.199:10380 describe pb.Package.PackageList

# 查看请求和响应类型
grpcurl -plaintext 192.168.0.199:10380 describe pb.PackageListRequest
grpcurl -plaintext 192.168.0.199:10380 describe pb.PackageListResponse
```

## 调用方法

### 1. 列出所有包

```bash
# 需要传递 agent-code 在 metadata 中
grpcurl -plaintext \
  -H "agent-code: agent-001" \
  192.168.0.199:10380 \
  pb.Package.PackageList
```

### 2. 启动服务

```bash
grpcurl -plaintext \
  -H "agent-code: agent-001" \
  -d '{"package_name": "my-service"}' \
  192.168.0.199:10380 \
  pb.Package.Start
```

### 3. 停止服务

```bash
grpcurl -plaintext \
  -H "agent-code: agent-001" \
  -d '{"package_name": "my-service"}' \
  192.168.0.199:10380 \
  pb.Package.Stop
```

### 4. 执行命令

```bash
grpcurl -plaintext \
  -H "agent-code: agent-001" \
  -d '{
    "command": "ls",
    "args": ["-la"],
    "timeout": 30
  }' \
  192.168.0.199:10380 \
  pb.Command.ExecCommand
```

## 使用 Controller 测试

Controller 通过 gRPC 代理调用 Agent V2，可以通过 Controller API 测试：

```bash
# 通过 Controller API 启动服务
curl -X POST http://localhost:8081/api/v1/agents/agent-001/packages/my-service/start

# 通过 Controller API 获取服务列表
curl http://localhost:8081/api/v1/agents/agent-001/packages
```

## 故障排查

### 反射 API 未启用

如果看到 "server does not support the reflection API" 错误：
1. 确认 Agent V2 已重启
2. 检查代码中是否调用了 `reflection.Register(s.grpcServer)`
3. 查看 Agent V2 日志确认 gRPC 服务器正常启动

### 连接失败

```bash
# 测试端口是否开放
telnet 192.168.0.199 10380

# 或使用 nc
nc -zv 192.168.0.199 10380
```

### 方法调用失败

1. 检查 metadata 中是否包含 `agent-code`
2. 检查请求参数格式是否正确
3. 查看 Agent V2 日志获取详细错误信息

## 性能测试

### 使用 ghz 进行负载测试

```bash
# 安装 ghz
go install github.com/bojand/ghz/cmd/ghz@latest

# 运行负载测试
ghz \
  --insecure \
  --proto ./api/proto/package.proto \
  --call pb.Package.PackageList \
  -H "agent-code: agent-001" \
  192.168.0.199:10380
```


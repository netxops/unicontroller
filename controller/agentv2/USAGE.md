# Agent V2 使用指南

## 编译

```bash
cd agentv2/cmd/agentv2
go build -o agentv2 main.go
```

## 运行

```bash
./agentv2 -config=../../configs/agentv2.yaml -grpc-port=10380 -http-port=8080
```

## 配置

编辑 `configs/agentv2.yaml` 文件进行配置。

### 主要配置项

- `server.grpc_port`: gRPC 服务器端口
- `server.http_port`: HTTP 服务器端口
- `agent.code`: Agent 标识码
- `agent.workspace`: 工作目录
- `health_check`: 健康检查默认配置
- `auto_recovery`: 自动恢复配置
- `metrics`: 指标收集配置
- `logging`: 日志配置

## API 端点

### HTTP 端点

- `GET /health`: 健康检查
- `GET /ready`: 就绪检查
- `GET /metrics`: Prometheus 指标

### gRPC 服务

- `Package`: 服务包管理
- `Command`: 命令执行
- `Health`: 健康检查（待实现）
- `Metrics`: 指标查询（待实现）

## 服务配置

在服务的 `package.json` 中添加 `operations` 配置：

```json
{
  "package": "my-service",
  "version": "1.0.0",
  "operations": {
    "health_check": {
      "type": "http",
      "interval": "30s",
      "timeout": "5s",
      "retries": 3,
      "http_path": "/health",
      "http_method": "GET"
    },
    "auto_recovery": {
      "enabled": true,
      "max_restarts": 5,
      "restart_delay": "5s",
      "backoff_factor": 2.0,
      "max_backoff": "60s"
    },
    "metrics": {
      "enabled": true,
      "interval": "10s"
    },
    "dependencies": ["service-1", "service-2"]
  }
}
```

## 健康检查类型

### HTTP 检查

```json
{
  "type": "http",
  "http_path": "/health",
  "http_method": "GET",
  "interval": "30s",
  "timeout": "5s"
}
```

### TCP 检查

```json
{
  "type": "tcp",
  "tcp_port": 8080,
  "interval": "30s",
  "timeout": "5s"
}
```

### 进程检查

```json
{
  "type": "process",
  "interval": "30s"
}
```

### 脚本检查

```json
{
  "type": "script",
  "script_path": "/path/to/check.sh",
  "interval": "30s",
  "timeout": "5s"
}
```

## 故障排查

### 查看日志

```bash
tail -f /var/log/agentv2/agentv2.log
```

### 检查服务状态

通过 gRPC 客户端或 HTTP API 查询服务状态。

### 调试模式

设置环境变量 `LOG_LEVEL=debug` 启用调试日志。


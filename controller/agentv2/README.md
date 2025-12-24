# Agent V2

Agent V2 是全新的 agent 实现，专注于提供强大的服务运维支持能力。

## 特性

- ✅ 健康检查系统（HTTP/TCP/进程/脚本）
- ✅ 自动故障恢复
- ✅ 指标收集和上报
- ✅ 日志管理
- ✅ 服务依赖管理
- ✅ 统一的服务生命周期管理

## 架构

Agent V2 采用清晰的分层架构：

- **API Layer**: gRPC/HTTP 服务接口
- **Service Layer**: 业务逻辑层
- **Domain Layer**: 领域模型
- **Infrastructure Layer**: 基础设施适配器

## 目录结构

```
agentv2/
├── cmd/agentv2/          # 入口程序
├── internal/             # 内部实现
├── pkg/                 # 公共包
├── api/                 # API 定义
└── configs/             # 配置文件
```

## 使用

### 基本使用

```bash
cd agentv2/cmd/agentv2
go run main.go -config=../../configs/agentv2.yaml
```

### 与 Controller 集成

Agent V2 通过 etcd 服务注册机制与 Controller 集成：

1. **配置 etcd**: 编辑 `configs/agentv2.yaml`，设置 etcd 地址
2. **配置 agent-code**: 设置唯一的 agent 标识码
3. **启动 Agent V2**: Agent V2 会自动向 etcd 注册
4. **Controller 发现**: Controller 会自动发现并连接 Agent V2

详细说明请参考：
- [QUICKSTART.md](QUICKSTART.md) - 快速开始
- [INTEGRATION.md](INTEGRATION.md) - 集成指南
- [CONTROLLER_UPGRADE.md](CONTROLLER_UPGRADE.md) - Controller 升级指南
- [AGENT_CENTRALIZED_MANAGEMENT.md](AGENT_CENTRALIZED_MANAGEMENT.md) - Agent 集中化管理指南

## 与原有 Agent 的区别

- 完全独立的实现，不影响原有代码
- 增强的运维支持能力
- 更清晰的架构设计
- 更好的可测试性


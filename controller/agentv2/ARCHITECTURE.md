# Agent V2 架构文档

## 概述

Agent V2 是一个全新的 agent 实现，专注于提供强大的服务运维支持能力。它采用清晰的分层架构设计，确保代码的可维护性和可测试性。

## 架构设计

### 分层架构

Agent V2 采用经典的分层架构：

```
┌─────────────────────────────────────┐
│      API Layer (gRPC/HTTP)           │
│  - PackageService                    │
│  - CommandService                    │
│  - HealthService                     │
│  - MetricsService                    │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│      Service Layer                  │
│  - ServiceManager                   │
│  - ServiceRegistry                  │
│  - DependencyManager                │
│  - HealthChecker                    │
│  - MetricsCollector                 │
│  - LogManager                       │
│  - AutoRecovery                     │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│      Domain Layer                    │
│  - Service (领域模型)                │
│  - HealthStatus                      │
│  - Metrics                           │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│      Infrastructure Layer           │
│  - SystemdAdapter                   │
│  - FileSystem                       │
│  - Network                          │
└─────────────────────────────────────┘
```

### 核心模块

#### 1. API Layer (`internal/api/`)

负责处理 gRPC 和 HTTP 请求，将外部请求转换为内部服务调用。

- **PackageService**: 处理服务包管理相关请求
- **CommandService**: 处理命令执行相关请求
- **HealthService**: 处理健康检查相关请求
- **MetricsService**: 处理指标查询相关请求

#### 2. Service Layer (`pkg/service/`, `pkg/ops/`)

实现核心业务逻辑。

- **ServiceManager**: 统一的服务生命周期管理
- **ServiceRegistry**: 服务注册表，管理所有已注册的服务
- **DependencyManager**: 服务依赖管理，支持拓扑排序
- **HealthChecker**: 健康检查系统，支持多种检查类型
- **MetricsCollector**: 指标收集系统
- **LogManager**: 日志管理系统
- **AutoRecovery**: 自动故障恢复系统

#### 3. Domain Layer (`pkg/domain/`)

定义领域模型和业务规则。

- **Service**: 服务领域模型
- **ServiceHealth**: 服务健康状态
- **ServiceMetrics**: 服务指标
- **SystemMetrics**: 系统指标

#### 4. Infrastructure Layer (`pkg/infrastructure/`)

提供基础设施适配器，封装外部依赖。

- **SystemdAdapter**: systemd 操作适配器
- **FileSystem**: 文件系统操作接口
- **Network**: 网络操作接口（待实现）

## 核心功能

### 1. 健康检查系统

支持多种健康检查类型：

- **HTTP 检查**: 通过 HTTP 请求检查服务健康状态
- **TCP 检查**: 通过 TCP 连接检查服务端口
- **进程检查**: 检查服务进程是否运行
- **脚本检查**: 执行自定义脚本进行健康检查

### 2. 自动故障恢复

当检测到服务不健康时，自动执行恢复操作：

- 自动重启服务
- 支持最大重启次数限制
- 指数退避算法避免频繁重启
- 重启失败告警

### 3. 指标收集

定期收集系统和服务的运行指标：

- 系统指标: CPU、内存、磁盘、网络
- 服务指标: 响应时间、请求数、错误率
- 支持 Prometheus 格式导出

### 4. 日志管理

提供完整的日志管理功能：

- 从 systemd journal 或日志文件收集日志
- 自动日志轮转
- 支持按时间、级别查询日志
- 日志上报到 Controller

### 5. 服务依赖管理

支持服务依赖关系的管理：

- 定义服务依赖关系
- 按依赖顺序启动服务
- 处理依赖服务故障场景

## 依赖注入

使用 Google Wire 进行依赖注入，确保组件之间的解耦。

## 错误处理

统一的错误处理机制：

- 定义标准错误代码
- 错误包装和转换
- 结构化错误信息

## 配置管理

支持通过配置文件进行配置，配置文件位于 `configs/agentv2.yaml`。

## 与原有实现的兼容性

- 完全独立的实现，不影响原有代码
- 保持与 Controller 的 gRPC 通信协议兼容
- 可以并行运行进行对比测试

## 扩展性

架构设计支持未来扩展：

- 插件化的健康检查器
- 可扩展的指标收集器
- 灵活的日志后端支持


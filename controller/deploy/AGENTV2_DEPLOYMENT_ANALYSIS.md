# Agent V2 部署文件分析

## 一、文件对比分析

### 1.1 package.json 对比

#### V1 版本特点：
- 包名：`uniops-agent`
- 二进制：`uniops-agent`
- 配置文件格式：TOML
- 配置文件路径：`/etc/uniops-agent/uniops-agent.toml`
- 使用 Jupiter 框架

#### V2 版本特点：
- 包名：`agentv2` 或 `uniops-agentv2`
- 二进制：`agentv2`
- 配置文件格式：**YAML**（不是 TOML）
- 配置文件路径：可配置，默认根据用户权限选择
- 独立实现，不依赖 Jupiter 框架

### 1.2 配置文件对比

#### V1 (uniops-agent.toml.template)：
- 格式：TOML
- 使用 Jupiter 配置结构
- 配置项：
  - `jupiter.mode = "server-agent"`
  - `jupiter.runtime.config.appId`
  - `jupiter.runtime.config.code` (agent_code)
  - `jupiter.etcdv3.default.endpoints`
  - `jupiter.server.grpc.port`
  - `jupiter.server.http.port`

#### V2 (agentv2.yaml)：
- 格式：**YAML**
- 独立配置结构
- 配置项：
  - `agent.code` (Agent 标识码，由运维平台生成)
  - `agent.workspace` (工作目录)
  - `agent.log_level`
  - `server.grpc_port`
  - `server.http_port`
  - `registry.etcd_endpoints` (数组)
  - `registry.enabled`
  - `registry.register_interval`
  - `registry.ttl`
  - `discovery.enabled`
  - `health_check.*`
  - `auto_recovery.*`
  - `metrics.*`
  - `logging.*`

### 1.3 Systemd Service 对比

#### V1 版本：
- 服务名：`uniops-agent`
- 启动命令：`uniops-agent --config=/etc/uniops-agent/uniops-agent.toml`
- 工作目录：`{{.install_dir}}`
- 日志目录：`{{.install_dir}}/logs`

#### V2 版本：
- 服务名：`agentv2` 或 `uniops-agentv2`
- 启动命令：`agentv2 --config=<config_path>`
- 工作目录：根据用户权限自动选择或配置指定
- 日志目录：根据用户权限自动选择或配置指定

## 二、关键差异

### 2.1 Agent Code 管理

**V1**：
- 配置字段：`jupiter.runtime.config.code`
- 在配置文件中设置

**V2**：
- 配置字段：`agent.code`
- **重要**：必须由运维平台生成和管理
- 在部署时通过模板变量注入

### 2.2 配置文件格式

**V1**：TOML 格式，使用模板变量 `{{ .variable }}`

**V2**：YAML 格式，也需要支持模板变量

### 2.3 端口配置

**V1**：
- gRPC 端口：通过 `jupiter.server.grpc.port` 配置
- HTTP 端口：通过 `jupiter.server.http.port` 配置

**V2**：
- gRPC 端口：`server.grpc_port`（默认 10380）
- HTTP 端口：`server.http_port`（默认 58080）

### 2.4 etcd 配置

**V1**：
- 单个 endpoint：`jupiter.etcdv3.default.endpoints = ["{{ .etcd_endpoint }}"]`

**V2**：
- 多个 endpoints：`registry.etcd_endpoints: ["endpoint1", "endpoint2"]`
- 支持集群配置

### 2.5 新增功能模块

**V2 新增**：
- 服务发现配置（`discovery`）
- 健康检查配置（`health_check`）
- 自动恢复配置（`auto_recovery`）
- 指标收集配置（`metrics`）
- 日志配置（`logging`）

## 三、部署文件改造建议

### 3.1 package.json 改造

需要创建 `package.json` 的 V2 版本，主要改动：
1. 包名改为 `agentv2` 或 `uniops-agentv2`
2. 二进制名称改为 `agentv2`
3. 配置文件格式改为 `yaml`
4. 配置文件名称改为 `agentv2.yaml`
5. 更新健康检查路径（如果不同）

### 3.2 配置文件模板改造

需要创建 `agentv2.yaml.template`，特点：
1. 使用 YAML 格式
2. 支持模板变量（使用 Go template 语法）
3. 包含所有 V2 配置项
4. Agent Code 通过模板变量注入（由运维平台提供）

### 3.3 Systemd Service 改造

需要创建 `agentv2.service.template`，主要改动：
1. 服务名改为 `agentv2`
2. 启动命令改为 `agentv2 --config=...`
3. 环境变量可能需要调整
4. 工作目录和日志目录使用配置中的值

## 四、部署流程

### 4.1 V1 部署流程
1. 读取 `package.json`
2. 根据模板生成 `uniops-agent.toml`
3. 根据模板生成 `uniops-agent.service`
4. 安装二进制文件
5. 安装配置文件
6. 安装 systemd service
7. 启动服务

### 4.2 V2 部署流程（建议）
1. 读取 `package.json`（V2 版本）
2. **从运维平台获取 Agent Code**（必须）
3. 根据模板生成 `agentv2.yaml`（注入 Agent Code）
4. 根据模板生成 `agentv2.service`
5. 安装二进制文件
6. 安装配置文件
7. 安装 systemd service
8. 启动服务

## 五、迁移注意事项

1. **Agent Code 管理**：V2 必须由运维平台生成，不能自动生成
2. **配置文件格式**：从 TOML 改为 YAML
3. **配置结构**：完全不同的配置结构
4. **端口默认值**：V2 使用不同的默认端口
5. **工作目录**：V2 支持根据用户权限自动选择
6. **日志目录**：V2 支持根据用户权限自动选择


# Agent V2 迁移指南

## 概述

本文档说明如何从 Agent V1 迁移到 Agent V2，包括部署文件的差异和迁移步骤。

## 文件对比

### 1. package.json

| 项目 | V1 | V2 |
|------|----|----|
| 文件名 | `package.json` | `package.json.agentv2` |
| 包名 | `uniops-agent` | `agentv2` |
| 二进制 | `uniops-agent` | `agentv2` |
| 配置格式 | `toml` | `yaml` |
| 配置文件 | `uniops-agent.toml` | `agentv2.yaml` |
| 服务名 | `uniops-agent` | `agentv2` |

### 2. 配置文件模板

| 项目 | V1 | V2 |
|------|----|----|
| 文件名 | `uniops-agent.toml.template` | `agentv2.yaml.template` |
| 格式 | TOML | YAML |
| Agent Code 字段 | `jupiter.runtime.config.code` | `agent.code` |
| etcd 配置 | 单个 endpoint | 支持多个 endpoints |
| 框架依赖 | Jupiter | 独立实现 |

### 3. Systemd Service

| 项目 | V1 | V2 |
|------|----|----|
| 文件名 | `uniops-agent.service.template` | `agentv2.service.template` |
| 启动命令 | `uniops-agent --config=...` | `agentv2 --config=...` |
| 配置文件路径 | `/etc/uniops-agent/uniops-agent.toml` | `/etc/agentv2/agentv2.yaml` |

## 关键差异

### 1. Agent Code 管理

**V1**：
- 在配置文件中设置：`jupiter.runtime.config.code = "{{ .agent_code }}"`
- 可以从模板变量获取

**V2**：
- 在配置文件中设置：`agent.code: "{{ .device_code }}"` 或 `"{{ .agent_code }}"`
- **重要**：必须由运维平台生成和管理
- 部署代理使用 `device_code` 变量传递，但实际值应该是运维平台生成的 `agent_code`

### 2. 模板变量映射

部署代理提供的变量（`prepareVariables` 函数）：
- `device_code` - Agent Code（从命令行参数 `--agent-code` 获取）
- `workspace` - 工作目录
- `install_dir` - 安装目录
- `config_dir` - 配置目录
- `user` - 运行用户
- `group` - 运行组
- `app_id` - 应用 ID
- `version` - 版本号

从 Controller 获取的变量（`getTemplateVarsFromController`）：
- 通过 `/api/v1/variables?agent_code=...&app_id=...` 获取
- 返回 `map[string]string`，可能包含：
  - `etcd_endpoint` 或 `etcd_endpoints`
  - `grpc_port`
  - `http_port`
  - `log_level`
  - 其他自定义变量

### 3. 配置结构差异

**V1 (TOML)**：
```toml
[jupiter.runtime.config]
appId = "{{ .app_id }}"
code = "{{ .agent_code }}"
workspace = "{{ .workspace }}"

[jupiter.etcdv3.default]
endpoints = ["{{ .etcd_endpoint }}"]
```

**V2 (YAML)**：
```yaml
agent:
  code: "{{ if .agent_code }}{{ .agent_code }}{{ else }}{{ .device_code }}{{ end }}"
  workspace: "{{ if .workspace }}{{ .workspace }}{{ else }}""{{ end }}"

registry:
  etcd_endpoints:
    - "{{ if .etcd_endpoint }}{{ .etcd_endpoint }}{{ else }}127.0.0.1:2379{{ end }}"
```

## 迁移步骤

### 步骤 1：更新部署代理

部署代理需要支持 Agent V2 的部署：

1. **识别 Agent 版本**：根据 `package.json` 中的包名或版本判断
2. **使用正确的模板文件**：
   - V1: `uniops-agent.toml.template` → `uniops-agent.toml`
   - V2: `agentv2.yaml.template` → `agentv2.yaml`
3. **确保 Agent Code 传递**：
   - 从运维平台获取 Agent Code
   - 通过 `--agent-code` 参数传递给部署代理
   - 或通过 Controller API 的 `/api/v1/variables` 获取

### 步骤 2：更新 Controller 部署逻辑

Controller 在部署 Agent V2 时：

1. **生成或获取 Agent Code**：
   ```go
   // 从设备记录获取 Agent Code（由运维平台生成）
   agentCode := device.AgentCode
   ```

2. **调用部署代理**：
   ```go
   // 部署命令
   cmd := exec.Command("deployment-agent",
       "--agent-code", agentCode,
       "--app-id", "agentv2",
       "--controller-url", controllerURL,
       // ... 其他参数
   )
   ```

3. **传递模板变量**：
   - 通过 Controller API `/api/v1/variables` 提供
   - 或通过环境变量传递

### 步骤 3：模板变量准备

部署 Agent V2 时，需要准备以下模板变量：

**必需变量**：
- `device_code` 或 `agent_code` - Agent Code（由运维平台提供）

**从部署代理自动提供**：
- `install_dir` - 安装目录
- `config_dir` - 配置目录
- `workspace` - 工作目录
- `user` - 运行用户
- `group` - 运行组
- `app_id` - 应用 ID
- `version` - 版本号

**从 Controller API 获取（可选）**：
- `etcd_endpoint` 或 `etcd_endpoints` - etcd 地址
- `grpc_port` - gRPC 端口
- `http_port` - HTTP 端口
- `log_level` - 日志级别
- 其他自定义配置

## 部署文件使用说明

### 1. package.json.agentv2

用于定义 Agent V2 的包信息，部署代理会读取此文件。

**使用方式**：
- 在部署包中包含此文件
- 或重命名为 `package.json`（如果只部署 V2）

### 2. agentv2.yaml.template

Agent V2 的配置文件模板。

**模板变量说明**：
- 使用标准 Go template 语法
- 不支持 `default` 函数，使用条件判断：`{{ if .var }}{{ .var }}{{ else }}default_value{{ end }}`
- Agent Code 优先使用 `agent_code`，如果没有则使用 `device_code`

### 3. agentv2.service.template

Agent V2 的 systemd 服务文件模板。

**注意事项**：
- 启动命令：`agentv2 --config={{.config_dir}}/agentv2.yaml`
- 环境变量 `AGENT_CODE` 用于传递 Agent Code

## 兼容性说明

### 向后兼容

- V1 和 V2 可以共存
- 使用不同的包名和服务名
- 使用不同的配置文件路径

### 模板变量兼容

- 部署代理提供的变量（`device_code`, `workspace` 等）在 V1 和 V2 中都可用
- V2 模板优先使用 `agent_code`，如果没有则回退到 `device_code`

## 最佳实践

1. **Agent Code 管理**：
   - 始终由运维平台生成
   - 在设备入库时或部署前生成
   - 通过部署代理的 `--agent-code` 参数传递

2. **配置文件生成**：
   - 使用模板引擎生成配置文件
   - 验证生成的配置文件格式正确
   - 确保所有必需变量都已提供

3. **部署验证**：
   - 检查服务是否启动成功
   - 验证 Agent 是否注册到 etcd
   - 检查健康检查端点是否响应

## 故障排查

### 1. Agent Code 未设置

**错误**：`agent code is required`

**解决**：
- 确保通过 `--agent-code` 参数传递
- 或通过 Controller API 的 `/api/v1/variables` 提供 `agent_code` 变量

### 2. 配置文件格式错误

**错误**：`failed to parse config file`

**解决**：
- 检查 YAML 格式是否正确
- 验证模板变量是否正确替换
- 检查缩进和语法

### 3. 端口冲突

**错误**：`address already in use`

**解决**：
- 检查端口是否被占用
- 修改配置文件中的端口配置
- 或通过模板变量覆盖默认端口

## 参考文档

- [Agent V2 部署文件分析](./AGENTV2_DEPLOYMENT_ANALYSIS.md)
- [Agent V2 部署指南](./AGENTV2_DEPLOYMENT_GUIDE.md)
- [Agent V2 快速开始](../agentv2/QUICKSTART.md)


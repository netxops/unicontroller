# Agent V2 部署文件总结

## 文件列表

### 1. 部署定义文件

#### package.json.agentv2
- **用途**：Agent V2 的包定义文件
- **格式**：JSON（支持模板变量）
- **关键字段**：
  - `package: "agentv2"`
  - `binary.name: "agentv2"`
  - `config.format: "yaml"`
  - `agent_code_required: true`
- **使用**：部署代理读取此文件来了解如何部署 Agent V2

### 2. 配置文件模板

#### agentv2.yaml.template
- **用途**：Agent V2 的配置文件模板
- **格式**：YAML（使用 Go template 语法）
- **关键配置**：
  - `agent.code` - Agent 标识码（必需，由运维平台提供）
  - `server.grpc_port` - gRPC 端口（默认：10380）
  - `server.http_port` - HTTP 端口（默认：58080）
  - `registry.etcd_endpoints` - etcd 地址列表
  - 其他功能模块配置（健康检查、自动恢复、指标收集等）
- **模板变量**：
  - `device_code` 或 `agent_code` - Agent Code（必需）
  - `etcd_endpoint` 或 `etcd_endpoints` - etcd 地址
  - `grpc_port`, `http_port` - 端口配置
  - `workspace`, `log_directory` - 路径配置（可选）
  - 其他配置项都有默认值

### 3. Systemd Service 模板

#### agentv2.service.template
- **用途**：Agent V2 的 systemd 服务文件模板
- **格式**：systemd unit file（使用 Go template 语法）
- **关键配置**：
  - 服务名：`agentv2`
  - 启动命令：`agentv2 --config={{.config_dir}}/agentv2.yaml`
  - 环境变量：`AGENT_CODE`（传递 Agent Code）
  - 工作目录：`{{.install_dir}}`
- **模板变量**：
  - `install_dir` - 安装目录
  - `config_dir` - 配置目录
  - `agent_code` 或 `device_code` - Agent Code
  - `user`, `group` - 运行用户和组（可选）
  - `log_directory` - 日志目录（可选）

### 4. 文档文件

#### AGENTV2_DEPLOYMENT_ANALYSIS.md
- **用途**：详细分析 V1 和 V2 的差异
- **内容**：
  - 文件对比分析
  - 关键差异说明
  - 部署流程对比
  - 迁移注意事项

#### AGENTV2_DEPLOYMENT_GUIDE.md
- **用途**：Agent V2 部署指南
- **内容**：
  - 文件说明
  - 部署流程
  - 配置示例
  - 故障排查

#### AGENTV2_MIGRATION_GUIDE.md
- **用途**：从 V1 迁移到 V2 的指南
- **内容**：
  - 文件对比表
  - 模板变量映射
  - 迁移步骤
  - 兼容性说明

## 关键改进点

### 1. Agent Code 管理

- **V1**：在配置文件中设置，可以从模板变量获取
- **V2**：必须由运维平台生成，通过模板变量注入
- **实现**：模板优先使用 `agent_code`，如果没有则使用 `device_code`

### 2. 配置文件格式

- **V1**：TOML 格式，使用 Jupiter 框架配置结构
- **V2**：YAML 格式，独立配置结构，更清晰易读

### 3. 模板语法

- **修复**：Go template 标准库不支持 `default` 函数
- **解决方案**：使用条件判断 `{{ if .var }}{{ .var }}{{ else }}default{{ end }}`

### 4. 功能模块

- **V2 新增**：
  - 服务发现配置
  - 健康检查配置
  - 自动恢复配置
  - 指标收集和上报配置
  - 日志配置

## 使用方式

### 方式 1：直接使用（推荐）

在部署包中包含以下文件：
- `package.json.agentv2`（或重命名为 `package.json`）
- `agentv2.yaml.template`
- `agentv2.service.template`

部署代理会自动识别并使用这些文件。

### 方式 2：重命名使用

如果需要与 V1 共存：
- 保持 V1 文件不变
- 将 V2 文件重命名为不同的名称
- 在部署时根据版本选择对应的文件

## 模板变量说明

### 部署代理自动提供的变量

这些变量由部署代理的 `prepareVariables` 函数提供：

- `device_code` - Agent Code（从 `--agent-code` 参数获取）
- `app_id` - 应用 ID
- `install_dir` - 安装目录
- `config_dir` - 配置目录
- `workspace` - 工作目录
- `user` - 运行用户
- `group` - 运行组
- `version` - 版本号
- `wanted_by` - systemd target

### 从 Controller API 获取的变量

通过 `/api/v1/variables?agent_code=...&app_id=...` 获取：

- `agent_code` - Agent Code（如果提供，优先使用）
- `etcd_endpoint` 或 `etcd_endpoints` - etcd 地址
- `grpc_port` - gRPC 端口
- `http_port` - HTTP 端口
- `log_level` - 日志级别
- 其他自定义配置变量

## 部署检查清单

- [ ] `package.json.agentv2` 已包含在部署包中
- [ ] `agentv2.yaml.template` 已包含在部署包中
- [ ] `agentv2.service.template` 已包含在部署包中
- [ ] Agent Code 已由运维平台生成
- [ ] 部署代理支持 Agent V2（或已更新）
- [ ] Controller 部署 API 已更新以支持 Agent V2
- [ ] 模板变量已正确准备
- [ ] 配置文件生成逻辑已更新（支持 YAML）
- [ ] 测试部署流程

## 下一步

1. **更新部署代理**：确保支持读取 `package.json.agentv2` 和处理 YAML 模板
2. **更新 Controller 部署逻辑**：确保在部署 Agent V2 时传递正确的 Agent Code
3. **测试部署流程**：验证所有模板变量正确替换
4. **文档更新**：更新部署文档，说明 V1 和 V2 的部署差异


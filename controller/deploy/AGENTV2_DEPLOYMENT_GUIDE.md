# Agent V2 部署指南

## 概述

本文档说明如何使用部署文件来部署 Agent V2。Agent V2 与 V1 版本在配置格式、启动方式等方面有显著差异。

## 文件说明

### 1. package.json.agentv2

Agent V2 的包定义文件，包含：
- 包名：`agentv2`
- 二进制名称：`agentv2`
- 配置文件格式：`yaml`
- 配置文件名称：`agentv2.yaml`
- 服务名称：`agentv2`

**关键字段**：
- `agent_code_required: true` - 表示 Agent Code 是必需的
- `agent_code_source: "platform"` - Agent Code 由运维平台提供

### 2. agentv2.yaml.template

Agent V2 的配置文件模板，使用 YAML 格式。

**必需的模板变量**：
- `agent_code` - Agent 标识码（由运维平台生成，必须唯一）

**可选的模板变量**：
- `grpc_port` - gRPC 端口（默认：10380）
- `http_port` - HTTP 端口（默认：58080）
- `etcd_endpoint` 或 `etcd_endpoints` - etcd 地址（默认：127.0.0.1:2379）
- `workspace` - 工作目录（留空则自动选择）
- `log_directory` - 日志目录（留空则自动选择）
- `log_level` - 日志级别（默认：info）
- 其他配置项都有默认值

### 3. agentv2.service.template

Agent V2 的 systemd 服务文件模板。

**必需的模板变量**：
- `install_dir` - 安装目录
- `config_dir` - 配置文件目录
- `agent_code` - Agent 标识码

**可选的模板变量**：
- `user` - 运行用户（可选）
- `group` - 运行组（可选）
- `log_directory` - 日志目录
- `workspace` - 工作目录
- `wanted_by` - systemd target（默认：multi-user.target）

## 部署流程

### 步骤 1：准备模板变量

部署前需要准备以下模板变量：

```go
templateVars := map[string]interface{}{
    // 必需变量
    "agent_code": "AG-a1b2c3d4",  // 由运维平台生成
    
    // 安装路径
    "install_dir": "/opt/agentv2",
    "config_dir": "/etc/agentv2",
    
    // 网络配置
    "grpc_port": 10380,
    "http_port": 58080,
    "etcd_endpoints": []string{"192.168.1.100:2379", "192.168.1.101:2379"},
    
    // 可选配置
    "workspace": "",  // 留空使用默认值
    "log_directory": "",  // 留空使用默认值
    "log_level": "info",
    
    // 用户权限（可选）
    "user": "root",
    "group": "root",
}
```

### 步骤 2：生成配置文件

使用模板引擎（如 Go template）生成配置文件：

```go
// 1. 读取模板文件
templateContent, _ := os.ReadFile("agentv2.yaml.template")

// 2. 解析模板
tmpl, _ := template.New("config").Parse(string(templateContent))

// 3. 生成配置文件
var buf bytes.Buffer
tmpl.Execute(&buf, templateVars)

// 4. 写入配置文件
os.WriteFile("/etc/agentv2/agentv2.yaml", buf.Bytes(), 0644)
```

### 步骤 3：生成 Systemd Service 文件

```go
// 1. 读取模板
serviceTemplate, _ := os.ReadFile("agentv2.service.template")

// 2. 解析并生成
tmpl, _ := template.New("service").Parse(string(serviceTemplate))
var buf bytes.Buffer
tmpl.Execute(&buf, templateVars)

// 3. 写入服务文件
os.WriteFile("/etc/systemd/system/agentv2.service", buf.Bytes(), 0644)
```

### 步骤 4：安装和启动

```bash
# 1. 安装二进制文件
cp agentv2 /opt/agentv2/agentv2
chmod +x /opt/agentv2/agentv2

# 2. 创建必要的目录
mkdir -p /etc/agentv2
mkdir -p /var/log/agentv2

# 3. 重新加载 systemd
systemctl daemon-reload

# 4. 启动服务
systemctl enable agentv2
systemctl start agentv2

# 5. 检查状态
systemctl status agentv2
```

## 配置示例

### 最小配置（仅必需项）

```yaml
server:
  grpc_port: 10380
  http_port: 58080

agent:
  code: "AG-a1b2c3d4"  # 必需，由运维平台提供

registry:
  enabled: true
  etcd_endpoints:
    - "192.168.1.100:2379"
```

### 完整配置

参考 `agentv2.yaml.template` 文件，包含所有可配置项。

## 关键差异（与 V1 对比）

### 1. 配置文件格式

- **V1**：TOML 格式 (`uniops-agent.toml`)
- **V2**：YAML 格式 (`agentv2.yaml`)

### 2. Agent Code 管理

- **V1**：在配置文件中设置 `jupiter.runtime.config.code`
- **V2**：必须通过模板变量 `agent_code` 注入，由运维平台生成

### 3. 端口默认值

- **V1**：使用 Jupiter 框架的默认端口
- **V2**：gRPC 默认 10380，HTTP 默认 58080

### 4. etcd 配置

- **V1**：单个 endpoint
- **V2**：支持多个 endpoints（数组）

### 5. 工作目录和日志目录

- **V1**：固定路径
- **V2**：支持根据用户权限自动选择，或通过配置指定

## 部署检查清单

- [ ] Agent Code 已由运维平台生成
- [ ] 模板变量已准备完整
- [ ] 配置文件已生成（`agentv2.yaml`）
- [ ] Systemd service 文件已生成
- [ ] 二进制文件已安装
- [ ] 目录权限已设置正确
- [ ] etcd 连接配置正确
- [ ] 服务已启动并运行正常
- [ ] 健康检查通过（`curl http://localhost:58080/health`）

## 故障排查

### 1. 服务启动失败

```bash
# 查看服务状态
systemctl status agentv2

# 查看日志
journalctl -u agentv2 -f

# 检查配置文件
agentv2 --config=/etc/agentv2/agentv2.yaml --validate
```

### 2. Agent Code 未设置

错误信息：`agent code is required`

解决：确保在模板变量中提供了 `agent_code`

### 3. etcd 连接失败

检查：
- etcd 地址是否正确
- 网络是否可达
- etcd 是否正常运行

### 4. 端口冲突

检查端口是否被占用：
```bash
netstat -tlnp | grep 10380
netstat -tlnp | grep 58080
```

## 参考文档

- [Agent V2 部署文件分析](./AGENTV2_DEPLOYMENT_ANALYSIS.md)
- [Agent V2 快速开始](../agentv2/QUICKSTART.md)
- [Agent V2 用户权限](../agentv2/USER_PERMISSIONS.md)


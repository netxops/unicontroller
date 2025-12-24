# Agent配置验证工具

用于读取和验证Agent配置文件的命令行工具。

## 功能特性

- ✅ 加载和解析Agent配置文件
- ✅ 验证配置项的有效性
- ✅ 测试etcd连接
- ✅ 测试网络连通性
- ✅ 检查端口可用性
- ✅ 输出详细的验证报告
- ✅ 支持JSON格式输出

## 使用方法

### 基本用法

```bash
# 验证配置文件
go run cmd/config-validator/main.go -config configs/agentv2.yaml

# 或编译后使用
go build -o bin/config-validator cmd/config-validator/main.go
./bin/config-validator -config configs/agentv2.yaml
```

### 命令行参数

```bash
-config string
    配置文件路径（必需）

-test-etcd
    是否测试etcd连接（默认：true）

-verbose
    启用详细输出（显示etcd中已注册的Agent）

-json
    以JSON格式输出结果
```

### 示例

#### 1. 基本验证

```bash
./bin/config-validator -config configs/agentv2.yaml
```

输出示例：
```
======================================================================
Agent Configuration Validator
======================================================================

Configuration:
  Agent Code:     agent-DEV20251220000066-c2e4213a
  Workspace:      /home/asialink/app
  gRPC Port:       10380
  HTTP Port:       58080
  Registry:       true
  Etcd Endpoints:  [192.168.100.122:2379]
  Etcd Auth:       true
  Register Interval: 30s
  TTL:             60s

Etcd Connection Test:
  Status:         ✓ Connected
  Endpoints:     [192.168.100.122:2379]
  Authentication: true
  Existing Agents: 0 found

Network Connectivity Test:
  Etcd:          ✓ Reachable
  gRPC Port:     ✓ Available

======================================================================
✓ Configuration validation PASSED
======================================================================
```

#### 2. JSON格式输出

```bash
./bin/config-validator -config configs/agentv2.yaml -json
```

输出示例：
```json
{
  "valid": true,
  "errors": [],
  "warnings": [],
  "config": {
    "agent": {
      "code": "agent-DEV20251220000066-c2e4213a",
      "workspace": "/home/asialink/app",
      "log_level": "info"
    },
    "server": {
      "grpc_port": 10380,
      "http_port": 58080
    },
    "registry": {
      "enabled": true,
      "etcd_endpoints": ["192.168.100.122:2379"],
      "etcd_username": "root",
      "etcd_password": "Etcd@Passw0rd",
      "register_interval": 30000000000,
      "ttl": 60000000000
    }
  },
  "etcd_test": {
    "connected": true,
    "endpoints": ["192.168.100.122:2379"],
    "has_auth": true
  },
  "network_test": {
    "etcd_reachable": true,
    "port_available": true
  },
  "summary": "Configuration validation PASSED"
}
```

#### 3. 详细输出（显示etcd中已注册的Agent）

```bash
./bin/config-validator -config configs/agentv2.yaml -verbose
```

#### 4. 跳过etcd测试

```bash
./bin/config-validator -config configs/agentv2.yaml -test-etcd=false
```

## 验证项目

### 基本配置验证

- ✅ Agent标识码（agent.code）必须配置
- ✅ gRPC端口必须在1-65535范围内
- ✅ HTTP端口必须在1-65535范围内
- ✅ gRPC端口和HTTP端口不能相同
- ✅ 工作目录必须存在且为目录

### 注册配置验证

- ✅ etcd端点必须配置（如果注册功能启用）
- ✅ etcd端点格式验证（host:port）
- ✅ etcd认证配置一致性检查
- ✅ 注册间隔必须大于0
- ✅ TTL必须大于0
- ⚠️ TTL应该大于注册间隔（警告）
- ⚠️ TTL建议至少是注册间隔的2倍（警告）

### 连接测试

- ✅ etcd连接测试
- ✅ etcd认证测试
- ✅ 网络连通性测试
- ✅ 端口可用性测试

## 错误处理

### 常见错误

1. **配置文件不存在**
   ```
   Error: Failed to load config: open configs/agentv2.yaml: no such file or directory
   ```
   解决：检查配置文件路径是否正确

2. **etcd连接失败**
   ```
   Etcd Connection Test:
     Status:         ✗ Failed
     Error:          Failed to connect to etcd: context deadline exceeded
   ```
   解决：检查etcd地址和认证信息是否正确

3. **端口被占用**
   ```
   Network Connectivity Test:
     gRPC Port:     ✗ Port 10380 is already in use
   ```
   解决：更改端口或停止占用端口的进程

## 集成到CI/CD

可以将此工具集成到CI/CD流程中，在部署前验证配置：

```bash
#!/bin/bash
# 验证配置
if ! ./bin/config-validator -config configs/agentv2.yaml; then
    echo "Configuration validation failed!"
    exit 1
fi

# 继续部署流程
...
```

## 退出码

- `0`: 验证通过
- `1`: 验证失败（有错误）

## 注意事项

1. **etcd认证**：如果etcd启用了认证，必须在配置文件中提供用户名和密码
2. **网络测试**：网络连通性测试需要能够访问etcd服务器
3. **端口测试**：端口可用性测试会尝试绑定端口，如果端口已被占用会失败
4. **配置文件格式**：必须使用YAML格式，符合Agent配置规范


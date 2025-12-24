# Agent配置验证工具使用指南

## 快速开始

### 编译工具

```bash
cd agent/agentv2
go build -o bin/config-validator cmd/config-validator/main.go
```

### 基本使用

```bash
# 验证配置文件
./bin/config-validator -config configs/agentv2.yaml
```

## 使用示例

### 示例1：验证本地配置文件

```bash
./bin/config-validator -config configs/agentv2.yaml
```

输出：
```
=======================================================================
Agent Configuration Validator
=======================================================================

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

Network Connectivity Test:
  Etcd:          ✓ Reachable
  gRPC Port:     ✓ Available

=======================================================================
✓ Configuration validation PASSED
=======================================================================
```

### 示例2：JSON格式输出

```bash
./bin/config-validator -config configs/agentv2.yaml -json
```

适用于脚本自动化处理。

### 示例3：详细输出（显示etcd中已注册的Agent）

```bash
./bin/config-validator -config configs/agentv2.yaml -verbose
```

会显示etcd中已存在的Agent注册信息。

### 示例4：跳过etcd测试

```bash
./bin/config-validator -config configs/agentv2.yaml -test-etcd=false
```

适用于etcd不可用但需要验证配置格式的场景。

## 验证项目说明

### 基本配置验证

- ✅ **Agent标识码**：必须配置且长度合理
- ✅ **端口范围**：gRPC和HTTP端口必须在1-65535范围内
- ✅ **端口唯一性**：gRPC和HTTP端口不能相同
- ✅ **工作目录**：如果配置了工作目录，必须存在且为目录

### 注册配置验证

- ✅ **etcd端点**：如果注册功能启用，必须配置etcd端点
- ✅ **端点格式**：验证host:port格式
- ✅ **认证一致性**：用户名和密码必须同时配置或同时为空
- ✅ **时间配置**：注册间隔和TTL必须大于0
- ⚠️ **TTL建议**：TTL应该大于注册间隔，建议至少2倍

### 连接测试

- ✅ **etcd连接**：测试能否连接到etcd
- ✅ **etcd认证**：如果配置了认证，测试认证是否有效
- ✅ **网络连通性**：测试能否访问etcd服务器
- ✅ **端口可用性**：测试gRPC端口是否可用（未被占用）

## 错误处理

### 常见错误及解决方案

#### 1. 配置文件不存在

```
Error: Failed to load config: open configs/agentv2.yaml: no such file or directory
```

**解决**：检查配置文件路径是否正确

#### 2. etcd连接失败

```
Etcd Connection Test:
  Status:         ✗ Failed
  Error:          Failed to connect to etcd: context deadline exceeded
```

**可能原因**：
- etcd地址不正确
- etcd服务未运行
- 网络不通
- 认证信息错误

**解决**：
```bash
# 检查etcd服务
etcdctl --endpoints="192.168.100.122:2379" endpoint health

# 检查网络
ping 192.168.100.122
telnet 192.168.100.122 2379
```

#### 3. 端口被占用

```
Network Connectivity Test:
  gRPC Port:     ✗ Port 10380 is already in use
```

**解决**：
```bash
# 查找占用端口的进程
lsof -i :10380
# 或
netstat -tlnp | grep 10380

# 停止进程或更改端口配置
```

#### 4. 配置验证失败

```
Errors:
  [1] registry.etcd_endpoints is required when registry is enabled
  [2] registry.ttl must be greater than 0
```

**解决**：根据错误信息修正配置文件

## 集成到CI/CD

### 在部署前验证配置

```bash
#!/bin/bash
# deploy.sh

# 验证配置
echo "Validating configuration..."
if ! ./bin/config-validator -config configs/agentv2.yaml; then
    echo "Configuration validation failed!"
    exit 1
fi

# 继续部署流程
echo "Configuration validated, proceeding with deployment..."
# ...
```

### 在Git钩子中验证

```bash
#!/bin/bash
# .git/hooks/pre-commit

# 检查是否有配置文件变更
if git diff --cached --name-only | grep -q "configs/.*\.yaml$"; then
    echo "Validating changed configuration files..."
    for file in $(git diff --cached --name-only | grep "configs/.*\.yaml$"); do
        if ! ./bin/config-validator -config "$file"; then
            echo "Configuration validation failed for $file"
            exit 1
        fi
    done
fi
```

## 退出码

- `0`：验证通过
- `1`：验证失败（有错误）

可以在脚本中使用退出码判断验证结果：

```bash
if ./bin/config-validator -config configs/agentv2.yaml; then
    echo "Config is valid"
else
    echo "Config has errors"
    exit 1
fi
```

## 最佳实践

1. **部署前验证**：在部署Agent前始终验证配置
2. **使用JSON输出**：在自动化脚本中使用JSON格式便于解析
3. **定期验证**：定期运行验证工具确保配置正确
4. **版本控制**：将配置文件纳入版本控制，使用Git钩子自动验证
5. **文档化**：记录配置变更和验证结果

## 注意事项

1. **etcd连接**：验证工具会实际连接etcd，确保etcd可访问
2. **端口测试**：端口可用性测试会尝试绑定端口，如果端口被占用会失败
3. **认证信息**：配置文件中的密码会显示在输出中（JSON格式），注意安全
4. **网络要求**：网络连通性测试需要能够访问etcd服务器


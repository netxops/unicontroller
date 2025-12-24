# Agent V2 用户权限支持

Agent V2 支持在特权用户（root）和普通用户权限下运行，会根据运行用户自动调整路径和配置。

## 自动检测

Agent 会自动检测运行用户权限：
- **特权用户（root）**: `os.Geteuid() == 0`
- **普通用户**: 其他所有用户

## 默认路径配置

### 工作目录（Workspace）

用于存放服务包和 package.json 文件：

- **特权用户**: `/opt/uniops-agent`
- **普通用户**: `~/app/uniops-agent`

### 日志目录

用于存放 Agent 和服务的日志文件：

- **特权用户**: `/var/log/agentv2`
- **普通用户**: `~/.local/log/agentv2`

### 服务配置目录

用于存放服务的配置文件：

- **特权用户**: `/etc/{service_name}`
- **普通用户**: `~/.config/{service_name}`

## Systemd 模式

Agent 会根据用户权限自动选择 systemd 模式：

- **特权用户**: 使用 `systemctl`（system 模式）
- **普通用户**: 使用 `systemctl --user`（user 模式）

## 配置文件

在配置文件中，可以：

1. **留空使用默认值**（推荐）：
   ```yaml
   agent:
     workspace: ""  # 自动根据用户权限选择
   logging:
     directory: ""  # 自动根据用户权限选择
   ```

2. **指定自定义路径**：
   ```yaml
   agent:
     workspace: "/custom/path"
   logging:
     directory: "/custom/log/path"
   ```

## 使用示例

### 特权用户运行

```bash
sudo ./agentv2 -config configs/agentv2.yaml
```

将使用：
- 工作目录: `/opt/uniops-agent`
- 日志目录: `/var/log/agentv2`
- Systemd: system 模式

### 普通用户运行

```bash
./agentv2 -config configs/agentv2.yaml
```

将使用：
- 工作目录: `~/app/uniops-agent`
- 日志目录: `~/.local/log/agentv2`
- Systemd: user 模式

## 注意事项

1. **目录权限**: Agent 会自动创建不存在的目录，但需要确保有创建权限
2. **Systemd User 模式**: 普通用户模式下，需要确保 systemd user 服务已启用：
   ```bash
   systemctl --user enable systemd-user-session
   ```
3. **日志权限**: 确保日志目录有写入权限
4. **服务配置**: 服务的配置文件路径也会根据用户权限自动调整

## 路径工具函数

代码中提供了工具函数（`pkg/utils/user.go`）：
- `IsPrivilegedUser()`: 检查是否为特权用户
- `GetDefaultWorkspace()`: 获取默认工作目录
- `GetDefaultLogDirectory()`: 获取默认日志目录
- `GetDefaultConfigDirectory(serviceName)`: 获取默认配置目录

## 迁移指南

如果从特权用户迁移到普通用户（或反之）：

1. 更新配置文件中的路径（或留空使用默认值）
2. 确保新路径有适当的权限
3. 迁移数据（如需要）：
   ```bash
   # 从特权用户迁移到普通用户
   cp -r /opt/uniops-agent/* ~/app/uniops-agent/
   cp -r /var/log/agentv2/* ~/.local/log/agentv2/
   ```


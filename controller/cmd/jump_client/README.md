# Jump Client - SSH/Telnet 测试客户端

这是一个通过 Jump Server 连接 SSH 或 Telnet 的交互式测试客户端工具。

## 功能特性

- ✅ 支持通过 Jump Server 连接 SSH 服务器
- ✅ 支持通过 Jump Server 连接 Telnet 服务器（支持自动登录）
- ✅ 交互式终端支持（支持原始模式）
- ✅ 自动处理窗口大小变化
- ✅ 支持命令行参数配置

## 使用方法

### SSH 连接

```bash
# 基本用法
./jump_client \
  -jumper-host=192.168.1.100 \
  -jumper-port=50022 \
  -jumper-user=user \
  -jumper-password=password \
  -target-host=10.0.0.1 \
  -target-port=22 \
  -protocol=ssh \
  -telnet-user=root \
  -telnet-password=admin123

# 如果未提供 SSH 用户名和密码，程序会提示输入
./jump_client \
  -jumper-host=192.168.1.100 \
  -jumper-port=50022 \
  -jumper-user=user \
  -jumper-password=password \
  -target-host=10.0.0.1 \
  -target-port=22 \
  -protocol=ssh
```

### Telnet 连接

```bash
# 基本用法（带自动登录）
./jump_client \
  -jumper-host=192.168.1.100 \
  -jumper-port=50022 \
  -jumper-user=user \
  -jumper-password=password \
  -target-host=10.0.0.1 \
  -target-port=23 \
  -protocol=telnet \
  -telnet-user=admin \
  -telnet-password=admin123

# 如果未提供 Telnet 用户名和密码，程序会提示输入
./jump_client \
  -jumper-host=192.168.1.100 \
  -jumper-port=50022 \
  -jumper-user=user \
  -jumper-password=password \
  -target-host=10.0.0.1 \
  -target-port=23 \
  -protocol=telnet
```

## 命令行参数

| 参数 | 说明 | 默认值 | 必需 |
|------|------|--------|------|
| `-jumper-host` | Jump Server 主机地址 | `localhost` | 否 |
| `-jumper-port` | Jump Server 端口 | `50022` | 否 |
| `-jumper-user` | Jump Server 用户名 | `user` | 否 |
| `-jumper-password` | Jump Server 密码 | `your-password` | 否 |
| `-target-host` | 目标服务器主机地址 | - | **是** |
| `-target-port` | 目标服务器端口 | `22` | 否 |
| `-protocol` | 协议类型：`ssh` 或 `telnet` | `ssh` | 否 |
| `-telnet-user` | Telnet/SSH 用户名（用于目标服务器） | - | 否 |
| `-telnet-password` | Telnet/SSH 密码（用于目标服务器） | - | 否 |

## 工作原理

### SSH 连接流程

1. 客户端连接到 Jump Server（SSH）
2. 通过 Jump Server 的 `direct-tcpip` channel 转发到目标服务器
3. 在转发的连接上建立 SSH 会话
4. 创建交互式终端会话

### Telnet 连接流程

1. 客户端连接到 Jump Server（SSH）
2. 用户名格式：`telnet:username:password` 或 `telnet:username`
3. Jump Server 检测到 telnet 标识，使用 telnet proxy 功能
4. 自动执行 telnet 登录（如果提供了用户名和密码）
5. 建立交互式连接

## 注意事项

1. **安全性**：当前实现使用 `InsecureIgnoreHostKey()`，在生产环境中应验证主机密钥
2. **密码输入**：如果未通过命令行提供密码，程序会以安全方式提示输入（不显示在屏幕上）
3. **终端模式**：程序会自动设置终端为原始模式，退出时会恢复
4. **信号处理**：支持 `SIGWINCH`（窗口大小变化）、`SIGINT`、`SIGTERM` 信号

## 编译

```bash
cd /Users/huangliang/project/agent
go build -o jump_client ./cmd/jump_client/
```

## 示例

### 示例 1：通过 Jump Server 连接远程 SSH 服务器

```bash
./jump_client \
  -jumper-host=jump.example.com \
  -jumper-port=50022 \
  -jumper-user=myuser \
  -jumper-password=mypass \
  -target-host=192.168.1.50 \
  -target-port=22 \
  -protocol=ssh \
  -telnet-user=root \
  -telnet-password=rootpass
```

### 示例 2：通过 Jump Server 连接 Telnet 设备（自动登录）

```bash
./jump_client \
  -jumper-host=jump.example.com \
  -jumper-port=50022 \
  -jumper-user=myuser \
  -jumper-password=mypass \
  -target-host=192.168.1.100 \
  -target-port=23 \
  -protocol=telnet \
  -telnet-user=admin \
  -telnet-password=admin123
```

### 示例 3：交互式输入凭据

```bash
# 不提供目标服务器凭据，程序会提示输入
./jump_client \
  -jumper-host=jump.example.com \
  -jumper-port=50022 \
  -jumper-user=myuser \
  -jumper-password=mypass \
  -target-host=192.168.1.50 \
  -target-port=22 \
  -protocol=ssh
```

## 故障排除

1. **连接失败**：检查 Jump Server 地址和端口是否正确
2. **认证失败**：确认 Jump Server 和目标服务器的用户名和密码
3. **Telnet 登录失败**：检查 telnet 用户名和密码格式是否正确
4. **终端显示异常**：程序会自动处理终端模式，如果出现问题，可以尝试重新运行


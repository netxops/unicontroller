# Sangfor Adapter 测试代码

## 概述

这个目录包含了 Sangfor 防火墙 Adapter 的测试代码，用于测试和验证 Adapter 的各项功能。

## 前置要求

1. **Redis**: 需要运行 Redis 服务器（默认地址：127.0.0.1:6379）
2. **Go 环境**: 需要 Go 1.19 或更高版本
3. **网络连接**: 能够访问 Sangfor 防火墙设备

## 配置

在使用测试代码之前，请修改 `main.go` 中的以下配置：

```go
info := session.NewDeviceBaseInfo(
    "192.168.100.107", // 设备IP - 请修改为实际的设备IP
    "admin",           // 用户名 - 请修改为实际的用户名
    "yaan@123",       // 密码 - 请修改为实际的密码
    "Sangfor",        // 设备类型
    "",               // community
    443,              // 端口（HTTPS）
)
```

## 运行测试

```bash
cd pkg/nodemap/adapter/fw/sangfor/example
go run main.go
```

## 测试内容

测试代码会测试以下功能：

1. **设备信息获取** (`Info`)
   - 获取设备主机名、型号、版本、序列号等信息

2. **设备名称解析** (`ParseName`)
   - 解析设备名称

3. **接口列表获取** (`PortList`)
   - 获取所有网络接口及其配置信息

4. **路由表获取** (`RouteTable`)
   - 获取 IPv4 和 IPv6 路由表

5. **配置获取** (`GetConfig`)
   - 获取设备配置

6. **API 数据获取** (`GetResponseByApi`)
   - 测试各种 API 端点：
     - 网络对象 (IPGroups)
     - 服务 (Services)
     - 安全策略 (Securitys)
     - 区域 (Zones)
     - 接口 (Interfaces)
     - 静态路由 (StaticRoutes)
     - 策略路由 (PBRs)
     - 路由状态 (Routes)
     - NAT (NATs)

## 输出示例

```
=== 测试 Sangfor Adapter ===

1. 获取设备信息:
   ✓ 主机名: 192.168.100.107
   ✓ 型号: Sangfor Firewall
   ✓ 版本: Unknown
   ✓ 序列号: 

2. 解析设备名称:
   ✓ 设备名称: 192.168.100.107

3. 获取接口列表:
   ⚠ 未找到接口（可能需要完善 parseInterface 方法）

4. 获取路由表:
   ⚠ 未找到 IPv4 路由表（可能需要完善路由解析方法）
   ⚠ 未找到 IPv6 路由表（可能需要完善路由解析方法）

5. 获取配置:
   ⚠ 配置为空

6. 通过 API 获取数据:
   6.1 获取网络对象 (IPGroups):
      ✓ 网络对象数据:
      {
        "code": 0,
        "message": "success",
        "data": {
          ...
        }
      }
   ...
```

## 注意事项

1. **认证**: 如果设备需要 token 认证，可以在创建 `DeviceBaseInfo` 后使用 `WithToken()` 方法设置 token
2. **HTTPS**: Sangfor 防火墙使用 HTTPS 协议，默认端口为 443
3. **证书验证**: 代码中已禁用证书验证（`InsecureSkipVerify: true`），仅用于测试环境
4. **错误处理**: 如果某个 API 调用失败，测试会继续执行其他测试项

## 故障排除

### Redis 连接失败
- 确保 Redis 服务器正在运行
- 检查 Redis 地址和端口是否正确
- 如果 Redis 设置了密码，请在代码中配置

### 设备连接失败
- 检查设备 IP 地址是否正确
- 检查网络连接是否正常
- 检查用户名和密码是否正确
- 检查防火墙端口是否开放

### API 调用失败
- 检查 token 是否有效
- 检查命名空间是否正确
- 检查设备权限是否足够
- 查看错误信息以获取更多详情

## 扩展测试

可以根据需要添加更多测试用例：

1. **批量操作测试**: 测试 `BatchRun` 和 `BatchConfig` 方法
2. **原始配置获取**: 测试 `GetRawConfig` 方法
3. **特定 API 测试**: 针对特定 API 端点进行详细测试

## 相关文件

- `../sangfor.go`: Sangfor Adapter 主实现文件
- `../enum/enum.go`: API 路径枚举定义


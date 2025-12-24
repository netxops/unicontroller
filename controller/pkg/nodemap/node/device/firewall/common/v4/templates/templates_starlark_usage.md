# Starlark 模板系统使用说明

## 概述

本系统使用 Starlark 脚本定义防火墙配置模板，替代原有的 Go 代码模板定义方式。这种方式具有以下优势：

1. **更灵活**：模板逻辑可以用脚本语言编写，易于修改和扩展
2. **更易维护**：模板代码更清晰，逻辑更直观
3. **动态加载**：可以在运行时加载和更新模板，无需重新编译

## 文件结构

```
dsl/
├── templates_starlark.go           # Go 代码：模板注册表和加载器
├── templates/                      # 模板文件目录
│   ├── templates_asa.star          # Starlark 脚本：ASA 模板定义
│   ├── templates_dptech.star       # Starlark 脚本：DPTech 模板定义
│   ├── templates_forti.star        # Starlark 脚本：FortiGate 模板定义
│   ├── templates_sangfor.star      # Starlark 脚本：Sangfor 模板定义
│   ├── templates_secpath.star      # Starlark 脚本：SecPath 模板定义
│   └── templates_usg.star          # Starlark 脚本：USG 模板定义
└── ...
```

## 基本用法

### 1. 加载模板

```go
import "github.com/netxops/utils/dsl"

// 创建模板注册表
registry := dsl.NewTemplateRegistry()

// 从文件加载模板
err := registry.LoadTemplateFile("secpath", "templates_secpath.star")
if err != nil {
    log.Fatal(err)
}

// 或者从目录批量加载（推荐方式）
err = registry.LoadTemplatesFromDir("./templates")
if err != nil {
    log.Fatal(err)
}
```

### 2. 渲染模板

```go
// 准备数据
intent := &policy.Intent{
    // ... 设置 intent 数据
}

meta := map[string]interface{}{
    "object_name": "test_address",
    "is_source": true,
    "description": "Test address object",
}

// 渲染地址对象模板
result, err := registry.RenderTemplate("secpath", "AddressObject", intent, meta)
if err != nil {
    log.Fatal(err)
}

fmt.Println(result)
```

## Starlark 模板脚本格式

### 基本结构

每个模板文件应该包含：

1. **辅助函数**：用于格式化各种数据
2. **渲染函数**：每个模板类型对应一个渲染函数
3. **模板字典**：将模板类型名映射到渲染函数

### 示例：地址对象模板

```python
# 格式化地址条目的辅助函数
def format_address_item(item, is_source):
    """格式化地址对象条目"""
    if item.type == "range":
        return " range " + item.first + " " + item.last
    elif item.type == "host":
        return " host address " + item.ip
    elif item.type == "subnet":
        return " subnet " + item.ip + " " + item.mask
    return ""

# 地址对象渲染函数
def render_address_object(intent, meta):
    """渲染地址对象模板"""
    if not meta.get("object_name"):
        return ""
    
    result = "object-group ip address " + meta["object_name"] + "\n"
    network_list = intent.src.EachDataRangeEntryAsAbbrNet() if meta.get("is_source", False) else intent.dst.EachDataRangeEntryAsAbbrNet()
    
    for item in network_list:
        result += " network" + format_address_item(item, meta.get("is_source", False)) + "\n"
    
    return result

# 模板注册表
templates = {
    "AddressObject": render_address_object,
    # ... 其他模板
}
```

## 模板函数签名

所有模板渲染函数都应该遵循以下签名：

```python
def render_template_name(intent, meta):
    """
    渲染模板
    
    参数:
        intent: Intent 对象，包含 src、dst、service 等信息
        meta: 字典，包含模板所需的元数据（如 object_name、description 等）
    
    返回:
        str: 渲染后的配置字符串
    """
    # 实现逻辑
    return result
```

## 可用的 Intent 方法

在模板脚本中，可以使用以下 Intent 相关的方法：

### 网络遍历

```python
# 遍历源网络（所有类型：host、subnet、range）
for item in intent.src.EachDataRangeEntryAsAbbrNet():
    print(item.ip)
    print(item.type)  # "host", "subnet", "range"
    print(item.mask)  # 仅 subnet 类型

# 遍历目标网络
for item in intent.dst.EachDataRangeEntryAsAbbrNet():
    print(item.ip)
```

### 服务遍历

```python
# 遍历所有服务
for item in intent.service.EachDetailed():
    print(item.protocol)  # "TCP", "UDP", "ICMP", etc.
    print(item.dst_port)  # 目标端口对象
    print(item.src_port)  # 源端口对象

# 仅遍历 TCP 服务
for item in intent.service.TcpEach():
    print(item.dst_port)

# 仅遍历 UDP 服务
for item in intent.service.UdpEach():
    print(item.dst_port)

# 仅遍历 ICMP 服务
for item in intent.service.IcmpEach():
    print(item.type)  # ICMP type
    print(item.code)  # ICMP code
```

### Intent 组合遍历（某些厂商使用）

```python
# ASA 使用 intent.items() 遍历所有组合（源地址 × 目标地址 × 服务）
for item in intent.items():
    print(item.src.ip)      # 源地址 IP
    print(item.dst.ip)      # 目标地址 IP
    print(item.service.protocol)  # 服务协议
```

### 网络属性

```python
item.type      # "host", "subnet", "range"
item.ip        # IP 地址
item.first     # 起始 IP（range 类型）
item.last      # 结束 IP（range 类型）
item.mask      # 掩码（subnet 类型）
item.prefix    # 前缀长度（subnet 类型）
item.cidr      # CIDR 格式（如 "192.168.1.0/24"）
item.isHost    # 是否为主机
item.isNetwork # 是否为网络类型
item.isRange   # 是否为范围类型
item.isFull    # 是否为全网络（0.0.0.0/0）
```

### 服务属性

```python
item.protocol          # 协议名称（"TCP", "UDP", "ICMP" 等）
item.protocol.lower    # 协议名称小写（属性，不是方法）
item.dst_port          # 目标端口对象
item.src_port          # 源端口对象
item.dst_port.first    # 目标端口起始值（range 类型）
item.dst_port.last     # 目标端口结束值（range 类型）
item.dst_port.compact  # 目标端口紧凑格式（单端口）
item.dst_port.count    # 目标端口数量
item.dst_port.isFull   # 目标端口是否为全端口（0-65535）
item.src_port.first    # 源端口起始值（range 类型）
item.src_port.last     # 源端口结束值（range 类型）
item.src_port.compact  # 源端口紧凑格式（单端口）
item.src_port.count    # 源端口数量
item.src_port.isFull   # 源端口是否为全端口（0-65535）
item.hasType           # ICMP 是否有类型
item.hasCode           # ICMP 是否有代码
item.type              # ICMP 类型
item.code              # ICMP 代码
```

## Meta 数据常用字段

```python
meta.get("object_name")        # 对象名称
meta.get("is_source")          # 是否为源地址
meta.get("description")        # 描述信息
meta.get("policy_name")        # 策略名称
meta.get("policy_id")          # 策略 ID
meta.get("action")             # 动作（permit/deny）
meta.get("enable")             # 是否启用
meta.get("sourceZones")        # 源区域列表
meta.get("destinationZones")   # 目标区域列表
meta.get("src_objects")        # 源地址对象列表
meta.get("dst_objects")        # 目标地址对象列表
meta.get("service_objects")    # 服务对象列表
meta.get("has_source_objects") # 是否有源地址对象
meta.get("has_destination_objects") # 是否有目标地址对象
meta.get("has_service_objects")    # 是否有服务对象
meta.get("nat_type")           # NAT 类型（"DNAT"/"SNAT"）
meta.get("real_ip")            # 真实 IP
meta.get("real_port")          # 真实端口
meta.get("snat")               # SNAT 地址
meta.get("pool_id")            # 地址池 ID
meta.get("pool_name")          # 地址池名称
meta.get("vip_name")           # VIP 名称
meta.get("mip_name")           # MIP 名称
meta.get("mip_object")         # MIP 对象
meta.get("is_reused")          # 是否重用
meta.get("fromPort")           # 源接口/区域
meta.get("toPort")             # 目标接口/区域
meta.get("has_pool_id")        # 是否有地址池 ID
meta.get("has_interface_name") # 是否有接口名称
meta.get("has_easy_ip")        # 是否使用 Easy IP
meta.get("use_pool")           # 是否使用地址池
meta.get("is_ip_protocol")     # 是否为 IP 协议
meta.get("member_objects")     # 成员对象列表（用于 AddressGroup 和 ServiceGroup）
meta.get("has_mip_object")     # 是否有 MIP 对象
meta.get("has_real_ip")        # 是否有真实 IP
meta.get("has_real_port")      # 是否有真实端口
meta.get("real_ip_object")     # 真实 IP 对象
meta.get("dst_port")           # 目标端口（用于 VIP）
meta.get("protocol")            # 协议（用于 VIP，如 "tcp"）
meta.get("section_count")       # 段计数（用于 USG 的 SnatPool）
```

## 完整示例

### 示例 1：地址对象模板

```python
def render_address_object(intent, meta):
    if not meta.get("object_name"):
        return ""
    
    result = "object-group ip address " + meta["object_name"] + "\n"
    
    # 根据 is_source 选择源或目标网络
    network_list = intent.src.EachDataRangeEntryAsAbbrNet() if meta.get("is_source", False) else intent.dst.EachDataRangeEntryAsAbbrNet()
    
    for item in network_list:
        if item.type == "range":
            result += " network range " + item.first + " " + item.last + "\n"
        elif item.type == "host":
            result += " network host address " + item.ip + "\n"
        elif item.type == "subnet":
            result += " network subnet " + item.ip + " " + item.mask + "\n"
    
    return result
```

### 示例 2：服务对象模板

```python
def render_service_object(intent, meta):
    if not meta.get("object_name"):
        return ""
    
    result = "object-group service " + meta["object_name"] + "\n"
    
    for item in intent.service.EachDetailed():
        protocol = item.protocol
        result += " service " + protocol.lower
        
        if protocol == "TCP" or protocol == "UDP":
            if hasattr(item, "src_port") and not item.src_port.isFull:
                if item.src_port.count == 1:
                    result += " source eq " + item.src_port.compact
                else:
                    result += " source range " + item.src_port.first + " " + item.src_port.last
            if hasattr(item, "dst_port") and not item.dst_port.isFull:
                if item.dst_port.count == 1:
                    result += " destination eq " + item.dst_port.compact
                else:
                    result += " destination range " + item.dst_port.first + " " + item.dst_port.last
        elif protocol == "ICMP":
            if hasattr(item, "hasType") and item.hasType:
                result += " type " + str(item.type)
                if hasattr(item, "hasCode") and item.hasCode:
                    result += " code " + str(item.code)
        
        result += "\n"
    
    return result
```

### 示例 3：安全策略模板

```python
def render_policy(intent, meta):
    result = "security-policy ip\n"
    result += " rule " + str(meta.get("policy_id", "")) + " name " + meta.get("policy_name", "") + "\n"
    
    if meta.get("description"):
        result += "  description " + meta["description"] + "\n"
    
    # 源区域
    for zone in meta.get("sourceZones", []):
        result += "  source-zone " + zone + "\n"
    
    # 目标区域
    for zone in meta.get("destinationZones", []):
        result += "  destination-zone " + zone + "\n"
    
    # 源地址
    if meta.get("has_source_objects"):
        for obj in meta.get("src_objects", []):
            result += "  source-ip " + obj + "\n"
    else:
        for item in intent.src.EachDataRangeEntryAsAbbrNet():
            if item.type == "host":
                result += "  source-ip-host " + item.ip + "\n"
            elif item.type == "range":
                result += "  source-ip-range " + item.first + " " + item.last + "\n"
            else:
                result += "  source-ip-subnet " + item.ip + " " + item.mask + "\n"
    
    # 目标地址
    if meta.get("has_destination_objects"):
        for obj in meta.get("dst_objects", []):
            result += "  destination-ip " + obj + "\n"
    else:
        for item in intent.dst.EachDataRangeEntryAsAbbrNet():
            if item.type == "host":
                result += "  destination-ip-host " + item.ip + "\n"
            elif item.type == "range":
                result += "  destination-ip-range " + item.first + " " + item.last + "\n"
            else:
                result += "  destination-ip-subnet " + item.ip + " " + item.mask + "\n"
    
    # 服务
    if meta.get("has_service_objects"):
        for obj in meta.get("service_objects", []):
            result += "  service " + obj + "\n"
    else:
        for item in intent.service.EachDetailed():
            protocol = item.protocol
            result += "  service-port " + protocol.lower
            
            if protocol == "TCP" or protocol == "UDP":
                if hasattr(item, "src_port") and not item.src_port.isFull:
                    if item.src_port.count == 1:
                        result += " source eq " + item.src_port.compact
                    else:
                        result += " source range " + item.src_port.first + " " + item.src_port.last
                if hasattr(item, "dst_port") and not item.dst_port.isFull:
                    if item.dst_port.count == 1:
                        result += " destination eq " + item.dst_port.compact
                    else:
                        result += " destination range " + item.dst_port.first + " " + item.dst_port.last
            elif protocol == "ICMP":
                if hasattr(item, "hasType") and item.hasType:
                    result += " type " + str(item.type)
                    if hasattr(item, "hasCode") and item.hasCode:
                        result += " code " + str(item.code)
            
            result += "\n"
    
    result += "  action " + meta.get("action", "permit") + "\n"
    if not meta.get("enable", True):
        result += "  disable\n"
    
    return result
```

## 注意事项

1. **字符串连接**：Starlark 不支持 f-string，使用 `+` 进行字符串连接
2. **类型转换**：使用 `str()` 将数字转换为字符串
3. **字典访问**：使用 `meta.get(key, default)` 安全访问字典
4. **属性检查**：使用 `hasattr(obj, "attr")` 检查对象是否有某个属性
5. **条件判断**：使用 `if/elif/else` 进行条件判断
6. **循环遍历**：使用 `for item in list:` 进行遍历
7. **协议属性**：`protocol.lower` 是属性，不是方法，不要加括号 `()`
8. **网络范围**：使用 `item.first` 和 `item.last` 而不是 `item.start` 和 `item.end`
9. **端口范围**：使用 `port.first` 和 `port.last` 访问端口范围的起始和结束值
10. **厂商限制**：某些厂商不支持某些功能（如 SecPath 不支持 VIP 和 MIP），应返回空字符串

## 迁移指南

从原 Go 代码模板迁移到 Starlark 模板：

1. **DSL 语法转换**：
   - `{if:condition}...{endif}` → `if condition: ...`
   - `{for:item in list}...{endfor}` → `for item in list: ...`
   - `{item:attr}` → `item.attr`
   - `{meta:key}` → `meta.get("key")`

2. **函数定义**：
   - 将每个模板类型定义为独立的函数
   - 函数接收 `intent` 和 `meta` 两个参数
   - 返回渲染后的字符串

3. **模板注册**：
   - 在 `templates` 字典中注册所有模板函数
   - 键名对应模板类型名（如 "AddressObject"）
   - 值为对应的渲染函数

## 厂商支持情况

不同厂商对模板类型的支持情况：

| 模板类型 | ASA | DPTech | FortiGate | Sangfor | SecPath | USG |
|---------|-----|--------|-----------|---------|---------|-----|
| AddressObject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| AddressGroup | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ServiceObject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ServiceGroup | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Policy | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| NatPolicy | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| VIP | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ |
| MIP | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| SnatPool | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ |

**说明**：
- ❌ 表示不支持，模板函数应返回空字符串
- ✅ 表示支持

## 测试

```go
func TestTemplateRendering(t *testing.T) {
    registry := NewTemplateRegistry()
    
    // 从 templates 目录加载所有模板
    err := registry.LoadTemplatesFromDir("./templates")
    assert.NoError(t, err)
    
    intent := &policy.Intent{
        PolicyEntry: policy.PolicyEntry{
            PolicyEntrySrc:     network.NewNetworkGroupFromStringMust("192.168.1.0/24"),
            PolicyEntryDst:     network.NewNetworkGroupFromStringMust("10.0.0.1/32"),
            PolicyEntryService: service.NewServiceMust("tcp:80"),
        },
    }
    
    meta := map[string]interface{}{
        "object_name": "test",
        "is_source": true,
    }
    
    result, err := registry.RenderTemplate("secpath", "AddressObject", intent, meta)
    assert.NoError(t, err)
    assert.Contains(t, result, "object-group ip address test")
}
```

## 常见问题

### 1. 为什么使用 `protocol.lower` 而不是 `protocol.lower()`？

`protocol.lower` 是一个属性，不是方法。在 Starlark 中，协议对象通过 `Attr` 方法提供 `lower` 属性，返回小写的协议名称字符串。

### 2. 为什么使用 `first`/`last` 而不是 `start`/`end`？

为了保持一致性，网络范围和端口范围都使用 `first` 和 `last` 属性来表示起始和结束值。

### 3. 如何处理不支持的功能？

如果某个厂商不支持某个模板类型（如 SecPath 不支持 VIP），模板函数应该直接返回空字符串：

```python
def render_vip(intent, meta):
    """渲染VIP模板 - SecPath 不支持 VIP"""
    return ""
```

### 4. 如何检查端口是否为全端口？

使用 `port.isFull` 属性：

```python
if hasattr(item, "dst_port") and not item.dst_port.isFull:
    # 处理非全端口的情况
    if item.dst_port.count == 1:
        result += " destination eq " + item.dst_port.compact
    else:
        result += " destination range " + item.dst_port.first + " " + item.dst_port.last
```


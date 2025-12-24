# 在 Starlark 模板中访问 PolicyEntry

## 概述

在 Starlark 模板中生成命令行时，可以直接访问 `intent` 对象的 PolicyEntry 信息。

## 在 Starlark 模板中访问 PolicyEntry

### 基本访问方式

```python
def ServiceObject(intent, meta):
    """生成服务对象命令行"""
    result = "object service " + meta["object_name"] + "\n"
    
    # 访问 intent 的 service（对应 PolicyEntry.Service()）
    for item in intent.service.EachDetailed():
        result += "  service " + item.protocol.lower
        
        if item.protocol.Equal("TCP") or item.protocol.Equal("UDP"):
            if hasattr(item, "dst_port") and not item.dst_port.isFull:
                result += " eq " + item.dst_port.compact
        
        result += "\n"
    
    return result
```

### 访问源地址和目标地址

```python
def AddressObject(intent, meta):
    """生成地址对象命令行"""
    result = "object network " + meta["object_name"] + "\n"
    
    # 根据 is_source 决定访问 src 还是 dst
    is_source = meta.get("is_source", True)
    
    # intent.src 对应 PolicyEntry.Src()
    # intent.dst 对应 PolicyEntry.Dst()
    network_list = intent.src.EachDataRangeEntryAsAbbrNet() if is_source else intent.dst.EachDataRangeEntryAsAbbrNet()
    
    for item in network_list:
        if hasattr(item, "isHost") and item.isHost:
            result += "  host " + item.ip + "\n"
        elif hasattr(item, "isNetwork") and item.isNetwork:
            result += "  subnet " + item.ip + " " + item.mask.dotted + "\n"
        elif hasattr(item, "isRange") and item.isRange:
            result += "  range " + item.first + " " + item.last + "\n"
    
    return result
```

### PolicyEntry 的三个主要组件

在 Starlark 模板中可以通过 `intent` 访问：

1. **intent.src** - 源地址（对应 Go 中的 `PolicyEntry.Src()`）
   - 类型：`*network.NetworkGroup`
   - 方法：`EachIPNet()`, `EachDataRangeEntryAsAbbrNet()`, `String()` 等

2. **intent.dst** - 目标地址（对应 Go 中的 `PolicyEntry.Dst()`）
   - 类型：`*network.NetworkGroup`
   - 方法：同上

3. **intent.service** - 服务（对应 Go 中的 `PolicyEntry.Service()`）
   - 类型：`*service.Service`
   - 方法：`EachDetailed()`, `String()` 等

## 在 Go 代码中调试 PolicyEntry

### 使用 PrintDebug 函数

```go
import (
    "github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
    "github.com/netxops/utils/policy"
)

// 示例 1: 对比 NAT 规则的 Original 和 Translate
func exampleNatRule(rule firewall.FirewallNatRule) {
    firewall.PrintDebug(
        "NAT Original", 
        rule.Original(),
        "NAT Translate", 
        rule.Translate(),
    )
}

// 示例 2: 在生成对象时打印 Intent 的 PolicyEntry
func exampleServiceObject(intent *policy.Intent) {
    emptyEntry := policy.NewPolicyEntry()
    
    firewall.PrintDebug(
        "Service Object Intent", 
        intent,
        "Empty Entry", 
        emptyEntry,
    )
    
    // 继续生成服务对象 CLI...
}

// 示例 3: 对比两个 Intent 的 PolicyEntry
func exampleCompareIntents(intent1, intent2 *policy.Intent) {
    firewall.PrintDebug(
        "Intent 1", 
        intent1,
        "Intent 2", 
        intent2,
    )
}
```

### PrintDebug 输出格式

```
[DEBUG] NAT Original: src:192.168.1.0/24 dst:10.0.0.1/32 service:tcp:80
[DEBUG] NAT Translate: src:0.0.0.0/0 dst:172.16.0.1/32 service:tcp:8080
```

## 完整示例：ASA 服务对象生成

### Go 代码（service_object_generator.go）

```go
if isNew {
    // 生成服务对象CLI
    objectMeta := copyMap(g.ctx.MetaData)
    if intent.MetaData != nil {
        objectMeta["is_source_port"] = intent.MetaData["is_source_port"] == "true"
    }

    // 可选：调试打印 PolicyEntry
    // firewall.PrintDebug("Service Object Intent", intent, "Empty Entry", policy.NewPolicyEntry())
    
    // 通过 starlark 生成命令行
    // intent 会被传递到 starlark 模板中
    objectCli := g.renderLayout(intent, serviceObjectLayout, objectMeta)
    if objectCli != "" {
        result.CLIString = objectCli
    }
}
```

### Starlark 模板（templates_asa.star）

```python
def ServiceObject(intent, meta):
    """
    生成 ASA 服务对象
    
    在这个函数中：
    - intent.src 对应 Go 中的 intent.Src()
    - intent.dst 对应 Go 中的 intent.Dst()
    - intent.service 对应 Go 中的 intent.Service()
    """
    result = "object service " + meta["object_name"] + "\n"
    
    # 遍历服务条目
    for item in intent.service.EachDetailed():
        protocol = item.protocol
        result += "  service " + protocol.lower
        
        if protocol.Equal("TCP") or protocol.Equal("UDP"):
            if hasattr(item, "dst_port") and not item.dst_port.isFull:
                if item.dst_port.count == 1:
                    result += " destination eq " + item.dst_port.compact
                else:
                    result += " destination range " + item.dst_port.first + " " + item.dst_port.last
        
        result += "\n"
    
    return result
```

## 数据流向

```
Go 代码 (service_object_generator.go)
    |
    v
renderLayout(intent, serviceObjectLayout, objectMeta)
    |
    v
StarlarkTemplatesAdapter.RenderStarlarkTemplate(templateName, intent, meta)
    |
    v
Starlark 模板 (templates_asa.star)
    |
    v
访问: intent.src, intent.dst, intent.service
    |
    v
生成命令行字符串
```

## 注意事项

1. **Starlark 中的访问方式**：
   - 使用 `intent.src`（小写，无括号）
   - 不是 `intent.Src()`（Go 风格）

2. **PolicyEntry 的三个组件**：
   - 所有访问都通过 `intent` 对象
   - `src` 和 `dst` 是 NetworkGroup 类型
   - `service` 是 Service 类型

3. **调试技巧**：
   - 在 Go 代码中使用 `firewall.PrintDebug()` 打印 PolicyEntry
   - 在 Starlark 中可以使用 `print()` 函数（会输出到标准错误）
   - 建议在开发阶段启用调试，生产环境关闭

4. **空值检查**：
   - 在 Starlark 中使用 `hasattr()` 检查属性是否存在
   - 在 Go 中检查 `!= nil` 和 `!IsEmpty()`


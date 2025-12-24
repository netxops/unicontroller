# Starlark Intent 笛卡尔积实现示例

本文档展示了如何使用 Starlark 实现 Intent 的源、目标、服务的笛卡尔积。

## 基本实现

最简单的笛卡尔积实现：

```python
def cartesian_product():
    result = []
    
    # 获取源网络列表
    src_list = src.EachIPNet()
    
    # 获取目标网络列表
    dst_list = dst.EachIPNet()
    
    # 获取服务列表
    service_list = service.EachDetailed()
    
    # 三重循环生成笛卡尔积
    for s in src_list:
        for d in dst_list:
            for svc in service_list:
                # 格式化每个组合
                entry = s.cidr + " -> " + d.cidr + ": " + svc.protocol
                if svc.dst_port:
                    entry = entry + ":" + svc.dst_port
                result.append(entry)
    
    return "\n".join(result)

result = cartesian_product()
```

## 带格式化的实现

如果需要更详细的格式化输出：

```python
def cartesian_product_formatted():
    result = []
    
    src_list = src.EachIPNet()
    dst_list = dst.EachIPNet()
    service_list = service.EachDetailed()
    
    for s in src_list:
        for d in dst_list:
            for svc in service_list:
                # 格式化输出
                line = "Source: " + s.ip + "/" + str(s.prefix)
                line = line + " -> Destination: " + d.ip + "/" + str(d.prefix)
                line = line + " -> Service: " + svc.protocol
                if svc.dst_port:
                    line = line + ":" + svc.dst_port
                result.append(line)
    
    return "\n".join(result)

result = cartesian_product_formatted()
```

## 返回列表格式

如果需要返回结构化的列表数据：

```python
def cartesian_product_list():
    result = []
    
    src_list = src.EachIPNet()
    dst_list = dst.EachIPNet()
    service_list = service.EachDetailed()
    
    for s in src_list:
        for d in dst_list:
            for svc in service_list:
                # 创建字典格式的条目
                entry = {
                    "src": s.cidr,
                    "dst": d.cidr,
                    "service": svc.protocol + (":" + svc.dst_port if svc.dst_port else "")
                }
                result.append(entry)
    
    return result

def format_products(products):
    result = "Total combinations: " + str(len(products))
    for item in products:
        result = result + "\n" + item["src"] + " -> " + item["dst"] + ": " + item["service"]
    return result

products = cartesian_product_list()
result = format_products(products)
```

## 计算笛卡尔积数量

如果只需要计算组合数量：

```python
def cartesian_product_count():
    # 获取网络数量（不是 IP 数量）
    src_count = len(src.EachIPNet())
    dst_count = len(dst.EachIPNet())
    service_count = len(service.EachDetailed())
    
    total = src_count * dst_count * service_count
    return "Source networks: " + str(src_count) + "\n" + \
           "Destination networks: " + str(dst_count) + "\n" + \
           "Services: " + str(service_count) + "\n" + \
           "Total combinations: " + str(total)

result = cartesian_product_count()
```

## 使用 intent 对象

也可以直接使用 `intent` 对象：

```python
def cartesian_product_from_intent():
    result = []
    
    # 使用 intent.src, intent.dst, intent.service
    src_list = intent.src.EachIPNet()
    dst_list = intent.dst.EachIPNet()
    service_list = intent.service.EachDetailed()
    
    for s in src_list:
        for d in dst_list:
            for svc in service_list:
                entry = s.cidr + " -> " + d.cidr + ": " + svc.protocol
                if svc.dst_port:
                    entry = entry + ":" + svc.dst_port
                result.append(entry)
    
    return "\n".join(result)

result = cartesian_product_from_intent()
```

## 使用 intent.items() 方法

实际上，`intent.items()` 方法已经返回了笛卡尔积的结果：

```python
result = ""
for item in intent.items():
    result += item.src.cidr + " -> " + item.dst.cidr + ": " + item.service.protocol
    if item.service.dst_port:
        result += ":" + item.service.dst_port
    result += "\n"
```

## 注意事项

1. **网络数量 vs IP 数量**：使用 `len(src.EachIPNet())` 获取网络数量，而不是 `src.count`（IP 数量）
2. **服务遍历**：使用 `service.EachDetailed()` 获取所有服务的详细列表
3. **函数包装**：如果脚本包含顶层循环，需要将代码包装在函数中
4. **性能考虑**：对于大型网络组，笛卡尔积可能会产生大量组合，注意性能影响

## 完整示例

```python
def generate_cartesian_product():
    """
    生成 Intent 的完整笛卡尔积
    返回格式化的字符串列表
    """
    combinations = []
    
    # 获取所有源网络
    sources = src.EachIPNet()
    
    # 获取所有目标网络
    destinations = dst.EachIPNet()
    
    # 获取所有服务
    services = service.EachDetailed()
    
    # 生成笛卡尔积
    for src_net in sources:
        for dst_net in destinations:
            for svc in services:
                # 构建组合字符串
                combo = {
                    "source": src_net.cidr,
                    "destination": dst_net.cidr,
                    "protocol": svc.protocol,
                    "port": svc.dst_port if svc.dst_port else ""
                }
                combinations.append(combo)
    
    # 格式化输出
    output = []
    output.append("Total combinations: " + str(len(combinations)))
    output.append("")
    
    for combo in combinations:
        line = combo["source"] + " -> " + combo["destination"] + ": " + combo["protocol"]
        if combo["port"]:
            line += ":" + combo["port"]
        output.append(line)
    
    return "\n".join(output)

result = generate_cartesian_product()
```


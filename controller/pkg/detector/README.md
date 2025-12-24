# 设备检测模块 (Device Detector)

## 概述

设备检测模块采用MVP（最小可行产品）设计思路，实现了完全配置驱动的设备自动检测机制。所有检测能力都基于配置文件，实现了高度的模块化和可扩展性。

## 架构设计

### MVP模块化结构

```
DeviceDetector (主控制器)
├── ConnectivityChecker  (连接检测模块)
├── InfoCollector       (信息采集模块)
├── RuleLoader          (规则匹配模块)
├── VersionExtractor    (版本提取模块)
├── ConfigMatcher       (配置匹配模块)
└── DetectionCache      (缓存模块)
```

### 配置驱动

所有检测能力都通过配置文件定义：

1. **连接检测配置**: `detect/connectivity_check.yaml`
   - 定义支持的协议（SNMP、SSH、TELNET）
   - 定义检测方式和超时设置

2. **信息采集配置**: `detect/device_info_collect.yaml`
   - 定义采集策略和优先级
   - 定义采集项（OID、命令、超时等）
   - 支持fallback机制

3. **规则匹配配置**: `detect/rules/*.yaml`
   - 厂商规则：`manufacturer_rules.yaml`
   - 平台规则：`platform_rules.yaml`
   - 版本提取规则：内嵌在平台规则中

4. **配置匹配配置**: `detect/config_matcher.yaml`
   - 定义设备配置匹配策略

## 模块说明

### 1. ConnectivityChecker (连接检测模块)

**职责**: 基于配置文件检测设备支持的协议类型

**配置**: `detect/connectivity_check.yaml`

**功能**:
- 按优先级检测协议可用性
- 支持SNMP、SSH、TELNET协议检测
- 配置驱动的超时和重试设置

**示例配置**:
```yaml
protocols:
  - name: SNMP
    enabled: true
    check:
      type: SNMP
      timeout: 5s
    priority: 1
```

### 2. InfoCollector (信息采集模块)

**职责**: 基于配置文件采集设备信息

**配置**: `detect/device_info_collect.yaml`

**功能**:
- 支持多策略采集（按优先级）
- 支持SNMP、SSH、TELNET采集
- 支持fallback机制
- 支持批量采集（一次采集多个字段）

**示例配置**:
```yaml
strategies:
  - name: snmpFirst
    priority: 1
    conditions:
      - protocol: SNMP
        available: true
    collect:
      - name: sysInfo
        method: SNMP
        target: 1.3.6.1.2.1.1
        output: sysDescr, sysName
        snmpConfig:
          indexPositions: [1]
          prefixMap:
            "1": sysDescr
            "5": sysName
```

### 3. RuleLoader (规则匹配模块)

**职责**: 加载和匹配检测规则

**配置**: `detect/rules/manufacturer_rules.yaml`, `detect/rules/platform_rules.yaml`

**功能**:
- 加载厂商和平台规则
- 按优先级和置信度匹配规则
- 支持正则表达式匹配
- 支持必填字段验证

### 4. VersionExtractor (版本提取模块)

**职责**: 基于规则配置提取版本信息

**功能**:
- 从匹配的规则中提取版本
- 支持多个捕获组
- 优先返回完整版本格式

### 5. ConfigMatcher (配置匹配模块)

**职责**: 匹配设备配置

**配置**: `detect/config_matcher.yaml`

**功能**:
- 根据检测结果匹配设备配置
- 支持版本映射
- 支持fallback策略

## 使用示例

### 基本使用

```go
// 创建设备检测器
detector, err := detector.NewDeviceDetector(templatePath)
if err != nil {
    log.Fatal(err)
}

// 执行检测
req := &detector.DetectionRequest{
    IP:            "192.168.1.1",
    SNMPCommunity: "public",
    SSHCredentials: &detector.SSHCredentials{
        Username: "admin",
        Password: "password",
        Port:     22,
    },
}

result, err := detector.Detect(req)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Detected: %s %s %s\n", 
    result.Manufacturer, 
    result.Platform, 
    result.Version)
```

## 配置扩展

### 添加新的采集项

在 `device_info_collect.yaml` 中添加新的采集项：

```yaml
collect:
  - name: customInfo
    method: SNMP
    target: 1.3.6.1.4.1.xxx
    output: customField
    snmpConfig:
      indexPositions: [1]
      prefixMap:
        "1": customField
```

### 添加新的检测规则

在 `platform_rules.yaml` 中添加新规则：

```yaml
rules:
  - name: vendor_platform_snmp
    manufacturer: Vendor
    platform: Platform
    priority: 20
    patterns:
      - source: sysDescr
        regex: "(?i)vendor.*platform"
        confidence: 0.9
        required: true
    versionExtract:
      source: sysDescr
      regex: "Version\\s+(\\S+)"
```

## MVP设计原则

1. **最小可行**: 先实现核心功能，保持简单
2. **配置驱动**: 所有能力都通过配置定义，无需修改代码
3. **模块化**: 每个模块职责单一，易于测试和扩展
4. **可扩展**: 通过配置文件轻松添加新设备类型和采集项

## 未来扩展

- [ ] 支持更多协议（API、Redfish等）
- [ ] 支持自定义采集器插件
- [ ] 支持采集结果验证和校验
- [ ] 支持采集结果缓存策略配置
- [ ] 支持分布式检测

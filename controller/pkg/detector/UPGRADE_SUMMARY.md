# 设备检测模块升级总结

## 升级目标

1. **模块化改造** - 以MVP思路进行模块化设计
2. **配置驱动** - 所有检查能力都基于配置

## 模块化架构

### 新增模块

1. **ConnectivityChecker** (`connectivity_checker.go`)
   - 职责：连接检测
   - 配置：`detect/connectivity_check.yaml`
   - 功能：基于配置检测协议可用性

2. **InfoCollector** (`info_collector.go`)
   - 职责：信息采集
   - 配置：`detect/device_info_collect.yaml`
   - 功能：基于配置采集设备信息（SNMP、SSH、TELNET）

3. **VersionExtractor** (`version_extractor.go`)
   - 职责：版本提取
   - 配置：从规则配置中读取
   - 功能：基于规则配置提取版本信息

### 重构的模块

1. **DeviceDetector** (`detector.go`)
   - 移除硬编码的采集逻辑
   - 使用模块化组件
   - 简化为流程编排

2. **RuleLoader** (`rule_loader.go`)
   - 移除版本提取逻辑（移至VersionExtractor）
   - 添加GetMatchedRule方法供版本提取使用

## 配置驱动改进

### 1. 连接检测配置化

**之前**: 硬编码的端口检测逻辑
```go
if req.SSHCredentials != nil {
    port := req.SSHCredentials.Port
    if port == 0 {
        port = 22
    }
    // ...
}
```

**现在**: 基于配置文件
```yaml
protocols:
  - name: SSH
    check:
      type: TCP
      port: 22
      timeout: 5s
```

### 2. 信息采集配置化

**之前**: 硬编码的OID和命令
```go
st, err := snmp.NewSnmpTask(
    req.IP,
    req.SNMPCommunity,
    "1.3.6.1.2.1.1", // 硬编码
    []int{1},        // 硬编码
    // ...
)
```

**现在**: 基于配置文件
```yaml
collect:
  - name: sysInfo
    method: SNMP
    target: 1.3.6.1.2.1.1
    snmpConfig:
      indexPositions: [1]
      prefixMap:
        "1": sysDescr
        "5": sysName
```

### 3. 版本提取配置化

**之前**: 硬编码在规则匹配中
```go
if best.VersionExtract != nil {
    version := extractVersion(...)
}
```

**现在**: 独立的VersionExtractor模块，基于规则配置

## MVP设计原则

1. **最小可行**: 先实现核心功能，保持简单
2. **单一职责**: 每个模块只负责一个功能
3. **配置驱动**: 所有能力都通过配置定义
4. **易于扩展**: 通过配置文件轻松添加新功能

## 文件结构

```
pkg/detector/
├── detector.go              # 主控制器（流程编排）
├── connectivity_checker.go  # 连接检测模块（新增）
├── info_collector.go        # 信息采集模块（新增）
├── version_extractor.go     # 版本提取模块（新增）
├── rule_loader.go           # 规则匹配模块（重构）
├── config_matcher.go        # 配置匹配模块（已有）
├── cache.go                 # 缓存模块（已有）
├── types.go                 # 类型定义（扩展）
└── README.md                # 文档（新增）

deploy/templates/detect/
├── connectivity_check.yaml      # 连接检测配置
├── device_info_collect.yaml     # 信息采集配置（更新）
├── config_matcher.yaml          # 配置匹配配置
└── rules/
    ├── manufacturer_rules.yaml   # 厂商规则
    └── platform_rules.yaml      # 平台规则（含版本提取规则）
```

## 使用方式

### 基本使用（无变化）

```go
detector, _ := detector.NewDeviceDetector(templatePath)
result, _ := detector.Detect(req)
```

### 扩展采集能力（配置驱动）

只需修改 `device_info_collect.yaml`，无需修改代码：

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

## 优势

1. **可维护性**: 模块职责清晰，易于理解和维护
2. **可扩展性**: 通过配置文件轻松扩展，无需修改代码
3. **可测试性**: 每个模块可独立测试
4. **配置驱动**: 所有能力都基于配置，灵活性强

## 向后兼容

- API接口保持不变
- 检测结果格式不变
- 配置文件格式向后兼容（支持旧格式）

## 下一步优化建议

1. 支持更多协议（API、Redfish等）
2. 支持自定义采集器插件
3. 支持采集结果验证和校验
4. 支持采集结果缓存策略配置
5. 支持分布式检测


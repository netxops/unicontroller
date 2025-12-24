# 设备自动检测配置

## 目录结构

```
detect/
├── README.md                    # 本文件
├── connectivity_check.yaml      # 连接检测配置
├── device_info_collect.yaml     # 设备信息采集配置
├── config_matcher.yaml          # 配置匹配策略
└── rules/                        # 检测规则库
    ├── manufacturer_rules.yaml   # 厂商识别规则
    ├── platform_rules.yaml       # 平台识别规则
    └── version_rules.yaml        # 版本识别规则
```

## 使用说明

### 1. 检测流程

设备检测分为以下几个阶段：

1. **连接检测**: 检测设备支持的协议（SNMP/SSH/TELNET）
2. **信息采集**: 根据可用协议采集设备标识信息
3. **规则匹配**: 使用规则库识别厂商和平台
4. **配置匹配**: 根据识别结果查找对应的设备配置
5. **结果验证**: 验证检测结果的准确性

### 2. 添加新设备类型

要添加新的设备类型检测，需要：

1. 在 `rules/manufacturer_rules.yaml` 中添加厂商识别规则
2. 在 `rules/platform_rules.yaml` 中添加平台识别规则
3. 在 `rules/version_rules.yaml` 中添加版本提取规则（可选）
4. 在对应的设备目录下创建配置模板

### 3. 规则优先级

规则按以下顺序匹配：

1. **优先级**: 数字越大优先级越高
2. **置信度**: 匹配成功的规则按置信度排序
3. **必需条件**: 标记为 `required: true` 的条件必须匹配

### 4. 检测结果

检测结果包含：

- `manufacturer`: 厂商名称
- `platform`: 平台名称
- `version`: 版本信息（如果可提取）
- `catalog`: 设备分类（NETWORK/SERVER/SWITCH/FIREWALL）
- `confidence`: 检测置信度（0.0-1.0）
- `deviceConfig`: 匹配到的设备配置

## 配置示例

### 厂商识别规则

```yaml
rules:
  - name: cisco
    manufacturer: Cisco
    priority: 10
    patterns:
      - source: sysDescr
        regex: "(?i)cisco"
        confidence: 0.9
```

### 平台识别规则

```yaml
rules:
  - name: cisco_ios
    manufacturer: Cisco
    platform: IOS
    priority: 20
    patterns:
      - source: sysDescr
        regex: "(?i)cisco.*ios.*software"
        confidence: 0.9
```

## 注意事项

1. 正则表达式使用Go的regexp语法
2. 置信度范围：0.0-1.0，建议使用0.7以上
3. 规则优先级建议：厂商规则10，平台规则20，版本规则30
4. 检测超时时间建议：SNMP 5s，SSH 10-15s


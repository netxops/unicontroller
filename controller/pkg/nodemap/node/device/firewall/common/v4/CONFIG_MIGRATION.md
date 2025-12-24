# V4 配置项迁移指南

本文档说明 config.yaml 中配置项在 V4 版本中的使用情况。

## 配置项分析（基于 config.yaml 382-417 行）

### ✅ 仍在使用（继续支持）

#### NAT 策略配置
- **`dnat_object_type`** ✅
  - 用途：指定 DNAT 对象类型（NETWORK_OBJECT/MIP/VIP/INLINE）
  - V4 位置：`templates_v4.go:147`
  - 示例：`dnat_object_type: "NETWORK_OBJECT"`

- **`snat_pool_type`** ✅
  - 用途：指定 SNAT 池类型（NETWORK_OBJECT/INTERFACE/INLINE/SNAT_POOL）
  - V4 位置：`templates_v4.go:151, 273`
  - 示例：`snat_pool_type: "NETWORK_OBJECT"`

- **`natpolicy.name_template`** ✅
  - 用途：NAT 策略命名模板
  - V4 位置：`templates_v4.go:140`, `nat_name_generator.go:48`
  - 示例：`natpolicy.name_template: "{VAR:ticket_number}_nat_{SEQ:id:5:1:1:MAIN}"`

- **`input.nat`** ✅
  - 用途：指定输入 NAT 类型（natpolicy.dnat）
  - V4 位置：`templates_v4.go:279`
  - 示例：`input.nat: "natpolicy.dnat"`

- **`output.nat`** ✅
  - 用途：指定输出 NAT 类型（natpolicy.snat）
  - V4 位置：`templates_v4.go:283`
  - 示例：`output.nat: "natpolicy.snat"`

#### 安全策略配置
- **`securitypolicy.source_address_style`** ✅
  - 用途：控制源地址对象风格（object/inline）
  - V4 位置：`templates_v4.go:209`
  - 示例：`securitypolicy.source_address_style: "object"`

- **`securitypolicy.destination_address_style`** ✅
  - 用途：控制目标地址对象风格（object/inline）
  - V4 位置：`templates_v4.go:231`
  - 示例：`securitypolicy.destination_address_style: "object"`

- **`securitypolicy.address_style`** ✅
  - 用途：通用地址对象风格（object/inline），当 source/destination_address_style 未设置时使用
  - V4 位置：`templates_v4.go:217, 239`
  - 示例：`securitypolicy.address_style: "object"`

- **`securitypolicy.service_style`** ✅
  - 用途：控制服务对象风格（object/inline）
  - V4 位置：`templates_v4.go:253`
  - 示例：`securitypolicy.service_style: "object"`

- **`securitypolicy.reuse_address_object`** ✅
  - 用途：是否复用已存在的地址对象
  - V4 位置：`templates_v4.go:113, 186`
  - 示例：`securitypolicy.reuse_address_object: true`

- **`securitypolicy.reuse_service_object`** ✅
  - 用途：是否复用已存在的服务对象
  - V4 位置：`templates_v4.go:119, 192`
  - 示例：`securitypolicy.reuse_service_object: true`

- **`securitypolicy.enable`** ✅
  - 用途：控制策略是否启用（true/false）
  - V4 位置：`templates_v4.go:128`
  - 示例：`securitypolicy.enable: "true"`

- **`securitypolicy.reuse_policy`** ✅
  - 用途：是否复用已存在的策略
  - V4 位置：`templates_v4.go:123`
  - 示例：`securitypolicy.reuse_policy: true`

- **`securitypolicy.empty_zone_matches_any`** ✅
  - 用途：当zone列表为空时，是否匹配任何zone
  - V4 位置：`templates_v4.go:124`
  - 示例：`securitypolicy.empty_zone_matches_any: false`

- **`action`** ✅
  - 用途：策略动作（permit/deny）
  - V4 位置：`templates_v4.go:127`, `policy_generator.go:296, 311`
  - 示例：`action: "permit"`

### ❌ 已废弃（不再使用）

#### NAT 策略配置
- **`natpolicy.snat.source_style`** ❌
  - **替代方案**：使用 `natpolicy.snat.source_object` (布尔值)
  - V4 位置：`templates_v4.go:170`
  - 迁移：`natpolicy.snat.source_style: "required"` → `natpolicy.snat.source_object: true`

- **`natpolicy.snat.destination_style`** ❌
  - **替代方案**：使用 `natpolicy.snat.destination_object` (布尔值)
  - V4 位置：`templates_v4.go:172`
  - 迁移：`natpolicy.snat.destination_style: "required"` → `natpolicy.snat.destination_object: true`

- **`natpolicy.dnat.source_style`** ❌
  - **替代方案**：使用 `natpolicy.dnat.source_object` (布尔值)
  - V4 位置：`templates_v4.go:162`
  - 迁移：`natpolicy.dnat.source_style: "required"` → `natpolicy.dnat.source_object: true`

- **`natpolicy.dnat.destination_style`** ❌
  - **替代方案**：使用 `natpolicy.dnat.destination_object` (布尔值)
  - V4 位置：`templates_v4.go:164`
  - 迁移：`natpolicy.dnat.destination_style: "required"` → `natpolicy.dnat.destination_object: true`

- **`natpolicy.use_service_object`** ❌
  - **替代方案**：使用 `natpolicy.dnat.service_object` 或 `natpolicy.snat.service_object` (布尔值)
  - V4 位置：`templates_v4.go:166, 174`
  - 迁移：
    - DNAT: `natpolicy.use_service_object: true` → `natpolicy.dnat.service_object: true`
    - SNAT: `natpolicy.use_service_object: true` → `natpolicy.snat.service_object: true`

- **`natpolicy.dnat.mip_as_address_object`** ❌
  - **状态**：未在 V4 代码中找到使用
  - **建议**：如果不再需要，可以移除；如果需要，可能需要添加到 V4 实现中

## 迁移示例

### 旧配置（V2/V3）
```yaml
natpolicy:
  snat:
    source_style: "required"
    destination_style: "required"
  dnat:
    source_style: "required"
    destination_style: "required"
  use_service_object: true
```

### 新配置（V4）
```yaml
natpolicy:
  snat:
    source_object: true        # 替代 source_style: "required"
    destination_object: true   # 替代 destination_style: "required"
    service_object: true       # 替代 use_service_object: true
  dnat:
    source_object: true        # 替代 source_style: "required"
    destination_object: true   # 替代 destination_style: "required"
    service_object: true       # 替代 use_service_object: true
```

## 总结

- **仍在使用**：15 个配置项
- **已废弃**：6 个配置项（需要迁移到新的布尔值配置）

V4 版本简化了配置，将字符串风格的配置（"required"/"optional"/"none"）统一改为布尔值配置（true/false），使配置更加直观和易于理解。


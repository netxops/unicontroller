# SecPath V4 测试配置清单

## 配置项统计

- **NAT策略配置**: 12项
- **安全策略配置**: 8项
- **总计**: 20项

## NAT策略配置

- `input.nat`: "natpolicy.dnat"
- `output.nat`: "natpolicy.snat"
- `dnat_object_type`: "NETWORK_OBJECT" | "INLINE"
- `snat_pool_type`: "SNAT_POOL" | "INTERFACE"
- `natpolicy.dnat.object_style`: "true"
- `natpolicy.dnat.source_object`: "true" | "false"
- `natpolicy.dnat.destination_object`: "true" | "false"
- `natpolicy.dnat.service_object`: "true" | "false"
- `natpolicy.snat.object_style`: "true"
- `natpolicy.snat.source_object`: "true" | "false"
- `natpolicy.snat.destination_object`: "true" | "false"
- `natpolicy.snat.service_object`: "true" | "false"

## 安全策略配置

- `policy_name_template`: 策略名称模板（DSL格式）
- `service_object_name_template`: 服务对象名称模板（DSL格式）
- `network_object_name_template`: 网络对象名称模板（DSL格式）
- `securitypolicy.object_style`: "true" | "false"
- `securitypolicy.source_object`: "true" | "false"
- `securitypolicy.destination_object`: "true" | "false"
- `securitypolicy.service_object`: "true" | "false"
- `reuse_policy`: "true" | "false"


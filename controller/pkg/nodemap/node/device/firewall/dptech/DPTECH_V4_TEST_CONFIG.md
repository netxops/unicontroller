# DPTech V4 测试配置清单

## 配置项统计

- **NAT策略配置**: 12项
- **安全策略配置**: 9项
- **总计**: 21项

## NAT策略配置

- `input.nat`: "natpolicy.dnat"
- `output.nat`: "natpolicy.snat"
- `dnat_object_type`: "MIP"（DPTech只支持MIP）
- `snat_object_type`: "SNAT_POOL" | "INTERFACE"
- `natpolicy.dnat.object_style`: "true"
- `natpolicy.dnat.source_object`: "true"（DPTech的NAT policy源地址必须是对象）
- `natpolicy.dnat.destination_object`: "true"（DPTech的NAT policy目标地址必须是对象）
- `natpolicy.dnat.service_object`: "true" | "false"
- `natpolicy.snat.object_style`: "true"
- `natpolicy.snat.source_object`: "true"（DPTech的NAT policy源地址必须是对象）
- `natpolicy.snat.destination_object`: "true"（DPTech的NAT policy目标地址必须是对象）
- `natpolicy.snat.service_object`: "true" | "false"

## 安全策略配置

- `policy_name_template`: 策略名称模板（DSL格式）
- `service_object_name_template`: 服务对象名称模板（DSL格式）
- `network_object_name_template`: 网络对象名称模板（DSL格式）
- `securitypolicy.address_style`: "object"（DPTech的policy中源地址、目标地址只支持对象模式）
- `securitypolicy.object_style`: "true"（DPTech的policy中源地址、目标地址只支持对象模式）
- `securitypolicy.source_object`: "true"（DPTech的policy中源地址只支持对象模式）
- `securitypolicy.destination_object`: "true"（DPTech的policy中目标地址只支持对象模式）
- `securitypolicy.service_object`: "true" | "false"
- `reuse_policy`: "true" | "false"


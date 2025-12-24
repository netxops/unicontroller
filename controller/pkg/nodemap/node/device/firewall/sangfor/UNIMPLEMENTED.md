# Sangfor 防火墙实现 - 未完成功能分析

## 1. CLI 生成功能（高优先级）

### 1.1 对象 CLI 生成
- **文件**: `object.go`
- **位置**: 
  - `SangforNetworkObject.Cli()` (line 99)
  - `SangforServiceObject.Cli()` (line 183)
- **状态**: 返回空字符串
- **需要**: 根据 Sangfor 的实际 CLI 语法生成网络对象和服务对象的配置命令

### 1.2 NAT 规则 CLI 生成
- **文件**: `nat.go`
- **位置**: `NatRule.Cli()` (line 39)
- **状态**: 返回空字符串
- **需要**: 生成 SNAT/DNAT/BNAT 规则的 CLI 配置

### 1.3 策略 CLI 生成
- **文件**: `policy.go`
- **位置**: `Policy.Cli()` (line 42)
- **状态**: 返回空字符串
- **需要**: 生成安全策略的 CLI 配置

## 2. 模板实现（高优先级）

### 2.1 Sangfor 特定模板
- **文件**: `common/templates_setting.go`
- **位置**: `NewSangforTemplates()` (lines 1498-1510)
- **状态**: 所有模板都是 TODO 占位符
- **需要实现**:
  - `NetworkObject.OneLoop`: 网络对象模板
  - `ServiceObject.OneLoop`: 服务对象模板
  - `Policy.OneLoop`: 策略模板
  - 可能还需要 NAT 相关模板

## 3. 输出策略功能（中优先级）

### 3.1 OutputPolicy 方法
- **文件**: `sangfor.go`
- **位置**: `OutputPolicy()` (line 149)
- **状态**: 返回 `nil`
- **需要**: 实现输出策略匹配逻辑

### 3.2 MakeOutputPolicyCli 方法
- **文件**: `sangfor.go`
- **位置**: `MakeOutputPolicyCli()` (line 226)
- **状态**: 返回 `nil, nil`
- **需要**: 实现输出策略 CLI 生成

## 4. 迭代器接口（中优先级）

### 4.1 IteratorFirewall 接口
- **状态**: 完全未实现
- **需要实现的方法**:
  - `PolicyIterator(opts ...IteratorOption) NamerIterator`
  - `AclIterator(opts ...IteratorOption) NamerIterator`
  - `NetworkIterator(opts ...IteratorOption) NamerIterator`
  - `ServiceIterator(opts ...IteratorOption) NamerIterator`
  - `SnatIterator(opts ...IteratorOption) NamerIterator`
  - `DnatIterator(opts ...IteratorOption) NamerIterator`
  - `StaticNatIterator(opts ...IteratorOption) NamerIterator`
  - `NatPoolIterator(opts ...IteratorOption) NamerIterator`
- **参考**: `forti/iterator.go` 中的实现

## 5. NAT 池相关功能（中优先级）

### 5.1 GetPoolByNetworkGroup
- **文件**: `nat.go`
- **位置**: `GetPoolByNetworkGroup()` (line 101)
- **状态**: 返回 `nil, false`
- **需要**: 根据网络组查找 NAT 池对象

### 5.2 HasPoolName
- **文件**: `nat.go`
- **位置**: `HasPoolName()` (line 107)
- **状态**: 返回 `false`
- **需要**: 检查是否存在指定名称的 NAT 池

## 6. 辅助功能（低优先级）

### 6.1 L4Port 查找
- **文件**: `object.go`
- **位置**: `L4Port()` (line 575)
- **状态**: 返回 `nil, false`
- **需要**: 根据名称查找 L4 端口对象

### 6.2 FromPorts/ToPorts
- **文件**: `policy.go`
- **位置**: `FromPorts()` (line 62), `ToPorts()` (line 66)
- **状态**: 返回空数组
- **需要**: 根据区域查找对应的接口（Port）列表
- **注意**: 可能需要接口映射或区域到接口的转换逻辑

## 7. 策略解析增强（低优先级）

### 7.1 用户/用户组处理
- **文件**: `policy.go`
- **位置**: `parsePolicyItem()` (line 174)
- **状态**: TODO 注释，暂时跳过
- **需要**: 解析 `srcAddrs` 中的 `users` 和 `userGroups` 字段
- **影响**: 如果策略使用用户/用户组作为源地址，当前无法正确解析

### 7.2 接口匹配检查
- **文件**: `policy.go`
- **位置**: `Match()` (line 238)
- **状态**: TODO 注释，跳过接口检查
- **需要**: 根据 Sangfor 实际格式检查源接口和目标接口
- **影响**: 策略匹配可能不够精确

## 8. FlyConfig 增强（低优先级）

### 8.1 字符串解析
- **文件**: `init.go`
- **位置**: `FlyConfig()` (line 109)
- **状态**: TODO，仅打印日志
- **需要**: 实现字符串格式的 CLI 解析逻辑
- **影响**: 如果传入字符串格式的 CLI，无法解析

## 9. 其他潜在问题

### 9.1 域名对象支持
- **文件**: `object.go`
- **位置**: `parseNetworkItem()` (line 254)
- **状态**: 注释说明暂时不处理
- **需要**: 如果 Sangfor 支持域名网络对象，需要实现解析逻辑
- **注意**: `network.NetworkGroup` 可能不支持域名，需要特殊处理

### 9.2 端口范围解析优化
- **文件**: `object.go`
- **位置**: `parsePortRanges()` (line 500)
- **状态**: 多个端口范围时只返回第一个
- **需要**: 支持多个端口范围的完整处理（当前用逗号连接，但可能需要更复杂的逻辑）

### 9.3 NAT 转换配置解析
- **文件**: `nat.go`
- **位置**: `parseNatItem()` (lines 231-252, 332-354)
- **状态**: 只处理了部分转换类型
- **需要**: 可能需要支持更多转换类型，如：
  - `OUTIF_IP`: 出接口 IP
  - `IP_RANGE`: IP 范围
  - `IP_PREFIX`: IP 前缀
  - `SLB_POOL`: SLB 地址池（DNAT）

## 10. 测试和验证

### 10.1 单元测试
- **状态**: 未发现测试文件
- **需要**: 创建 `templates_test.go` 等测试文件，验证：
  - 对象解析正确性
  - NAT 规则解析和匹配
  - 策略解析和匹配
  - CLI 生成（实现后）

### 10.2 集成测试
- **需要**: 使用真实的 Sangfor API 响应数据进行端到端测试

## 优先级总结

### 高优先级（核心功能）
1. ✅ 对象解析（已完成）
2. ✅ NAT 解析（已完成）
3. ✅ 策略解析（已完成）
4. ❌ CLI 生成（未实现）
5. ❌ 模板实现（未实现）

### 中优先级（重要功能）
1. ❌ 输出策略功能
2. ❌ 迭代器接口
3. ❌ NAT 池功能

### 低优先级（增强功能）
1. ❌ 用户/用户组支持
2. ❌ 接口匹配检查
3. ❌ FlyConfig 字符串解析
4. ❌ 域名对象支持
5. ❌ L4Port 查找

## 建议实现顺序

1. **第一步**: 实现模板（`templates_setting.go`），这是 CLI 生成的基础
2. **第二步**: 实现 CLI 生成方法（`Cli()` 方法）
3. **第三步**: 实现输出策略功能
4. **第四步**: 实现迭代器接口（如果需要查询功能）
5. **第五步**: 实现 NAT 池功能
6. **第六步**: 增强策略解析（用户/用户组、接口匹配）
7. **第七步**: 其他辅助功能


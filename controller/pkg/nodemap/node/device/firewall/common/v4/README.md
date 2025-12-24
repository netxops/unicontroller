# V4 版本架构说明

## 概述

V4 版本对 MakePolicyV3 和 MakeNatPolicyV3 进行了重构，使用 struct 来组织代码，提高了代码的可维护性和可扩展性。

## 架构设计

### 核心组件

1. **AddressObjectGenerator** - 地址对象生成器
   - 负责生成源地址对象和目标地址对象
   - 支持单个对象和地址组两种模式
   - 支持对象复用

2. **ServiceObjectGenerator** - 服务对象生成器
   - 负责生成服务对象
   - 支持单个对象和服务组两种模式
   - 支持对象复用

3. **NatObjectGenerator** - NAT对象生成器
   - 负责生成VIP/MIP对象（DNAT）
   - 负责生成SNAT_POOL对象（SNAT）
   - 支持多种对象类型：VIP、MIP、NETWORK_OBJECT、SNAT_POOL、INTERFACE、INLINE

4. **PolicyGenerator** - 策略生成器
   - 使用 AddressObjectGenerator 和 ServiceObjectGenerator
   - 负责生成安全策略CLI
   - 支持策略复用

5. **NatPolicyGenerator** - NAT策略生成器
   - 使用 AddressObjectGenerator、ServiceObjectGenerator 和 NatObjectGenerator
   - 负责生成NAT策略CLI
   - 支持Twice NAT和Object NAT两种模式

### 数据结构

#### 配置结构
- `AddressObjectGeneratorConfig` - 地址对象生成器配置
- `ServiceObjectGeneratorConfig` - 服务对象生成器配置
- `NatObjectGeneratorConfig` - NAT对象生成器配置
- `PolicyGeneratorConfig` - 策略生成器配置
- `NatPolicyGeneratorConfig` - NAT策略生成器配置

#### 结果结构
- `AddressObjectResult` - 地址对象生成结果
- `ServiceObjectResult` - 服务对象生成结果
- `VipMipResult` - VIP/MIP生成结果
- `SnatPoolResult` - SNAT_POOL生成结果
- `PolicyResult` - 策略生成结果
- `NatPolicyResult` - NAT策略生成结果

#### 上下文结构
- `GeneratorContext` - 生成器上下文，包含共享资源
- `GeneratorInput` - 生成器输入参数

## 使用方式

### 基本使用

```go
// 创建上下文
ctx := &v4.GeneratorContext{
    Node:      node,
    Templates: templates,
    MetaData:  metaData,
}

// 创建策略生成器
policyConfig := v4.PolicyGeneratorConfig{
    PolicyNameTemplate: "{VAR:ticket_number}_policy_{SEQ:id:5:10000:1:MAIN}",
    AddressObjectConfig: v4.AddressObjectGeneratorConfig{
        UseSourceObject:      true,
        UseDestinationObject: true,
        ReuseAddressObject:   true,
    },
    ServiceObjectConfig: v4.ServiceObjectGeneratorConfig{
        UseServiceObject:   true,
        ReuseServiceObject: true,
    },
    ReusePolicy: true,
    Enable:      "true",
    Action:      "permit",
}

generator := v4.NewPolicyGenerator(ctx, policyConfig)

// 创建输入参数
input := &v4.GeneratorInput{
    Intent:  intent,
    FromPort: fromPort,
    ToPort:   toPort,
    FromZone: fromZone,
    ToZone:   toZone,
    Context:  policyContext,
}

// 生成策略
result, err := generator.Generate(input)
```

### 使用 CommonTemplatesV4

```go
// 创建V4模板实例
templatesV4 := v4.NewCommonTemplatesV4(node, templates, metaData)

// 生成策略
policyResult, err := templatesV4.MakePolicyV4(from, to, intent, ctx, metaData)

// 生成NAT策略
natResult, err := templatesV4.MakeNatPolicyV4(from, to, intent, ctx, metaData)
```

## 优势

1. **模块化设计** - 每个生成器独立负责特定功能，职责清晰
2. **易于测试** - 每个生成器可以独立测试
3. **易于扩展** - 新增功能只需添加新的生成器或扩展现有生成器
4. **配置集中** - 所有配置通过结构体管理，便于维护
5. **类型安全** - 使用强类型结构体，减少运行时错误

## 与V3版本的对比

| 特性 | V3版本 | V4版本 |
|------|--------|--------|
| 代码组织 | 函数式 | Struct式 |
| 配置管理 | 分散在函数参数中 | 集中在Config结构体中 |
| 可测试性 | 中等 | 高 |
| 可扩展性 | 中等 | 高 |
| 代码复用 | 中等 | 高 |

## 文件结构

```
v4/
├── types.go                    # 类型定义
├── helpers.go                  # 辅助函数
├── address_object_generator.go # 地址对象生成器
├── service_object_generator.go # 服务对象生成器
├── nat_object_generator.go     # NAT对象生成器
├── policy_generator.go         # 策略生成器
├── nat_policy_generator.go     # NAT策略生成器
├── templates_v4.go             # 主入口文件
└── README.md                   # 本文档
```


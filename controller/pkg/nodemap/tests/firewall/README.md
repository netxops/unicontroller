# 防火墙节点测试

## 概述

本目录包含防火墙节点相关的测试，包括各个厂商防火墙节点的基础功能和策略生成测试。

## 测试结构

```
firewall/
├── firewall_base_test.go    # 防火墙基础接口测试
└── README.md                # 本文件
```

## 测试计划

### 基础测试
- [x] 防火墙节点接口实现验证
- [x] 防火墙节点基础功能测试

### 各厂商防火墙节点测试（未来扩展）

#### USG 防火墙
- [ ] USG 节点创建和初始化
- [ ] USG 策略生成
- [ ] USG NAT 策略生成
- [ ] USG 对象管理

#### SecPath 防火墙
- [ ] SecPath 节点创建和初始化
- [ ] SecPath 策略生成
- [ ] SecPath NAT 策略生成
- [ ] SecPath 对象管理

#### FortiGate 防火墙
- [ ] FortiGate 节点创建和初始化
- [ ] FortiGate 策略生成
- [ ] FortiGate NAT 策略生成
- [ ] FortiGate 对象管理

#### 其他厂商
- [ ] ASA 防火墙测试
- [ ] SRX 防火墙测试
- [ ] Sangfor 防火墙测试
- [ ] Dptech 防火墙测试

## 使用指南

### 运行测试

```bash
# 运行所有防火墙测试
go test ./pkg/nodemap/tests/firewall/...

# 运行特定测试
go test ./pkg/nodemap/tests/firewall -run TestFirewallNodeInterface
```

### 添加新测试

1. 使用 `fixtures` 包创建测试数据
2. 使用 `helpers` 包中的辅助函数
3. 遵循现有的测试模式

## 注意事项

- 防火墙节点测试可能需要模拟设备配置
- 某些测试可能需要网络连接（未来可以添加 mock）
- 测试应该覆盖正常流程和异常情况


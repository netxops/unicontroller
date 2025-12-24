# NodeMap 测试框架

## 概述

本目录包含 NodeMap 项目的完整测试套件，采用模块化设计，支持逐步完善测试覆盖。

## 目录结构

```
tests/
├── README.md                    # 本文件
├── fixtures/                    # 测试数据和 mock 对象
│   ├── nodemap_fixtures.go      # NodeMap 测试数据生成器
│   ├── firewall_fixtures.go     # 防火墙节点测试数据生成器
│   └── network_fixtures.go      # 网络数据生成器
├── helpers/                     # 测试辅助函数
│   ├── test_helpers.go          # 通用测试辅助函数
│   ├── assert_helpers.go       # 自定义断言函数
│   └── logger.go                # 测试日志配置
├── nodemap/                     # NodeMap 核心功能测试
│   ├── nodemap_test.go          # NodeMap 基础功能测试
│   ├── locate_node_test.go      # 源节点定位测试（包括地址列表匹配）
│   ├── serialize_test.go        # 序列化/反序列化测试
│   └── stub_test.go             # Stub 节点测试
├── firewall/                     # 防火墙节点测试
│   ├── firewall_base_test.go    # 防火墙基础接口测试
│   └── README.md                # 防火墙测试说明
└── traverse/                     # 网络遍历测试（未来扩展）
    └── README.md                 # 遍历测试说明（占位）
```

## 使用指南

### 运行测试

```bash
# 运行所有测试
go test ./pkg/nodemap/tests/...

# 运行特定模块测试
go test ./pkg/nodemap/tests/nodemap/...

# 运行单个测试文件
go test ./pkg/nodemap/tests/nodemap/nodemap_test.go

# 运行特定测试函数
go test ./pkg/nodemap/tests/nodemap -run TestNodeMapCreation

# 查看测试覆盖率
go test ./pkg/nodemap/tests/... -cover
```

### 添加新测试

1. **确定测试模块**：根据测试目标选择对应的模块目录
   - `nodemap/` - NodeMap 核心功能
   - `firewall/` - 防火墙节点相关
   - `traverse/` - 网络遍历相关

2. **使用 Fixtures**：使用 `fixtures` 包中的函数创建测试数据
   ```go
   import "github.com/influxdata/telegraf/controller/pkg/nodemap/tests/fixtures"
   
   nm := fixtures.NewTestNodeMap()
   node := fixtures.NewTestNode("node1")
   ```

3. **使用 Helpers**：使用 `helpers` 包中的辅助函数
   ```go
   import "github.com/influxdata/telegraf/controller/pkg/nodemap/tests/helpers"
   
   logger := helpers.SetupTestLogger()
   helpers.AssertNodeMapEqual(t, expected, actual)
   ```

4. **编写测试**：遵循 Go 测试命名规范
   ```go
   func TestFeatureName(t *testing.T) {
       // 测试代码
   }
   ```

## 测试数据管理

所有测试数据通过 `fixtures` 包统一生成，确保：
- 测试数据的一致性
- 测试的可维护性
- 测试数据的可复用性

### 使用 Fixtures

```go
// 创建基础 NodeMap
nm := fixtures.NewTestNodeMap()

// 创建带地址列表的 NodeMap
nm := fixtures.NewTestNodeMap(
    fixtures.WithAddressList([]*config.AddressListInfo{...}),
)

// 创建测试节点
node := fixtures.NewTestNode("node1", api.FIREWALL)

// 创建测试端口
port := fixtures.NewTestPort("port1", "192.168.1.1/24")
```

## 测试辅助函数

`helpers` 包提供以下功能：

- **日志管理**：统一的测试日志配置
- **断言函数**：针对 NodeMap 特定类型的断言
- **比较函数**：深度比较复杂数据结构
- **清理函数**：测试后的数据清理

## 模块说明

### nodemap/
NodeMap 核心功能的单元测试，包括：
- NodeMap 的创建和管理
- 节点和端口的操作
- 源节点定位（包括地址列表匹配）
- 序列化/反序列化
- Stub 节点处理

### firewall/
防火墙节点相关的测试，包括：
- 防火墙节点接口实现
- 各厂商防火墙节点的基础功能
- 策略生成和匹配
- NAT 策略处理

### traverse/
网络遍历和路径分析的测试（未来扩展）

## 最佳实践

1. **使用 Fixtures**：不要直接创建测试数据，使用 fixtures 包
2. **保持独立**：每个测试应该是独立的，不依赖其他测试的执行顺序
3. **清理资源**：测试后清理创建的资源
4. **使用断言**：使用 `testify/assert` 或自定义断言函数
5. **命名清晰**：测试函数名应该清晰描述测试内容
6. **测试覆盖**：优先测试核心功能和边界情况

## 扩展计划

- [ ] 添加 traverse 模块测试
- [ ] 完善各厂商防火墙节点的详细测试
- [ ] 添加集成测试
- [ ] 添加性能测试
- [ ] 添加测试覆盖率报告

## 贡献指南

添加新测试时，请确保：
1. 遵循现有的代码风格
2. 使用 fixtures 和 helpers
3. 添加必要的注释
4. 更新相关文档


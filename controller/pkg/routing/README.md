# routing - 通用路由处理项目

## 概述

`routing` 是一个通用的路由处理项目，提供3层路由查询、路径计算、多路径支持等核心能力。

## 核心功能

1. **路由查询**：支持IPv4/IPv6路由查询
2. **路径计算**：支持从源到目标的路径计算
3. **多路径支持**：支持ECMP（等价多路径）
4. **路径跟踪系统**：完整的路径跟踪和管理能力

## 项目结构

```
pkg/routing/
├── core/              # 核心路由处理
├── model/             # 数据模型
├── graph/             # 图结构（网络拓扑）
├── multipath/         # 多路径支持
├── query/             # 查询接口
└── example/           # 使用示例
```

## 使用示例

```go
import "github.com/netxops/l2service/pkg/routing"

// 创建拓扑
topology := routing.NewTopology()

// 创建路径计算器
calculator := routing.NewPathCalculator(topology, &routing.PathQueryOptions{
    Source:      srcNetwork,
    Destination: dstNetwork,
    EnableECMP:  true,
})

// 计算路径
paths, err := calculator.CalculatePath(ctx)
```


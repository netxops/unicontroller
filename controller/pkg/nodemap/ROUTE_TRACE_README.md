# 路由跟踪系统使用说明

## 概述

路由跟踪系统为 `NodeMap.MakeTemplates` 函数提供了完整的路由和路由抉择过程记录功能。它能够跟踪 Intent 在网络拓扑中的路由过程，记录每个节点的路由决策，以及整个路由路径的构建过程。

## 主要功能

### 1. 路由跟踪事件类型

系统定义了以下路由跟踪事件类型：

- `EventMakeTemplatesStart/End`: MakeTemplates 函数开始和结束
- `EventTraverseStart/End`: 路由遍历开始和结束
- `EventLocateNodeStart/End`: 源节点定位开始和结束
- `EventRouteQueryStart/End`: 路由查询开始和结束
- `EventNextHopFound`: 找到下一跳节点
- `EventOutsidePortFound`: 找到 Outside 端口
- `EventStubPortFound`: 找到 Stub 端口
- `EventLoopDetected`: 检测到路由循环
- `EventRouteDecision`: 路由决策记录
- `EventNodeProcessing`: 节点处理记录
- `EventPathUpdate`: 路径更新记录

### 2. 核心组件

#### RouteTracer
路由跟踪器，负责记录和管理所有路由跟踪事件。

```go
type RouteTracer struct {
    entries    []RouteTraceEntry
    logger     *zap.Logger
    intentID   string
    startTime  time.Time
    context    context.Context
}
```

#### RouteTraceEntry
路由跟踪条目，记录单个路由事件。

```go
type RouteTraceEntry struct {
    Timestamp   time.Time         `json:"timestamp"`
    Event       RouteTraceEvent   `json:"event"`
    IntentID    string            `json:"intent_id,omitempty"`
    NodeName    string            `json:"node_name,omitempty"`
    PortName    string            `json:"port_name,omitempty"`
    VRF         string            `json:"vrf,omitempty"`
    Path        string            `json:"path,omitempty"`
    NextHop     string            `json:"next_hop,omitempty"`
    OutPort     string            `json:"out_port,omitempty"`
    Area        string            `json:"area,omitempty"`
    Decision    string            `json:"decision,omitempty"`
    Reason      string            `json:"reason,omitempty"`
    Error       string            `json:"error,omitempty"`
    Details     map[string]interface{} `json:"details,omitempty"`
    Duration    time.Duration     `json:"duration,omitempty"`
}
```

## 使用方法

### 1. 基本使用

路由跟踪功能已经集成到 `MakeTemplates` 函数中，无需额外配置即可使用：

```go
// 创建 NodeMap 和 Intent
nm := &NodeMap{...}
intent := &policy.Intent{...}
ctx := context.Background()

// 调用 MakeTemplates，路由跟踪会自动启用
tp := nm.MakeTemplates(intent, ctx)

// 获取路由跟踪信息
if tp.RouteTracer != nil {
    // 打印路由跟踪摘要
    tp.PrintRouteTrace()
    
    // 获取 JSON 格式的跟踪数据
    traceJSON, err := tp.GetRouteTraceJSON()
    if err == nil {
        fmt.Println(string(traceJSON))
    }
    
    // 获取跟踪摘要
    summary := tp.GetRouteTraceSummary()
    fmt.Printf("访问的节点: %v\n", summary["nodes_visited"])
    fmt.Printf("总事件数: %d\n", summary["total_events"])
}
```

### 2. 手动记录路由决策

如果需要记录自定义的路由决策，可以使用以下方法：

```go
// 记录路由决策
tp.LogRouteDecision("firewall-01", "eth0", "default", "forward", "匹配到路由表", map[string]interface{}{
    "route_table": "main",
    "next_hop": "192.168.1.1",
})

// 记录路径更新
tp.LogPathUpdate("default:firewall-01|default:router-01")
```

### 3. 获取跟踪数据

```go
// 获取所有跟踪条目
entries := tp.RouteTracer.GetTraceEntries()
for _, entry := range entries {
    fmt.Printf("事件: %s, 节点: %s, 时间: %s\n", 
        entry.Event, entry.NodeName, entry.Timestamp)
}

// 获取跟踪摘要
summary := tp.RouteTracer.GetTraceSummary()
fmt.Printf("Intent ID: %s\n", summary["intent_id"])
fmt.Printf("持续时间: %v\n", summary["duration"])
fmt.Printf("访问的节点: %v\n", summary["nodes_visited"])
```

## 跟踪数据格式

### JSON 格式示例

```json
[
  {
    "timestamp": "2024-01-15T10:30:00Z",
    "event": "MakeTemplatesStart",
    "intent_id": "intent_1705312200_192.168.1.0/24_10.0.0.0/8",
    "details": {
      "intent": {...}
    }
  },
  {
    "timestamp": "2024-01-15T10:30:01Z",
    "event": "LocateNodeStart",
    "intent_id": "intent_1705312200_192.168.1.0/24_10.0.0.0/8",
    "details": {
      "src_network": "192.168.1.0/24",
      "vrf": "default",
      "area": "",
      "gateway": ""
    }
  },
  {
    "timestamp": "2024-01-15T10:30:02Z",
    "event": "NextHopFound",
    "intent_id": "intent_1705312200_192.168.1.0/24_10.0.0.0/8",
    "node_name": "firewall-01",
    "next_hop": "192.168.1.1",
    "out_port": "eth0",
    "details": {
      "current_node": "firewall-01",
      "next_node": "router-01",
      "next_port": "eth1",
      "next_hop_ip": "192.168.1.1",
      "out_port": "eth0"
    }
  }
]
```

### 跟踪摘要格式

```json
{
  "intent_id": "intent_1705312200_192.168.1.0/24_10.0.0.0/8",
  "total_events": 15,
  "duration": "2.5s",
  "start_time": "2024-01-15T10:30:00Z",
  "end_time": "2024-01-15T10:30:02Z",
  "event_counts": {
    "MakeTemplatesStart": 1,
    "MakeTemplatesEnd": 1,
    "TraverseStart": 1,
    "TraverseEnd": 1,
    "LocateNodeStart": 1,
    "LocateNodeEnd": 1,
    "RouteQueryStart": 3,
    "RouteQueryEnd": 3,
    "NextHopFound": 2,
    "OutsidePortFound": 1
  },
  "nodes_visited": ["firewall-01", "router-01", "switch-01"],
  "paths": [
    "default:firewall-01",
    "default:firewall-01|default:router-01",
    "default:firewall-01|default:router-01|default:switch-01"
  ]
}
```

## 集成说明

### 1. 自动集成

路由跟踪功能已经自动集成到以下关键函数中：

- `NodeMap.MakeTemplates()`: 创建路由跟踪器并记录开始/结束事件
- `TraverseProcess.Traverse()`: 记录遍历开始/结束和源节点定位事件
- `TraverseNode.RunL3Route()`: 记录路由查询和下一跳发现事件

### 2. 日志输出

路由跟踪器会同时输出到：
- 结构化日志（通过 zap.Logger）
- 内存中的跟踪条目（用于后续分析）

### 3. 性能影响

路由跟踪功能对性能的影响很小：
- 事件记录是轻量级操作
- 跟踪数据存储在内存中
- 可以通过设置 `RouteTracer` 为 `nil` 来禁用跟踪

## 故障排除

### 1. 没有跟踪数据

确保 `TraverseProcess.RouteTracer` 不为 `nil`：

```go
if tp.RouteTracer == nil {
    fmt.Println("路由跟踪器未初始化")
}
```

### 2. 跟踪数据不完整

检查日志级别设置，确保路由跟踪事件能够正常输出：

```go
logger, _ := zap.NewDevelopment() // 开发环境
// 或
logger, _ := zap.NewProduction()  // 生产环境
```

### 3. 内存使用

对于长时间运行的服务，建议定期清理跟踪数据或限制跟踪条目的数量。

## 扩展功能

### 1. 自定义事件类型

可以添加新的事件类型：

```go
const EventCustomEvent RouteTraceEvent = "CustomEvent"

tracer.LogEvent(EventCustomEvent, map[string]interface{}{
    "custom_data": "value",
})
```

### 2. 持久化存储

可以将跟踪数据保存到文件或数据库：

```go
// 保存到文件
traceJSON, _ := tp.GetRouteTraceJSON()
ioutil.WriteFile("route_trace.json", traceJSON, 0644)

// 保存到数据库（需要实现相应的数据库接口）
// saveToDatabase(tp.RouteTracer.GetTraceEntries())
```

### 3. 实时监控

可以基于跟踪数据实现实时路由监控和告警功能。

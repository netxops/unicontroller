# pkg/nodemap - 网络设备仿真建模与策略自动化配置系统

## 概述

`pkg/nodemap` 是一个企业级网络设备仿真建模和策略自动化配置系统，专门用于处理安全策略工单和网络设备配置管理。该系统支持多厂商路由器、交换机、防火墙、负载均衡设备，通过仿真网络环境实现端到端的策略自动开通能力。

系统提供两个核心功能：
- **MakeTemplates**: 用于安全策略工单处理，生成新的防火墙策略配置
- **Policies**: 用于灵活查询和匹配现有的安全策略，进行策略分析和审计

## 核心功能

### 1. 安全策略工单处理与生成
- **源节点定位**: 自动识别和定位策略工单中的源节点
- **安全策略匹配**: 在仿真网络中进行策略匹配分析
- **防火墙策略生成**: 自动生成设备特定的防火墙策略配置
- **配置下发**: 生成可执行的设备配置命令

### 2. 策略查询与匹配
- **多维度策略匹配**: 支持地址、服务、动作等多维度策略查询
- **策略冲突检测**: 自动检测和报告策略冲突
- **策略影响分析**: 分析策略变更对网络的影响
- **策略审计**: 进行策略合规性检查和审计

### 3. 多厂商设备支持
- **防火墙设备**: USG、ASA、SRX、FortiGate、SecPath、Dptech
- **负载均衡设备**: F5
- **路由器设备**: H3C、思科IOS、思科Nexus

### 4. 网络路径分析
- **源节点定位**: 基于源网络和目标网络自动定位入口节点
- **路由路径构建**: 通过路由表查询构建完整的数据包路径
- **环路检测**: 自动检测和避免路由环路
- **多路径支持**: 支持直连、下一跳、Outside、Stub等多种路径类型

### 5. 策略命名与配置风格定制
- **命名模板**: 支持自定义策略、对象、服务的命名规则
- **配置风格**: 支持对象风格和直接配置风格切换
- **策略复用**: 支持现有策略的复用和匹配
- **运维规范**: 确保生成的配置符合客户的安全运维习惯

## 系统架构

### 核心组件

```
pkg/nodemap/
├── nodemap.go          # 核心网络拓扑管理
├── policy.go           # 策略匹配和查询引擎
├── traverse.go         # 网络遍历和路径分析核心
├── factory.go          # 设备适配器工厂
├── node/               # 设备节点抽象
│   ├── device/         # 具体设备实现
│   │   ├── firewall/   # 防火墙设备
│   │   │   ├── process.go    # 防火墙策略处理核心
│   │   │   ├── api.go        # 防火墙接口定义
│   │   │   ├── step.go       # 处理步骤定义
│   │   │   └── [vendor]/     # 厂商特定实现
│   │   └── lb/         # 负载均衡设备
│   └── processor/      # 节点处理器
├── adapter/            # 设备适配器
├── api/                # 接口定义
├── config/             # 配置管理
└── example/            # 使用示例
```

### 主要数据结构

#### NodeMap - 网络拓扑容器
```go
type NodeMap struct {
    Name       string
    Ports      []api.Port
    Nodes      []api.Node
    Ipv4Areas  []*config.AreaInfo
    Ipv6Areas  []*config.AreaInfo
    Ipv4Stubs  []*StubInfo
    Ipv6Stubs  []*StubInfo
    CxMananger *ConnectorManager
    TNodeMapID *uint
    logger     *zap.Logger
    taskId     uint
    mutex      sync.Mutex
}
```

#### PolicyMatchResult - 策略匹配结果
```go
type PolicyMatchResult struct {
    Policy         firewall.FirewallPolicy
    MatchDetails   map[string]MatchDetail
    MatchType      MatchType
    MatchedAddress *network.NetworkGroup
    OverallMatch   bool
}
```

## 核心方法详解

### 1. 网络遍历与节点定位 (Traverse)

**位置**: `pkg/nodemap/traverse.go`

**功能**: 在NodeMap的多个节点中进行工单定位和路由分析，构建完整的网络路径

**核心组件**:

#### TraverseProcess - 遍历处理器
```go
type TraverseProcess struct {
    SimpleGraph
    Intent         *policy.Intent
    IPFamily       network.IPFamily
    NodeMap        *NodeMap
    Vrf            string
    Gateway        string
    Area           string
    TraverseOnly   bool
    Results        *TraverseResult
    FuncationNodes []api.Node
    Vertices       map[interface{}]graph.Vertex
    logger         *zap.Logger
}
```

#### TraverseNode - 遍历节点
```go
type TraverseNode struct {
    nm           *NodeMap
    Node         api.Node
    Intent       *policy.Intent
    InVrf        string
    InPort       api.Port
    Neighbor     map[interface{}]graph.Vertex
    IPFamily     network.IPFamily
    Path         string
    Ok           bool
    Info         string
    Process      *TraverseProcess
    TraverseOnly bool
    logger       *zap.Logger
}
```

**详细处理流程**:

#### 1. 源节点定位
```go
func (tp *TraverseProcess) Traverse(ctx context.Context) {
    // 1. 进入Traverse入口
    // 2. 开始定位源节点
    ok, srcNode, portNameOrMsg = tp.NodeMap.LocateNode(srcNetworkList, dstNetworkList, tp.Intent.InputNode, tp.Vrf, tp.Gateway, tp.Area)
    // 3. 源节点定位完成
    // 4. 源端口确定
    // 5. 开始进行路由查询
}
```

#### 2. 路由查询与路径构建
```go
func (tn *TraverseNode) RunL3Route(traverseOnly bool, ctx context.Context) (processErr model.ProcessErr) {
    // 1. 检查环路避免
    // 2. 执行路由查询
    ok, hopTable, _, _ := tn.Node.IpRouteCheck(*dstNetworkList, tn.InPort.Name(), tn.InVrf, tn.IPFamily)
    // 3. 处理下一跳
    // 4. 递归处理后续节点
}
```

#### 3. 节点类型处理
- **防火墙节点**: 执行策略匹配和生成
- **负载均衡节点**: 执行负载均衡策略处理
- **路由器节点**: 执行路由转发

#### 4. 路径类型支持
- **直连路由**: 目标网络直接连接
- **下一跳路由**: 通过其他设备转发
- **Outside路由**: 外部网络路由
- **Stub路由**: 存根网络路由

**环路检测机制**:
```go
func (tn *TraverseNode) IsLoop() bool {
    var pathList []string
    if tn.Path != "" {
        pathList = append(pathList, strings.Split(tn.Path, "|")...)
    }
    path := tn.InVrf + ":" + tn.Node.Name()
    return tools.Contains(pathList, path)
}
```

### 2. MakeTemplates - 安全策略工单处理与生成

**位置**: `pkg/nodemap/nodemap.go` (入口) 和 `pkg/nodemap/node/device/firewall/process.go` (具体实现)

**功能**: 接收安全策略工单，执行源节点定位、安全策略匹配，**生成新的防火墙策略配置**

**主要用途**: 
- **安全策略工单处理**: 处理新的安全策略开通需求
- **策略配置生成**: 根据工单要求生成新的防火墙策略
- **配置下发**: 生成可执行的设备配置命令
- **策略验证**: 在仿真环境中验证生成的策略

**工作流程**:
1. **意图分离**: 将策略意图分离为IPv4和IPv6两部分
2. **遍历处理**: 创建TraverseProcess进行网络遍历
3. **源节点定位**: 自动定位策略工单中的源节点
4. **策略匹配**: 在仿真网络中进行安全策略匹配
5. **策略生成**: 生成设备特定的防火墙策略配置

**详细处理流程** (在 `firewall/process.go` 中实现):

#### 防火墙策略处理阶段
```go
func (fp *FirewallProcess) MakeTemplates(ctx context.Context, intent *policy.Intent, inPort api.Port, vrf api.Vrf, force bool) (translateTo *policy.Intent, cmdList []interface{}, additionCli []string, err model.ProcessErr)
```

**四个核心处理阶段**:

1. **INPUT_NAT 处理** (`processInputNat`)
   - 检查入站NAT策略
   - 处理静态NAT配置
   - 计算流出端口
   - 生成NAT配置命令

2. **INPUT_POLICY 处理** (`processInputPolicy`)
   - 检查入站安全策略
   - 匹配现有策略或生成新策略
   - 处理策略冲突（Deny策略）
   - 生成安全策略配置命令

3. **OUTPUT_POLICY 处理** (`processOutputPolicy`)
   - 检查出站安全策略
   - 确保双向策略一致性
   - 生成出站策略配置命令

4. **OUTPUT_NAT 处理** (`processOutputNat`)
   - 检查出站NAT策略
   - 处理动态NAT配置
   - 生成SNAT配置命令

**策略验证机制**:
- **FlyConfig**: 在仿真环境中验证生成的配置
- **MeetStatus**: 检查策略是否满足意图要求
- **冲突检测**: 自动检测和报告策略冲突

**使用示例**:
```go
// 创建策略意图（用于生成新策略）
intent := &policy.Intent{
    PolicyEntry:  *policyEntry,
    Snat:         "interface",
    TicketNumber: "TICKET-001",
    Area:         "DMZ",
}

// 执行策略模板生成（生成新的安全策略配置）
tp := nodeMap.MakeTemplates(intent, ctx)
if tp != nil {
    // 处理生成结果
    results := tp.Results
    // 执行配置下发
    Execute(results, deviceList, taskId)
}
```

**策略命名配置示例**:
```yaml
# 不同客户的策略命名习惯配置
devices:
  - file_path: "firewall_config.txt"
    mode: "SecPath"
    metadata:
      # 客户A的命名习惯：GL4F-policy0001
      policy_name_template: "GL4F-policy{SEQ:id:4:1:1:MAIN}"
      
      # 客户B的命名习惯：JiS_DMZ_001
      policy_name_template: "JiS_DMZ_{SEQ:id:3:1:1:MAIN}"
      
      # 客户C的命名习惯：iboc_policy_20250101_01
      policy_name_template: "iboc_policy_{DATE:date:YYYYMMDD}_{SEQ:id:2:1:1:MAIN}"
      
      # 配置风格：启用对象风格
      securitypolicy.object_style: "true"
      securitypolicy.source_object: "true"
      securitypolicy.destination_object: "true"
      securitypolicy.service_object: "true"
      reuse_policy: "true"
```

**网络遍历示例**:
```go
// 创建遍历处理器
traverseProcess := &TraverseProcess{
    Intent:       intent,
    IPFamily:     network.IPv4,
    NodeMap:      nodeMap,
    Vrf:          "default",
    TraverseOnly: false,
    Results:      &TraverseResult{},
    Vertices:     make(map[interface{}]graph.Vertex),
}

// 执行网络遍历
traverseProcess.Traverse(ctx)

// 处理遍历结果
for _, item := range traverseProcess.Results.Items {
    fmt.Printf("节点: %s, 路径: %s\n", item.Node.Name(), item.Node.(*TraverseNode).Path)
    
    // 获取匹配和生成的CLI命令
    matched, generated := traverseProcess.Results.GetTraverseResult(item.Node.CmdIp())
    fmt.Printf("匹配策略: %v\n", matched)
    fmt.Printf("生成配置: %v\n", generated)
}
```

**策略处理示例**:
```go
// 创建防火墙处理器
firewallProcess := NewFirewallProcess(firewallNode, intent)

// 执行四个阶段的策略处理
translateTo, cmdList, additionCli, err := firewallProcess.MakeTemplates(
    ctx, intent, inPort, vrf, false)

if err.NotNil() {
    // 处理错误
    switch err.GetMark() {
    case model.ConfigConflict:
        // 配置冲突处理
    case model.PolicyDeny:
        // 策略拒绝处理
    case model.SimylationVerificationFailed:
        // 仿真验证失败处理
    }
}

// 处理生成的配置命令
for _, cmd := range cmdList {
    // 执行配置命令
}
```

### 3. Policies - 策略查询与匹配

**位置**: `pkg/nodemap/policy.go`

**功能**: 根据指定的匹配条件**查询和匹配**网络中现有的策略

**主要用途**:
- **策略查询**: 根据条件查询现有的安全策略
- **策略匹配**: 灵活匹配符合条件的安全策略
- **策略分析**: 分析现有策略的配置和影响
- **策略审计**: 进行策略合规性检查和审计

**支持的匹配器**:
- **AddressMatcher**: 地址匹配（源地址/目标地址）
- **ActionMatcher**: 动作匹配（permit/deny/reject等）
- **ServiceMatcher**: 服务匹配（协议/端口）
- **NameMatcher**: 策略名称匹配
- **CliMatcher**: CLI模式匹配
- **CompositeMatcher**: 复合匹配器

**匹配策略**:
- `StrategyOverlap`: 重叠匹配
- `StrategyContains`: 包含匹配
- `StrategyContainedBy`: 被包含匹配
- `StrategyExactMatch`: 精确匹配
- `StrategyThreshold`: 阈值匹配
- `StrategyOverlapIgnoreAny`: 重叠匹配忽略Any

**使用示例**:
```go
// 创建地址匹配器（用于查询现有策略）
srcMatcher := &nodemap.AddressMatcher{
    Address:  srcNetwork,
    IsSource: true,
    Strategy: nodemap.StrategyOverlap,
}

// 创建动作匹配器
actionMatcher := nodemap.ActionMatcher{
    Action: firewall.POLICY_PERMIT,
}

// 执行策略查询（查询和匹配现有策略）
matchedPolicies := nodeMap.Policies("action-id", srcMatcher, actionMatcher)

// 处理查询结果
for device, policies := range matchedPolicies {
    fmt.Printf("设备 %s 匹配的策略数量: %d\n", device, len(policies))
    for _, policy := range policies {
        fmt.Printf("策略: %s, 匹配类型: %s\n", 
            policy.Policy.Name(), policy.MatchType)
    }
}
```

## 设备适配器

### 防火墙设备适配器

系统支持多种防火墙设备的适配器，每个适配器负责：
- 设备配置解析
- 策略语法转换
- 配置命令生成
- 设备状态管理

**核心处理流程**:
每个防火墙设备都实现了 `FirewallTemplates` 接口，提供以下方法：
- `MakeInputPolicyCli()`: 生成入站策略配置
- `MakeOutputPolicyCli()`: 生成出站策略配置
- `MakeStaticNatCli()`: 生成静态NAT配置
- `MakeDynamicNatCli()`: 生成动态NAT配置
- `FlyObjectToFlattenCli()`: 将对象转换为CLI命令

**支持的防火墙类型**:
```go
// 在 factory.go 中定义
switch baseInfo.Type {
case terminalmode.ASA:
    return ASA.NewASAAdapter(baseInfo, dc.Config)
case terminalmode.SRX:
    return SRX.NewSRXAdapter(baseInfo, dc.Config)
case terminalmode.SecPath:
    return SECPATH.NewSecPathAdapter(baseInfo, dc.Config)
case terminalmode.F5:
    return F5.NewF5Adapter(baseInfo, dc.Config)
case terminalmode.FortiGate:
    return FortiGate.NewFortiAdapter(baseInfo, dc.Config)
case terminalmode.Dptech:
    return DP.NewDptechAdapter(baseInfo, dc.Config)
case terminalmode.HuaWei:
    return USG.NewUsgAdapter(baseInfo, dc.Config)
}
```

### 负载均衡设备适配器

支持F5等负载均衡设备的配置管理：
- 虚拟服务器配置
- 健康检查策略
- 会话保持配置
- 负载均衡算法

## 配置管理

### 设备配置

```yaml
devices:
  - host: "192.168.1.1"
    username: "admin"
    password: "password"
    mode: "USG"
    port: 22
    metadata:
      securitypolicy.object_style: "true"
      securitypolicy.source_object: "true"
      securitypolicy.destination_object: "true"
      securitypolicy.service_object: "true"
```

### 策略配置

```yaml
policy:
  source: "192.168.1.0/24"
  destination: "10.0.0.0/8"
  service:
    protocol: "tcp"
    port: "80"
  ticketNumber: "TICKET-001"
  area: "DMZ"
  snat: "interface"
```

### 策略命名与配置风格定制

系统支持通过YAML配置定制策略的命名习惯和配置风格，确保生成的策略符合客户的安全运维规范：

#### 1. 策略命名模板

**策略名称模板**:
```yaml
metadata:
  policy_name_template: "GL4F-policy{SEQ:id:4:1:1:MAIN}"
  # 或
  policy_name_template: "JiS_DMZ_{SEQ:id:3:1:1:MAIN}"
  # 或
  policy_name_template: "iboc_policy_{DATE:date:YYYYMMDD}_{SEQ:id:2:1:1:MAIN}"
```

**服务对象名称模板**:
```yaml
metadata:
  service_object_name_template: |
    {policy_name}_{protocol}{if:exist:compact_port=="true"}_{compact_port}{endif}
```

**网络对象名称模板**:
```yaml
metadata:
  network_object_name_template: |
    {if:exist:single_rule=="true"}DMZ_{ip}
    {else}
      {if:exist:object_name=="true"}
          {object_name}
      {else}
        {if:exist:policy_name=="true"}
          {policy_name}{if:exist:is_source=="true"}_src_addr{else}_dst_addr{endif}
        {endif}	
      {endif}
    {endif}
```

#### 2. 配置风格控制

**对象风格配置**:
```yaml
metadata:
  securitypolicy.object_style: "true"      # 启用对象风格
  securitypolicy.source_object: "true"     # 启用源地址对象
  securitypolicy.destination_object: "true" # 启用目标地址对象
  securitypolicy.service_object: "true"    # 启用服务对象
  reuse_policy: "true"                     # 启用策略复用
```

**NAT策略配置**:
```yaml
metadata:
  natpolicy.snat.object_style: "true"      # SNAT对象风格
  natpolicy.snat.source_object: "false"    # SNAT源地址对象
  natpolicy.snat.destination_object: "false" # SNAT目标地址对象
  natpolicy.snat.service_object: "true"    # SNAT服务对象
```

#### 3. 模板变量说明

**序列号变量**:
- `{SEQ:id:4:1:1:MAIN}`: 4位数字序列号，从1开始，步长1，主序列
- `{SEQ:id:3:1:1:MAIN}`: 3位数字序列号，从1开始，步长1，主序列
- `{SEQ:id:4:2000:1:MAIN}`: 4位数字序列号，从2000开始，步长1，主序列

**日期变量**:
- `{DATE:date:YYYYMMDD}`: 当前日期，格式为YYYYMMDD

**条件变量**:
- `{if:exist:compact_port=="true"}`: 条件判断，如果compact_port存在且为true
- `{if:exist:is_source=="true"}`: 条件判断，如果是源地址
- `{if:exist:single_rule=="true"}`: 条件判断，如果是单规则

**引用变量**:
- `{policy_name}`: 引用策略名称
- `{protocol}`: 引用协议名称
- `{ip}`: 引用IP地址
- `{object_name}`: 引用对象名称

## 使用示例

### 完整工作流程示例

```go
package main

import (
    "context"
    "github.com/influxdata/telegraf/controller/pkg/nodemap"
    "github.com/influxdata/telegraf/controller/pkg/nodemap/config"
    "github.com/netxops/utils/network"
    "github.com/netxops/utils/policy"
    "github.com/netxops/utils/service"
)

func main() {
    // 1. 加载设备配置
    deviceConfigs := []config.DeviceConfig{
        // ... 设备配置
    }
    
    // 2. 创建网络拓扑
    nodeMap, ctx := nodemap.NewNodeMapFromNetwork(
        "test-network", 
        deviceConfigs, 
        false, 
        1, 
        nil,
    )
    
    // 3. 创建策略意图（用于生成新策略）
    pe := policy.NewPolicyEntry()
    src, _ := network.NewNetworkGroupFromString("192.168.1.0/24")
    dst, _ := network.NewNetworkGroupFromString("10.0.0.0/8")
    svs, _ := service.NewServiceWithL4("tcp", "", "80")
    pe.AddSrc(src)
    pe.AddDst(dst)
    pe.AddService(svs)
    
    intent := &policy.Intent{
        PolicyEntry:  *pe,
        Snat:         "interface",
        TicketNumber: "TICKET-001",
        Area:         "DMZ",
    }
    
    // 4. 执行策略模板生成（生成新的安全策略配置）
    tp := nodeMap.MakeTemplates(intent, ctx)
    if tp != nil {
        // 5. 执行配置下发
        nodemap.Execute(tp.Results, deviceConfigs, 1)
    }
    
    // 6. 策略查询示例（查询现有策略）
    srcMatcher := &nodemap.AddressMatcher{
        Address:  src,
        IsSource: true,
        Strategy: nodemap.StrategyOverlap,
    }
    
    matchedPolicies := nodeMap.Policies("query-001", srcMatcher)
    for device, policies := range matchedPolicies {
        fmt.Printf("设备 %s 匹配的策略: %d\n", device, len(policies))
    }
}
```

## 错误处理

系统定义了多种错误类型：

```go
const (
    ConfigConflict               = "配置冲突"
    MissRoute                    = "路由缺失"
    SimylationVerificationFailed = "仿真验证失败"
    PolicyDeny                   = "Deny策略"
    RouteLoop                    = "路由环路"
    RouteQuery                   = "路由查询失败"
    SrcNodePoositionErr          = "源节点定位失败"
    NextHop_Empty                = "下一跳路由为空"
    Not_Support_Multi_Route      = "不支持多路由"
)
```

### 网络遍历错误处理

在网络遍历过程中，系统会进行详细的错误检测和处理：

#### 1. 源节点定位失败
```go
// 在 Traverse 方法中
ok, srcNode, portNameOrMsg = tp.NodeMap.LocateNode(srcNetworkList, dstNetworkList, tp.Intent.InputNode, tp.Vrf, tp.Gateway, tp.Area)
if !ok {
    tp.Results.err = model.NewProcessErr(portNameOrMsg, model.SrcNodePoositionErr)
    return
}
```

#### 2. 路由查询失败
```go
// 在 RunL3Route 方法中
ok, hopTable, _, _ := tn.Node.IpRouteCheck(*dstNetworkList, tn.InPort.Name(), tn.InVrf, tn.IPFamily)
if !ok {
    errStr := fmt.Sprintf("路由查询失败: 节点=%s, 入接口=%s, 意图=%s", tn.Node.Name(), tn.InPort.Name(), tn.Intent.String())
    return model.NewProcessErr(errStr, model.RouteQuery)
}
```

#### 3. 路由环路检测
```go
// 在 Run 方法中
if tn.IsLoop() {
    errStr := fmt.Sprintf("%s 在路径中形成循环: {%s} 目标: {%s}", tn.Node.Name(), tn.Path, tn.Intent.Dst())
    processErr = model.NewProcessErr(errStr, model.RouteLoop)
    tn.Process.Results.err = processErr
    return processErr
}
```

#### 4. 下一跳路由问题
```go
// 在 RunL3Route 方法中
if len(hopTable.Column("connected").List().Distinct()) == 0 {
    errStr := fmt.Sprintf("下一跳表为空: 目标网络=%v, 入接口=%s, VRF=%s", dstNetworkList, tn.InPort.Name(), tn.InVrf)
    return model.NewProcessErr(errStr, model.NextHop_Empty)
} else if len(hopTable.Column("connected").List().Distinct()) > 1 {
    errStr := fmt.Sprintf("不支持多路由匹配: 连接=%v", hopTable.Column("connected").List())
    return model.NewProcessErr(errStr, model.Not_Support_Multi_Route)
}
```

### 策略处理错误处理

在防火墙策略处理过程中，系统会进行详细的错误检测和处理：

#### 1. 配置冲突检测
```go
// 在 processInputNat 和 processOutputNat 中
if result.Action() == int(NAT_MATCHED) {
    errStr := fmt.Sprintf("nat matched, but not meet intent, Rule:[%s]", result.(*NatMatchResult).Rule().Cli())
    return nil, nil, nil, nil, model.NewProcessErr(errStr, model.ConfigConflict)
}
```

#### 2. 策略拒绝处理
```go
// 在 processInputPolicy 和 processOutputPolicy 中
case result.Action() == int(POLICY_DENY):
    if !force {
        return nil, nil, nil, model.NewProcessErr(fmt.Sprintf("POLICY Deny, Rule:[%s]", result.(*PolicyMatchResult).Rule().Cli()), model.PolicyDeny)
    }
```

#### 3. 仿真验证失败
```go
// 在所有策略生成后都会进行仿真验证
node.FlyConfig(flyObjects)
resultFly := node.InputPolicy(translateTo, inPort, outPort)
if resultFly.Action() != int(POLICY_PERMIT) {
    errStr := fmt.Sprintf("fly config failed, TranslateTo:[%s]", translateTo.String())
    return nil, nil, nil, model.NewProcessErr(errStr, model.SimylationVerificationFailed)
}
```

## 性能优化

### 进度跟踪
系统支持长时间操作的进度跟踪：

```go
func (nm *NodeMap) progressCounter(key string, count int, nodeCount int) error {
    progress := int64(float64(count) / float64(nodeCount) * 100)
    if err := global.Redis.Set(context.Background(), key, progress, 6*time.Hour).Err(); err != nil {
        return err
    }
    nm.logger.Info(fmt.Sprintf("l3 node map process progress %d%s", progress, "%"))
    return nil
}
```

### 并发处理
- 支持多设备并发配置下发
- 异步策略查询和匹配
- 分布式进度跟踪

## 扩展性

### 添加新设备支持
1. 实现设备适配器接口
2. 在工厂中注册新设备类型
3. 添加设备特定的策略模板

### 自定义匹配器
实现 `PolicyMatcher` 接口：

```go
type CustomMatcher struct {
    // 自定义匹配逻辑
}

func (cm *CustomMatcher) Match(policy firewall.FirewallPolicy) MatchResult {
    // 实现匹配逻辑
    return MatchResult{
        Matched: true,
        // ... 其他字段
    }
}
```

### 自定义命名模板
系统支持通过YAML配置自定义命名模板，适应不同客户的运维习惯：

```yaml
metadata:
  # 自定义策略命名模板
  policy_name_template: "{VAR:SYSTEM}_{VAR:APP}_policy{SEQ:id:4:1:1:MAIN}"
  
  # 自定义服务对象命名模板
  service_object_name_template: |
    {policy_name}_{protocol}{if:exist:compact_port=="true"}_{compact_port}{endif}
  
  # 自定义网络对象命名模板
  network_object_name_template: |
    {if:exist:single_rule=="true"}{VAR:AREA}_{ip}
    {else}
      {if:exist:object_name=="true"}
          {object_name}
      {else}
        {policy_name}{if:exist:is_source=="true"}_src_addr{else}_dst_addr{endif}
      {endif}
    {endif}
```

**支持的模板变量类型**:
- **序列号变量**: `{SEQ:id:位数:起始值:步长:序列类型}`
- **日期变量**: `{DATE:date:格式}`
- **条件变量**: `{if:exist:条件}...{endif}`
- **引用变量**: `{policy_name}`, `{protocol}`, `{ip}`
- **自定义变量**: `{VAR:变量名}`

## 依赖项

- `github.com/netxops/utils`: 工具库
- `github.com/netxops/utils/network`: 网络工具
- `github.com/netxops/utils/policy`: 策略工具
- `github.com/netxops/utils/graph`: 图算法
- `go.uber.org/zap`: 日志库
- `github.com/redis/go-redis/v9`: Redis客户端

## 许可证

本项目采用 MIT 许可证。

## 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目。

## 联系方式

如有问题或建议，请联系项目维护者。

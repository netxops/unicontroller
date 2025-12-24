package nodemap

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/model"

	"github.com/influxdata/telegraf/controller/global"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/lb"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/processor"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"github.com/netxops/log"

	"strings"

	"github.com/netxops/utils/graph"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/tools"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type TraverseResult struct {
	Items []*TraverseResultItem
	err   model.ProcessErr
}

func (tr *TraverseResult) Execute(session api.NodeSession) {
	for _, item := range tr.Items {
		session.BatchRun(item.CmdListList, true)
	}
}

type TraverseResultItem struct {
	Node        api.Node
	StepProcess *processor.NodeProcessor
	CmdListList []interface{}
	AdditionCli []string
	State       []string
	LBResult    lb.LBProcessResult
}

func (tr *TraverseResult) GetErr() model.ProcessErr {
	return tr.err
}

func (tr *TraverseResult) NodeList() []api.Node {
	nodeList := []api.Node{}

	for _, item := range tr.Items {
		nodeList = append(nodeList, item.Node)
	}

	return nodeList
}

func (tr *TraverseResult) GetTraverseResult(nodeIp string) (matched []string, generated []string) {

	for _, item := range tr.Items {
		if item.Node.CmdIp() == nodeIp {
			matched = item.MatchedCli()
			generated = item.GenerateCli()

			return
		}
	}

	return
}

func (ti *TraverseResultItem) Execute(deviceList []*config.DeviceConfig, task_id uint, screen chan string) (global.CmdExecuteStatusColor, string, string, error) {
	logger := log.NewLogger(nil, true)
	ip := ti.Node.CmdIp()
	logger.Info("开始执行命令推送", zap.Any("Ip", ip), zap.Any("Cli", ti.GenerateCli()))

	for _, dc := range deviceList {
		if ip == dc.Host {
			logger.Info("在目标设备上执行命令", zap.Any("Ip", dc.Host), zap.Any("Name", ti.Node.Name()))
			adapter := NewAdapter(dc)

			// 在某一台防火墙设备上执行配置推送
			adapter.AttachChannel(screen)
			cmdList, err := adapter.BatchConfig(ti.CmdListList, ti.AdditionCli)
			if err != nil {
				panic(err)
			}

			// color: 显示当前设备推送配置的亮灯状态，GREEN、YELLOW(表示必须执行的命令都成功了，但是部分选命令执行出错)、RED(表示有必须命名执行出错)
			color := cmdList.(command.CmdExecuteStatus).Color()
			beforeCmd := cmdList.(command.CmdExecuteStatus).Cmd("before")
			if beforeCmd == nil {
				panic("get before command failed")
			}
			afterCmd := cmdList.(command.CmdExecuteStatus).Cmd("after")
			if afterCmd == nil {
				panic("get after command failed")
			}

			logger.Info("执行结果", zap.Any("Color", color.String()), zap.Any("Error", cmdList.(command.CmdExecuteStatus).Error()))

			return color, string(beforeCmd.Msg()), string(afterCmd.Msg()), cmdList.(command.CmdExecuteStatus).Error()
		}
	}
	logger.Error("执行失败，未找到对应设备", zap.Any("Ip", ip))
	panic("unknown error")
}

func (ti *TraverseResultItem) MatchedCli() []string {
	var result []string
	for it := ti.StepProcess.Iterator(); it.HasNext(); {
		_, step := it.Next()
		if step.GetCli() == "" {
			result = append(result, strings.TrimSpace(step.GetResult().Cli()))
		}
	}

	return result
}

func (ti *TraverseResultItem) GenerateCli() []string {
	result := []string{}
	for it := ti.StepProcess.Iterator(); it.HasNext(); {
		_, step := it.Next()
		if step.GetCli() != "" {
			result = append(result, strings.TrimSpace(step.GetCli()))
		}
	}
	return result
}

func (ti *TraverseResultItem) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		StepProcess *processor.NodeProcessor
	}{
		StepProcess: ti.StepProcess,
	})
}

func (ti *TraverseResultItem) UnmarshalJSON(b []byte) error {
	type ts struct {
		StepProcess *processor.NodeProcessor
	}

	tsMod := &ts{}
	if err := json.Unmarshal(b, tsMod); err != nil {
		return err
	}

	ti.StepProcess = tsMod.StepProcess
	return nil
}

type TraverseProcess struct {
	graph.SimpleGraph
	Intent         *policy.Intent
	IPFamily       network.IPFamily
	NodeMap        *NodeMap
	Vrf            string
	Gateway        string
	Area           string
	TraverseOnly   bool
	FuncationNodes []api.Node
	Results        *TraverseResult
	logger         *zap.Logger
	Vertices       map[interface{}]graph.Vertex
	RouteTracer    *RouteTracer        // 添加路由跟踪器
	Warnings       []model.WarningInfo // 警告信息列表
	// directed bool
	// 通过fn来创建新Vetex节点
	// fn func(key interface{}) Vertex
}

// AddWarning 添加警告信息
func (tp *TraverseProcess) AddWarning(warning model.WarningInfo) {
	tp.Warnings = append(tp.Warnings, warning)
}

func (tp *TraverseProcess) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Intent  string
		Vrf     string
		Area    string
		Results *TraverseResult
	}{
		Intent:  tp.Intent.String(),
		Vrf:     tp.Vrf,
		Area:    tp.Area,
		Results: tp.Results,
	})
}

func (tp *TraverseProcess) AddResult(node api.Node, stepProcess *processor.NodeProcessor, cmdListList []interface{}, addtionCli []string) {
	tp.Results.Items = append(
		tp.Results.Items,
		&TraverseResultItem{
			Node:        node,
			StepProcess: stepProcess,
			CmdListList: cmdListList,
			AdditionCli: addtionCli,
		})
}

func (tp *TraverseProcess) AddF5Result(node api.Node, stepProcess *processor.NodeProcessor, result lb.LBProcessResult) {
	tp.Results.Items = append(
		tp.Results.Items,
		&TraverseResultItem{
			Node:        node,
			StepProcess: stepProcess,
			LBResult:    result,
		})
}

func (tp *TraverseProcess) WithLogger(logger *zap.Logger) {
	tp.logger = logger
}

func (tp *TraverseProcess) PushFunctionNode(n api.Node) {
	for _, fn := range tp.FuncationNodes {
		if fn.FlattenName() == n.FlattenName() {
			return
		}
	}

	tp.FuncationNodes = append(tp.FuncationNodes, n)
}

func (tp *TraverseProcess) GetFunctionNode(name string) api.Node {
	for _, fn := range tp.FuncationNodes {
		if fn.Name() == name || fn.FlattenName() == name {
			return fn
		}
	}

	return nil
}

func (tp *TraverseProcess) WithIntent(intent *policy.Intent) *TraverseProcess {
	// if tp.Intent == nil {
	tp.Intent = intent
	// }
	return tp
}

// NodeMap路由和策略匹配的入口
func (tp *TraverseProcess) Traverse(ctx context.Context) {
	tp.logger.Info("1. 进入Traverse入口")

	// 记录Traverse开始事件
	if tp.RouteTracer != nil {
		tp.RouteTracer.LogEvent(EventTraverseStart, map[string]interface{}{
			"src": tp.Intent.Src().String(),
			"dst": tp.Intent.Dst().String(),
		})
	}

	src := tp.Intent.Src()

	var ok bool
	var srcNode api.Node
	var portNameOrMsg string

	var srcNetworkList *network.NetworkList
	if tp.IPFamily == network.IPv4 {
		srcNetworkList = src.IPv4()
	} else {
		srcNetworkList = src.IPv6()
	}

	var dstNetworkList *network.NetworkList
	if tp.IPFamily == network.IPv4 {
		dstNetworkList = tp.Intent.Dst().IPv4()
	} else {
		dstNetworkList = tp.Intent.Dst().IPv6()
	}

	tp.logger.Info("2. 开始定位源节点")

	// 记录LocateNode开始事件
	if tp.RouteTracer != nil {
		tp.RouteTracer.LogEvent(EventLocateNodeStart, map[string]interface{}{
			"src_network": srcNetworkList.String(),
			"vrf":         tp.Vrf,
			"area":        tp.Area,
			"gateway":     tp.Gateway,
		})
	}

	ok, srcNode, portNameOrMsg = tp.NodeMap.Locator().Locate(srcNetworkList, dstNetworkList, tp.Intent.InputNode, tp.Vrf, tp.Gateway, tp.Area)

	// 记录LocateNode结束事件
	if tp.RouteTracer != nil {
		if ok {
			tp.RouteTracer.LogEvent(EventLocateNodeEnd, map[string]interface{}{
				"success": true,
				"node":    srcNode.Name(),
				"port":    portNameOrMsg,
			})
			// 记录源节点信息
			tp.RouteTracer.LogSourceNode(portNameOrMsg, srcNode.Name())

			// 记录源节点定位决策
			criteria := map[string]interface{}{
				"src_network": srcNetworkList.String(),
				"vrf":         tp.Vrf,
				"area":        tp.Area,
				"gateway":     tp.Gateway,
				"input_node":  tp.Intent.InputNode,
			}
			tp.RouteTracer.LogSourceNodeLocation(srcNode.Name(), portNameOrMsg, tp.Vrf, criteria, "success", "成功定位源节点")
		} else {
			tp.RouteTracer.LogEvent(EventLocateNodeEnd, map[string]interface{}{
				"success": false,
				"error":   portNameOrMsg,
			})

			// 记录源节点定位失败决策（带详细失败原因分析）
			criteria := map[string]interface{}{
				"src_network": srcNetworkList.String(),
				"vrf":         tp.Vrf,
				"area":        tp.Area,
				"gateway":     tp.Gateway,
				"input_node":  tp.Intent.InputNode,
			}
			tp.RouteTracer.LogSourceNodeLocationFailure(portNameOrMsg, criteria)
		}
	}

	if !ok {
		tp.Results.err = model.NewProcessErr(portNameOrMsg, model.SrcNodePoositionErr)
		return
	}
	tp.logger.Info("3. 源节点定位完成， 源节点:", zap.Any("node", srcNode.Name()))

	port := srcNode.GetPortByNameOrAlias(portNameOrMsg)
	tp.logger.Info("4. 源端口:", zap.Any("port", port))
	tn := NewTraverseNode(tp.NodeMap,
		srcNode,
		tp.Intent.Copy().(*policy.Intent),
		port.Vrf(),
		port,
		tp.IPFamily,
		"",
		tp,
		tp.TraverseOnly)
	tp.AddVertex(tn)

	tn.WithLogger(tp.logger)

	tp.logger.Info("5. 开始进行路由查询")
	tn.Run(tp.TraverseOnly, ctx)

	// 记录Traverse结束事件
	if tp.RouteTracer != nil {
		tp.RouteTracer.LogEvent(EventTraverseEnd, map[string]interface{}{
			"result": tp.Results,
		})
	}
}

type TraverseNode struct {
	nm     *NodeMap
	Node   api.Node
	Intent *policy.Intent
	InVrf  string
	InPort api.Port
	// Next     []*TraverseNode
	Neighbor map[interface{}]graph.Vertex
	IPFamily network.IPFamily
	Path     string
	Ok       bool
	Info     string
	Process  *TraverseProcess
	// Session      api.NodeSession
	TraverseOnly bool
	// CmdListList      []interface{}
	logger *zap.Logger
}

func (tn *TraverseNode) MarshalJSON() ([]byte, error) {
	var neighbors []string
	for _, v := range tn.Neighbor {
		neighbors = append(neighbors, v.(*TraverseNode).Node.Name())
	}
	return json.Marshal(&struct {
		Neighbors []string
		// Process   *TraverseProcess
		Path string
	}{
		Neighbors: neighbors,
		// Process:   tn.Process,
		Path: tn.Path,
	})
}

func NewTraverseNode(nm *NodeMap,
	n api.Node,
	intent *policy.Intent,
	inVrf string,
	inPort api.Port,
	ipFamily network.IPFamily,
	path string,
	process *TraverseProcess,
	traverseOnly bool) *TraverseNode {
	return &TraverseNode{
		nm:           nm,
		Node:         n,
		Intent:       intent,
		InVrf:        inVrf,
		InPort:       inPort,
		IPFamily:     ipFamily,
		Path:         path,
		Neighbor:     map[interface{}]graph.Vertex{},
		Process:      process,
		TraverseOnly: traverseOnly,
	}
}

func (tn *TraverseNode) WithLogger(logger *zap.Logger) {
	tn.logger = logger
}

func (tn *TraverseNode) Flatten() []string {
	var data []string
	if len(tn.Neighbor) > 0 {
		// for _, child := range tn.Next{
		for _, child := range tn.Neighbor {
			// for _, childFlatten := range child.Flatten() {
			data = append(data, child.(*TraverseNode).Flatten()...)
		}

		for index, _ := range data {
			data[index] = tn.Node.Name() + "->" + data[index]
		}
	} else {
		data = append(data, tn.Node.Name())
	}

	return data
}

func (tn *TraverseNode) IsLoop() bool {
	var pathList []string

	if tn.Path != "" {
		pathList = append(pathList, strings.Split(tn.Path, "|")...)
	}

	path := tn.InVrf + ":" + tn.Node.Name()
	if !tools.Contains(pathList, path) {
		// 节点不在路径中，不是循环
		return false
	}

	// 节点已经在路径中，需要判断是否是真正的路由循环
	// 对于防火墙和负载均衡设备，允许在设备内部处理阶段的第二次路由匹配
	nodeType := tn.Node.NodeType()
	isFunctionNode := nodeType == api.FIREWALL || nodeType == api.LB

	if isFunctionNode {
		// 对于防火墙和负载均衡设备，检查是否是设备内部的路由匹配
		// 如果节点已经在路径中出现过，且是功能节点，可能是设备内部的第二次路由匹配
		// 这种情况下，需要检查是否是真正的循环（即路径中出现了两次相同的节点，且不是设备内部处理）

		// 统计路径中该节点出现的次数
		occurrenceCount := 0
		for _, p := range pathList {
			if p == path {
				occurrenceCount++
			}
		}

		// 如果节点只出现一次，说明这是第一次进入设备，不是循环
		if occurrenceCount == 1 {
			return false
		}

		// 如果节点出现多次，需要进一步判断：
		// 1. 检查是否是设备内部处理阶段的第二次路由匹配
		// 2. 通过检查 Vertices 来判断是否是真正的循环
		// 如果节点已经在 Vertices 中，说明已经处理过，这是真正的循环
		if _, exists := tn.Process.Vertices[tn.Key()]; exists {
			// 节点已经在 Vertices 中，且路径中出现多次，这是真正的循环
			return true
		}

		// 节点在路径中出现多次，但不在 Vertices 中，可能是设备内部的第二次路由匹配
		// 允许继续，不判定为循环
		return false
	}

	// 对于非功能节点（如路由器），如果节点已经在路径中，就是循环
	return true
}

func (tn *TraverseNode) MarkFunctionNode(traverseOnly bool, ctx context.Context) (processErr model.ProcessErr) {
	fn := tn.Process.GetFunctionNode(tn.Node.Name())
	if fn == nil {
		// 记录功能节点检查决策
		if tn.Process.RouteTracer != nil {
			isFunctionNode := tn.Node.NodeType() == api.FIREWALL || tn.Node.NodeType() == api.LB
			nodeType := tn.Node.NodeType().String()
			result := "not_function_node"
			reason := "节点不是功能节点"

			if isFunctionNode {
				result = "function_node"
				reason = "节点是功能节点，执行策略仿真"
			}

			tn.Process.RouteTracer.LogFunctionNodeCheck(tn.Node.Name(), tn.InPort.Name(), tn.InVrf, isFunctionNode, nodeType, result, reason)
		}

		if !traverseOnly {
			var translateTo *policy.Intent
			var cmdList []interface{}
			var additionCli []string
			var f5Result lb.LBProcessResult
			switch tn.Node.NodeType() {
			case api.FIREWALL:
				firewallProcessor := firewall.NewFirewallProcess(tn.Node.(firewall.FirewallNode), tn.Intent)
				firewallProcessor.SetLogger(*tn.logger)
				// 设置 TraverseProcess 到 PolicyContext 以便 calculateOutPort 可以添加警告
				if policyCtx, ok := ctx.(*firewall.PolicyContext); ok {
					policyCtx.TraverseProcess = tn.Process
				}
				translateTo, cmdList, additionCli, processErr = firewallProcessor.MakeTemplates(ctx, tn.Intent, tn.InPort, tn.Node.GetVrf(tn.InVrf), traverseOnly)
				tn.Process.AddResult(tn.Node, &firewallProcessor.NodeProcessor, cmdList, additionCli)
				tn.Intent = translateTo
			case api.LB:
				lbProcessor := lb.NewF5Processor(tn.Node, tn.Intent)
				lbProcessor.SetLogger(*tn.logger)
				f5Result = lbProcessor.MakeTemplates(ctx, tn.Intent, tn.InPort, tn.Node.GetVrf(tn.InVrf), traverseOnly)
				tn.Process.AddF5Result(tn.Node, &lbProcessor.NodeProcessor, f5Result)
			}

			//*processor.(firewall.FirewallProcess).MakeTemplates(ctx, tn.Intent, tn.InPort, tn.Node.GetVrf(tn.InVrf), false)
			//translateTo, cmdListList, additionCli := processor.MakeTemplates(tn.Intent, tn.InPort, tn.Node.GetVrf(tn.InVrf), false)
			// tn.logger.Info("MarkFunctionNode", zap.Any("CmdListList", cmdListList))
			// cmdListList应该是HttpCmdList和CliCmdList所组成的集合
			//tn.Process.AddResult(tn.Node, processor, cmdList, additionCli)
		} else {
		}
	} else {
		// 记录功能节点检查决策（已处理过）
		if tn.Process.RouteTracer != nil {
			tn.Process.RouteTracer.LogFunctionNodeCheck(tn.Node.Name(), tn.InPort.Name(), tn.InVrf, true, "already_processed", "already_processed", "节点已经处理过")
		}
	}
	return
}

func (tn *TraverseNode) Run(traverseOnly bool, ctx context.Context) (processErr model.ProcessErr) {
	tn.logger.Info("开始执行 Run 方法",
		zap.String("节点", tn.Node.Name()),
		zap.String("路径", tn.Path),
		zap.Any("意图", tn.Intent),
		zap.Bool("仅遍历", traverseOnly))

	if tn.IsLoop() {
		// 将路由环路转换为警告
		loopPath := tn.Path
		nodesInLoop := []string{}
		// 从路径中提取节点
		pathParts := strings.Split(loopPath, "|")
		for _, part := range pathParts {
			if part != "" {
				nodesInLoop = append(nodesInLoop, part)
			}
		}

		warning := model.WarningInfo{
			Type:      model.WarningRouteLoop,
			Message:   fmt.Sprintf("%s 在路径中形成循环: {%s} 目标: {%s}", tn.Node.Name(), loopPath, tn.Intent.Dst()),
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"loop_path":           loopPath,
				"destination_network": tn.Intent.Dst().String(),
				"nodes_in_loop":       nodesInLoop,
				"node":                tn.Node.Name(),
				"in_port":             tn.InPort.Name(),
				"vrf":                 tn.InVrf,
			},
		}
		tn.Process.AddWarning(warning)
		tn.Ok = false
		tn.logger.Warn("检测到路由循环",
			zap.String("类型", warning.Type),
			zap.String("消息", warning.Message),
			zap.Any("详情", warning.Details))

		// 记录到 RouteTracer
		if tn.Process.RouteTracer != nil {
			tn.Process.RouteTracer.LogExit(ExitReasonRouteLoop, tn.Node.Name(), tn.InPort.Name(), tn.InVrf, false, warning.Message, warning.Details)
		}
		return model.ProcessErr{} // 返回空错误，因为已经转换为警告
	}

	if tn.Node.NodeType() == api.LB {
		tn.logger.Info("执行负载均衡器查询",
			zap.String("节点", tn.Node.Name()),
			zap.Any("目标网络", tn.Intent.Dst()),
			zap.String("入端口", tn.InPort.Name()),
			zap.String("路径", tn.Path))
		return tn.MarkFunctionNode(traverseOnly, ctx)
	} else {
		tn.logger.Info("执行路由查询",
			zap.String("节点", tn.Node.Name()),
			zap.Any("目标网络", tn.Intent.Dst()),
			zap.String("入端口", tn.InPort.Name()),
			zap.String("路径", tn.Path))

		processErr = tn.MarkFunctionNode(traverseOnly, ctx)
		if processErr.NotNil() {
			tn.logger.Error("标记功能节点失败",
				zap.String("描述", processErr.GetDesc()),
				zap.String("标记", processErr.GetMark()))
			tn.Process.Results.err = processErr
			return
		}

		tn.logger.Info("开始执行 L3 路由查询")
		processErr = tn.RunL3Route(traverseOnly, ctx)
		if processErr.NotNil() {
			tn.logger.Error("L3 路由查询失败",
				zap.String("描述", processErr.GetDesc()),
				zap.String("标记", processErr.GetMark()))
			tn.Process.Results.err = processErr
			return
		}
		tn.logger.Info("L3 路由查询完成")
	}

	tn.logger.Info("Run 方法执行完成",
		zap.String("节点", tn.Node.Name()),
		zap.String("路径", tn.Path),
		zap.Any("意图", tn.Intent))
	return
}

// func (tn *TraverseNode) RunL3Route(nodeMap *NodeMap, traverseOnly bool) (processErr model.ProcessErr) {
// 	// srcNetworkList := tn.Intent.Src().NetworkList(tn.IPFamily)
// 	dstNetworkList := tn.Intent.Dst().NetworkList(tn.IPFamily)
// 	if tn.IsLoop() {
// 		errStr := fmt.Sprintf("%s is in loop path:{%s} dst:{%s}", tn.Node.Name(), tn.Path, tn.Intent.Dst())
// 		return model.NewProcessErr(errStr, model.RouteLoop)
// 	}

// 	translateIntent := tn.Intent.Copy().(*policy.Intent)
// 	// func (node *Node) IpRouteCheck(netList network.NetworkList, inPort, vrf string, af network.IPFamily) (bool, string, []interface{}) {
// 	ok, hopTable, _ := tn.Node.IpRouteCheck(*dstNetworkList, tn.InPort.Name(), tn.InVrf, tn.IPFamily)
// 	if !ok {
// 		tn.Ok = false
// 		// tn.Info = hopIp
// 		errStr := fmt.Sprintf("路由查询失败，node=%s inPort=%s intent=%s", tn.Node.Name(), tn.InPort.Name(), tn.Intent.String())
// 		tn.logger.Error("路由查询失败", zap.Any("node", tn.Node), zap.Any("inPort", tn.InPort), zap.Any("intent", tn.Intent), zap.Any("route", tn.Node.Ipv4RouteTable(tn.InVrf)))
// 		return model.NewProcessErr(errStr, model.RouteQuery)
// 	}

// 	if len(hopTable.Column("connected").List().Distinct()) == 0 {
// 		errStr := fmt.Sprintf("Nexthop table is empty, DstNetWorkList:[%#v] InPort:[%s] InVrf[%s]", dstNetworkList, tn.InPort.Name(), tn.InVrf)
// 		return model.NewProcessErr(errStr, model.NextHop_Empty)
// 	} else if len(hopTable.Column("connected").List().Distinct()) > 1 {
// 		errStr := fmt.Sprintf("current not support multiple match route, HopTable(connected):[%#v]", hopTable.Column("connected").List())
// 		return model.NewProcessErr(errStr, model.Not_Support_Multi_Route)
// 	}

// 	tn.logger.Debug("路由查询结果", zap.Any("hop", hopTable))

// 	connectedList := hopTable.Column("connected").List().Distinct()
// 	if connectedList[0].(bool) {
// 		tn.Ok = true
// 		path := fmt.Sprintf("%s:%s", tn.InVrf, tn.Node.Name())
// 		tn.Path += "|" + path

// 		// fmt.Printf("End of Node, path: %s\n", tn.Path)
// 		tn.logger.Info("路由查询成功", zap.Any("Node", tn.Node.Name()), zap.Any("Path", tn.Path), zap.Any("Intent", tn.Intent), zap.Any("Hop", hopTable))
// 		return
// 	}

// 	for it := hopTable.Iterator(); it.HasNext(); {
// 		_, hopMap := it.Next()
// 		hopIp := hopMap["ip"].(string)
// 		outPortName := hopMap["interface"].(string)

// 		outPort := tn.Node.GetPort(outPortName)

// 		nextDeviceNode, nextInputPort := outPort.Connector().SelectNodeByIp(hopIp, outPort.Vrf())

// 		if nextDeviceNode != nil {
// 			path := fmt.Sprintf("%s:%s", tn.InVrf, tn.Node.Name())
// 			nextNode := NewTraverseNode(nextDeviceNode,
// 				translateIntent,
// 				nextInputPort.Vrf(),
// 				nextInputPort,
// 				tn.IPFamily,
// 				tn.Path+"|"+path,
// 				tn.Process,
// 				traverseOnly)
// 			nextNode.WithLogger(tn.logger)
// 			// tn.AddVertex()
// 			// tn.Neighbor[nextNode.Key()] = nextNode
// 			tn.Process.AddVertex(nextNode)
// 			tn.Process.AddEdge(tn.Key(), nextNode.Key())
// 			// tn.Next = append(tn.Next, nextNode)

// 			tn.logger.Info("匹配到下一跳", zap.Any("NextNode", nextDeviceNode.Name()), zap.Any("ThisNode", tn.Node.Name()))
// 			tn.logger.Info("下一跳信息", zap.Any("nextInputPort", nextInputPort.Name()))
// 			tn.logger.Info("下一跳信息", zap.Any("Intent", translateIntent))
// 		} else {
// 			// if hopMap["default_gw"].(bool) {
// 			// tn.logger.Info("匹配到默认路由")
// 			// fmt.Printf("route to outside hop:{%+v}\n", hopMap)
// 			// } else {
// 			if ok, _ := nodeMap.IsOutsidePort(tn.Node.Name(), hopMap["interface"].(string), tn.IPFamily); ok {
// 				tn.logger.Info("路由下一条为Outside", zap.Any("nextInterface", hopMap["interface"]), zap.Any("hopIp", hopIp), zap.Any("node", tn.Node.Name()), zap.Any("intent", translateIntent))
// 				return

// 			} else {
// 				// fmt.Println("next hop is outside of nodemap.", " intent: ", translateIntent)
// 				// func (nm *NodeMap) IsStubPort(node api.Node, port api.Port, ipType network.IPFamily) bool {
// 				if nodeMap.IsStubPort(tn.Node, outPort, tn.IPFamily) {
// 					tn.logger.Info("路由下一跳是Stub Port", zap.Any("nextInterface", hopMap["interface"]), zap.Any("hopIp", hopIp), zap.Any("node", tn.Node.Name()), zap.Any("intent", translateIntent))
// 				} else {
// 					tn.logger.Error("路由下一跳不在NodeMap中", zap.Any("nextInterface", hopMap["interface"]), zap.Any("hopIp", hopIp), zap.Any("node", tn.Node.Name()), zap.Any("intent", translateIntent))
// 					return model.NewProcessErr(fmt.Sprintf("路由下一跳不在NodeMap中，nextInterface=%s hopIp=%s node=%s", hopMap["interface"], hopIp, tn.Node.Name()), model.NextHop_Empty)
// 				}
// 				// panic("next hop is outside of nodemap")
// 			}
// 		}
// 		// }
// 	}

// 	tn.logger.Info("在下一级节点中进行路由查询")
// 	for it := tn.Iterator(); it.HasNext(); {
// 		_, nextNode := it.Next()
// 		processErr = nextNode.(*TraverseNode).Run(nodeMap, traverseOnly)
// 		if processErr.NotNil() {
// 			return
// 		}
// 	}
// 	return
// }

func (tn *TraverseNode) RunL3Route(traverseOnly bool, ctx context.Context) (processErr model.ProcessErr) {
	// 先更新路径，将当前节点添加到路径中（如果还没有添加）
	currentPathKey := fmt.Sprintf("%s:%s", tn.InVrf, tn.Node.Name())
	if tn.Path == "" {
		tn.Path = currentPathKey
	} else if !strings.Contains(tn.Path, currentPathKey) {
		tn.Path += "|" + currentPathKey
	}

	tn.logger.Info("开始路由查询",
		zap.String("当前节点", tn.Node.Name()),
		zap.String("经过路径", tn.Path))

	// 记录路由查询开始事件
	if tn.Process.RouteTracer != nil {
		tn.Process.RouteTracer.LogEvent(EventRouteQueryStart, map[string]interface{}{
			"node":        tn.Node.Name(),
			"in_port":     tn.InPort.Name(),
			"dst_network": tn.Intent.Dst().NetworkList(tn.IPFamily).String(),
			"vrf":         tn.InVrf,
		})
	}

	// 检查当前节点是否已经在路径中（使用 IsLoop 检查）
	if tn.IsLoop() {
		// 将路由环路转换为警告
		loopPath := tn.Path
		nodesInLoop := []string{}
		// 从路径中提取节点
		pathParts := strings.Split(loopPath, "|")
		for _, part := range pathParts {
			if part != "" {
				nodesInLoop = append(nodesInLoop, part)
			}
		}

		warning := model.WarningInfo{
			Type:      model.WarningRouteLoop,
			Message:   fmt.Sprintf("%s 在路径中形成循环: {%s} 目标: {%s}", tn.Node.Name(), loopPath, tn.Intent.Dst()),
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"loop_path":           loopPath,
				"destination_network": tn.Intent.Dst().String(),
				"nodes_in_loop":       nodesInLoop,
				"node":                tn.Node.Name(),
				"in_port":             tn.InPort.Name(),
				"vrf":                 tn.InVrf,
			},
		}
		tn.Process.AddWarning(warning)
		tn.Ok = false
		tn.logger.Warn("检测到路由循环",
			zap.String("类型", warning.Type),
			zap.String("消息", warning.Message),
			zap.Any("详情", warning.Details))

		// 记录到 RouteTracer
		if tn.Process.RouteTracer != nil {
			tn.Process.RouteTracer.LogExit(ExitReasonRouteLoop, tn.Node.Name(), tn.InPort.Name(), tn.InVrf, false, warning.Message, warning.Details)
		}
		return model.ProcessErr{} // 返回空错误，因为已经转换为警告
	}

	// 检查当前节点是否已经被访问过（使用 Vertices 检查）
	if _, exists := tn.Process.Vertices[tn.Key()]; exists {
		tn.logger.Info("节点已被访问，跳过处理以避免环路",
			zap.String("节点", tn.Node.Name()),
			zap.String("VRF", tn.InVrf))
		return
	}

	// 将当前节点添加到已访问的节点列表中
	tn.Process.AddVertex(tn)

	// 打印当前经过的路径
	tn.PrintCurrentPath()

	// if tn.IsLoop() {
	// 	errStr := fmt.Sprintf("检测到路由循环: 节点=%s, 路径=%s, 目标=%s", tn.Node.Name(), tn.Path, tn.Intent.Dst())
	// 	return model.NewProcessErr(errStr, model.RouteLoop)
	// }

	dstNetworkList := tn.Intent.Dst().NetworkList(tn.IPFamily)
	translateIntent := tn.Intent.Copy().(*policy.Intent)

	// 检查目标地址是否属于当前节点的任何接口网段（到达终点检测）
	// 如果目标地址属于本地接口网段，应该判断为到达终点，而不是继续路由查询
	// 遍历当前节点的所有端口，检查目标地址是否属于任何端口的网段
	for _, net := range dstNetworkList.List() {
		// 获取当前节点的所有端口
		var allPorts []api.Port
		if deviceNode, ok := tn.Node.(*node.DeviceNode); ok {
			allPorts = deviceNode.PortList()
		} else {
			// 如果不是 DeviceNode，尝试通过 NodeMap 获取
			if tn.nm != nil {
				// 使用 SelectPortListByNetwork 查找匹配的端口
				matchingPorts := tn.nm.SelectPortListByNetwork(net, tn.InVrf)
				if len(matchingPorts) > 0 {
					allPorts = matchingPorts
				}
			}
		}

		// 遍历所有端口，检查目标网络是否匹配
		for _, port := range allPorts {
			// 检查端口是否属于当前 VRF
			if !port.MatchVrfOrPeerVrf(tn.InVrf) {
				continue
			}
			// 检查目标网络是否匹配端口的网络
			if port.HitByNetwork(net) {
				// 找到匹配的端口，说明目标地址属于本地接口网段
				// 标记为直连路由/到达终点
				tn.Ok = true
				path := fmt.Sprintf("%s:%s", tn.InVrf, tn.Node.Name())
				if !strings.Contains(tn.Path, path) {
					tn.Path += "|" + path
				}

				tn.logger.Info("目标地址属于本地接口网段，判断为到达终点",
					zap.String("节点", tn.Node.Name()),
					zap.String("目标网络", net.String()),
					zap.String("匹配的接口", port.Name()),
					zap.String("路径", tn.Path))

				// 记录到 RouteTracer
				if tn.Process.RouteTracer != nil {
					tn.Process.RouteTracer.LogRouteHop(tn.InPort.Name(), tn.Node.Name(), port.Name())

					// 记录退出信息（到达终点）
					details := map[string]interface{}{
						"route_type":    "local_interface",
						"path":          tn.Path,
						"destination":   net.String(),
						"matching_port": port.Name(),
					}
					tn.Process.RouteTracer.LogExit(ExitReasonConnectedRoute, tn.Node.Name(), port.Name(), tn.InVrf, true, "目标地址属于本地接口网段", details)
				}
				return model.ProcessErr{} // 到达终点，返回
			}
		}
	}

	// 使用内部方法获取路由检查结果（包含警告信息）
	var routeResult *model.RouteCheckResult
	if deviceNode, ok := tn.Node.(*node.DeviceNode); ok {
		routeResult = deviceNode.IpRouteCheckInternal(*dstNetworkList, tn.InPort.Name(), tn.InVrf, tn.IPFamily)
	} else {
		// 如果不是 DeviceNode，使用旧的接口方法
		ok, hopTable, _, _ := tn.Node.IpRouteCheck(*dstNetworkList, tn.InPort.Name(), tn.InVrf, tn.IPFamily)
		if !ok {
			// 路由查询失败 - 转换为警告
			warning := model.WarningInfo{
				Type:      model.WarningRouteQueryFailed,
				Message:   fmt.Sprintf("路由查询失败: 节点=%s, 入接口=%s, 意图=%s", tn.Node.Name(), tn.InPort.Name(), tn.Intent.String()),
				Timestamp: time.Now(),
				Details: map[string]interface{}{
					"destination_network": dstNetworkList.String(),
					"in_port":             tn.InPort.Name(),
					"vrf":                 tn.InVrf,
					"node":                tn.Node.Name(),
				},
			}
			tn.Process.AddWarning(warning)
			tn.Ok = false
			tn.logger.Warn("路由查询失败",
				zap.String("类型", warning.Type),
				zap.String("消息", warning.Message),
				zap.Any("详情", warning.Details))

			if tn.Process.RouteTracer != nil {
				tn.Process.RouteTracer.LogExit(ExitReasonRouteQueryFailed, tn.Node.Name(), tn.InPort.Name(), tn.InVrf, false, warning.Message, warning.Details)
			}
			return model.ProcessErr{}
		}
		routeResult = &model.RouteCheckResult{
			Ok:       ok,
			HopTable: hopTable, // tools.Table 实现了 interface{}，可以直接赋值
			PortList: []string{},
		}
	}

	// 检查是否有警告（多路由匹配等）
	if routeResult.Warning != nil {
		tn.Process.AddWarning(*routeResult.Warning)
		tn.Ok = false
		tn.logger.Warn("路由检查警告",
			zap.String("类型", routeResult.Warning.Type),
			zap.String("消息", routeResult.Warning.Message),
			zap.Any("详情", routeResult.Warning.Details))

		if tn.Process.RouteTracer != nil {
			var exitReason ExitReason
			switch routeResult.Warning.Type {
			case model.WarningMultiRouteMatch:
				exitReason = ExitReasonMultiRoute
			case model.WarningMissRoute:
				exitReason = ExitReasonRouteQueryFailed
			default:
				exitReason = ExitReasonRouteQueryFailed
			}
			tn.Process.RouteTracer.LogExit(exitReason, tn.Node.Name(), tn.InPort.Name(), tn.InVrf, false, routeResult.Warning.Message, routeResult.Warning.Details)
		}
		return model.ProcessErr{}
	}

	// 类型断言 HopTable 为 *tools.Table
	var hopTable *tools.Table
	if routeResult.HopTable != nil {
		if ht, ok := routeResult.HopTable.(*tools.Table); ok {
			hopTable = ht
		}
	}
	ok := routeResult.Ok

	// 记录路由查询结束事件
	if tn.Process.RouteTracer != nil {
		if ok && hopTable != nil {
			tn.Process.RouteTracer.LogEvent(EventRouteQueryEnd, map[string]interface{}{
				"success":   true,
				"node":      tn.Node.Name(),
				"hop_table": hopTable,
			})
		} else {
			tn.Process.RouteTracer.LogEvent(EventRouteQueryEnd, map[string]interface{}{
				"success": false,
				"node":    tn.Node.Name(),
				"error":   "路由查询失败",
			})

			// 记录路由查询失败决策
			criteria := map[string]interface{}{
				"dst_network": dstNetworkList.String(),
				"in_port":     tn.InPort.Name(),
				"vrf":         tn.InVrf,
			}
			tn.Process.RouteTracer.LogRouteQuery(tn.Node.Name(), tn.InPort.Name(), tn.InVrf, dstNetworkList.String(), criteria, "failed", "路由查询失败")
		}
	}

	if !ok || hopTable == nil {
		tn.Ok = false
		// 路由查询失败 - 转换为警告
		warning := model.WarningInfo{
			Type:      model.WarningRouteQueryFailed,
			Message:   fmt.Sprintf("路由查询失败: 节点=%s, 入接口=%s, 意图=%s", tn.Node.Name(), tn.InPort.Name(), tn.Intent.String()),
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"destination_network": dstNetworkList.String(),
				"in_port":             tn.InPort.Name(),
				"vrf":                 tn.InVrf,
				"node":                tn.Node.Name(),
			},
		}
		tn.Process.AddWarning(warning)
		tn.logger.Warn("路由查询失败",
			zap.String("类型", warning.Type),
			zap.String("消息", warning.Message),
			zap.Any("详情", warning.Details))

		if tn.Process.RouteTracer != nil {
			tn.Process.RouteTracer.LogExit(ExitReasonRouteQueryFailed, tn.Node.Name(), tn.InPort.Name(), tn.InVrf, false, warning.Message, warning.Details)
		}
		return model.ProcessErr{}
	}

	// 检查下一跳表（hopTable 已经断言为 *tools.Table）
	connectedList := hopTable.Column("connected").List().Distinct()
	if len(connectedList) == 0 {
		// 下一跳表为空 - 转换为警告
		warning := model.WarningInfo{
			Type:      model.WarningNextHopEmpty,
			Message:   fmt.Sprintf("下一跳表为空: 目标网络=%v, 入接口=%s, VRF=%s", dstNetworkList, tn.InPort.Name(), tn.InVrf),
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"destination_network": dstNetworkList.String(),
				"in_port":             tn.InPort.Name(),
				"vrf":                 tn.InVrf,
				"node":                tn.Node.Name(),
				"hop_table_info":      "下一跳表为空",
			},
		}
		tn.Process.AddWarning(warning)
		tn.Ok = false
		tn.logger.Warn("下一跳表为空",
			zap.String("类型", warning.Type),
			zap.String("消息", warning.Message),
			zap.Any("详情", warning.Details))

		if tn.Process.RouteTracer != nil {
			tn.Process.RouteTracer.LogExit(ExitReasonNextHopNotFound, tn.Node.Name(), tn.InPort.Name(), tn.InVrf, false, warning.Message, warning.Details)
		}
		return model.ProcessErr{}
	} else if len(connectedList) > 1 {
		// 多路由匹配 - 转换为警告
		// 提取所有匹配的路由详情
		var matchedRoutes []map[string]interface{}
		interfaces := hopTable.Column("interface").List()
		ips := hopTable.Column("ip").List()
		connected := hopTable.Column("connected").List()

		// 使用 map 来去重，key 为 "interface:ip:connected" 的组合
		seenRoutes := make(map[string]bool)

		rowCount := len(hopTable.Rows)
		for i := 0; i < rowCount && i < len(interfaces) && i < len(ips) && i < len(connected); i++ {
			// 创建唯一标识符
			routeKey := fmt.Sprintf("%s:%v:%v", interfaces[i], ips[i], connected[i])

			// 只有当这个路由组合还没有出现过时才添加
			if !seenRoutes[routeKey] {
				routeInfo := map[string]interface{}{
					"interface": interfaces[i],
					"ip":        ips[i],
					"connected": connected[i],
				}
				matchedRoutes = append(matchedRoutes, routeInfo)
				seenRoutes[routeKey] = true
			}
		}

		warning := model.WarningInfo{
			Type:      model.WarningMultiRouteMatch,
			Message:   fmt.Sprintf("目标网络匹配到多条不同路由: 节点=%s, 入接口=%s, VRF=%s", tn.Node.Name(), tn.InPort.Name(), tn.InVrf),
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"matched_routes":      matchedRoutes,
				"route_count":         len(connectedList),
				"destination_network": dstNetworkList.String(),
				"in_port":             tn.InPort.Name(),
				"vrf":                 tn.InVrf,
				"node":                tn.Node.Name(),
				"connected_list":      connectedList,
			},
		}
		tn.Process.AddWarning(warning)
		tn.Ok = false
		tn.logger.Warn("多路由匹配",
			zap.String("类型", warning.Type),
			zap.String("消息", warning.Message),
			zap.Any("详情", warning.Details))

		if tn.Process.RouteTracer != nil {
			tn.Process.RouteTracer.LogExit(ExitReasonMultiRoute, tn.Node.Name(), tn.InPort.Name(), tn.InVrf, false, warning.Message, warning.Details)
		}
		return model.ProcessErr{}
	}

	tn.logger.Debug("路由查询结果", zap.Any("下一跳", hopTable))

	// 使用之前已经定义的 connectedList
	if connectedList[0].(bool) {
		tn.Ok = true
		path := fmt.Sprintf("%s:%s", tn.InVrf, tn.Node.Name())
		tn.Path += "|" + path
		tn.logger.Info("路由查询成功",
			zap.String("节点", tn.Node.Name()),
			zap.String("路径", tn.Path),
			zap.Any("意图", tn.Intent),
			zap.Any("下一跳", hopTable))

		// 记录直连路由跳（没有出接口）
		if tn.Process.RouteTracer != nil {
			tn.Process.RouteTracer.LogRouteHop(tn.InPort.Name(), tn.Node.Name(), "")

			// 记录退出信息
			details := map[string]interface{}{
				"route_type": "connected",
				"path":       tn.Path,
			}
			tn.Process.RouteTracer.LogExit(ExitReasonConnectedRoute, tn.Node.Name(), tn.InPort.Name(), tn.InVrf, true, "", details)
		}
		return
	}

	// 记录路由跳（只记录一次，在循环外）
	var outPortName string
	var hopIp string

	for it := hopTable.Iterator(); it.HasNext(); {
		_, hopMap := it.Next()
		tn.logger.Debug("处理下一跳",
			zap.Any("下一跳信息", hopMap))
		hopIp = hopMap["ip"].(string)
		outPortName = hopMap["interface"].(string)
		outPort := tn.Node.GetPortByNameOrAlias(outPortName)
		outPortConnector := tn.nm.CxMananger.GetConnectorByID(outPort.ConnectorID())
		nextDeviceNode, nextInputPort := outPortConnector.SelectNodeByIp(hopIp, outPort.Vrf())

		// 记录路由查询决策（包含输出端口信息）
		if tn.Process.RouteTracer != nil {
			criteria := map[string]interface{}{
				"dst_network": dstNetworkList.String(),
				"in_port":     tn.InPort.Name(),
				"vrf":         tn.InVrf,
				"hop_ip":      hopIp,
			}
			tn.Process.RouteTracer.LogRouteQueryWithOutput(tn.Node.Name(), tn.InPort.Name(), tn.InVrf, dstNetworkList.String(), outPortName, criteria, "success", "路由查询成功，找到输出端口")
		}

		if nextDeviceNode != nil {
			// 检查下一跳节点是否是当前节点本身（防止路由循环）
			if nextDeviceNode == tn.Node {
				// 检测到路由循环：下一跳节点就是当前节点
				loopPath := tn.Path
				if loopPath == "" {
					loopPath = fmt.Sprintf("%s:%s", tn.InVrf, tn.Node.Name())
				} else {
					loopPath += "|" + fmt.Sprintf("%s:%s", tn.InVrf, tn.Node.Name())
				}

				warning := model.WarningInfo{
					Type:      model.WarningRouteLoop,
					Message:   fmt.Sprintf("检测到路由循环：下一跳节点就是当前节点 %s，目标: %s", tn.Node.Name(), tn.Intent.Dst()),
					Timestamp: time.Now(),
					Details: map[string]interface{}{
						"loop_path":           loopPath,
						"destination_network": tn.Intent.Dst().String(),
						"current_node":        tn.Node.Name(),
						"next_node":           nextDeviceNode.Name(),
						"out_port":            outPortName,
						"in_port":             tn.InPort.Name(),
						"vrf":                 tn.InVrf,
					},
				}
				tn.Process.AddWarning(warning)
				tn.Ok = false
				tn.logger.Warn("检测到路由循环：下一跳节点就是当前节点",
					zap.String("类型", warning.Type),
					zap.String("消息", warning.Message),
					zap.Any("详情", warning.Details))

				// 记录到 RouteTracer
				if tn.Process.RouteTracer != nil {
					tn.Process.RouteTracer.LogExit(ExitReasonRouteLoop, tn.Node.Name(), outPortName, tn.InVrf, false, warning.Message, warning.Details)
				}
				return model.ProcessErr{} // 返回空错误，因为已经转换为警告
			}

			path := fmt.Sprintf("%s:%s", tn.InVrf, tn.Node.Name())
			nextNode := NewTraverseNode(tn.nm, nextDeviceNode, translateIntent, nextInputPort.Vrf(), nextInputPort, tn.IPFamily, tn.Path+"|"+path, tn.Process, traverseOnly)
			nextNode.WithLogger(tn.logger)
			// tn.Process.AddVertex(nextNode)
			// tn.Process.AddEdge(tn.Key(), nextNode.Key())

			// 记录下一跳找到事件
			if tn.Process.RouteTracer != nil {
				tn.Process.RouteTracer.LogNextHop(
					tn.Node.Name(),
					nextDeviceNode.Name(),
					nextInputPort.Name(),
					hopIp,
					outPortName,
				)

				// 记录下一跳选择决策
				criteria := map[string]interface{}{
					"hop_ip":    hopIp,
					"out_port":  outPortName,
					"next_node": nextDeviceNode.Name(),
					"next_port": nextInputPort.Name(),
				}
				tn.Process.RouteTracer.LogNextHopSelection(tn.Node.Name(), outPortName, tn.InVrf, hopIp, nextDeviceNode.Name(), nextInputPort.Name(), criteria, "success", "成功选择下一跳")
			}

			// tn.logger.Info("匹配到下一跳",
			// 	zap.String("当前节点", tn.Node.Name()),
			// 	zap.String("下一跳节点", nextDeviceNode.Name()),
			// 	zap.String("下一跳接口", nextInputPort.Name()),
			// 	zap.Any("意图", translateIntent))
			// 检查下一个节点是否已经被访问过
			if _, exists := tn.Process.Vertices[nextNode.Key()]; !exists {
				tn.Process.AddVertex(nextNode)
				tn.Process.AddEdge(tn.Key(), nextNode.Key())

				tn.logger.Info("匹配到下一跳",
					zap.String("当前节点", fmt.Sprintf("%s:%s", tn.InVrf, tn.Node.Name())),
					zap.String("下一跳节点", fmt.Sprintf("%s:%s", nextInputPort.Vrf(), nextDeviceNode.Name())),
					zap.String("下一跳接口", nextInputPort.Name()),
					zap.Any("意图", translateIntent))
			} else {
				tn.logger.Info("下一跳节点已被访问，跳过以避免环路",
					zap.String("下一跳节点", fmt.Sprintf("%s:%s", nextInputPort.Vrf(), nextDeviceNode.Name())))
			}
		} else {
			if ok, area := tn.nm.IsOutsidePort(tn.Node.Name(), hopMap["interface"].(string), tn.IPFamily); ok {
				// 记录Outside端口找到事件
				if tn.Process.RouteTracer != nil {
					tn.Process.RouteTracer.LogEvent(EventOutsidePortFound, map[string]interface{}{
						"node":   tn.Node.Name(),
						"port":   hopMap["interface"].(string),
						"area":   area,
						"hop_ip": hopIp,
					})

					// 记录区域分类决策
					criteria := map[string]interface{}{
						"port":   hopMap["interface"].(string),
						"hop_ip": hopIp,
					}
					tn.Process.RouteTracer.LogAreaClassification(tn.Node.Name(), hopMap["interface"].(string), tn.InVrf, area, criteria, "success", "端口属于Outside区域")
				}

				tn.logger.Info("路由下一跳为Outside",
					zap.String("出接口", hopMap["interface"].(string)),
					zap.String("下一跳IP", hopIp),
					zap.String("节点", tn.Node.Name()),
					zap.Any("意图", translateIntent),
					zap.String("区域", area))

				sameAreaPorts := tn.nm.GetPortsByArea(area, tn.IPFamily)
				sameAreaPorts = filterOutCurrentNodePorts(sameAreaPorts, tn.Node.Name(), tn.logger)

				nextNode, nextPort, foundMatch := findMatchingOutsideNode(tn.nm, sameAreaPorts, tn)

				if !foundMatch {
					tn.logger.Info("数据已被转发到Outside，结束匹配", zap.String("区域", area))
					tn.Ok = true
					path := fmt.Sprintf("%s:%s", tn.InVrf, tn.Node.Name())
					tn.Path += "|" + path + "|Outside:" + area
					tn.logger.Info("路由查询成功",
						zap.String("节点", tn.Node.Name()),
						zap.String("路径", tn.Path),
						zap.Any("意图", tn.Intent))

					// 记录Outside路由跳（没有出接口）
					if tn.Process.RouteTracer != nil {
						tn.Process.RouteTracer.LogRouteHop(tn.InPort.Name(), tn.Node.Name(), hopMap["interface"].(string))

						// 记录退出信息
						details := map[string]interface{}{
							"route_type": "outside",
							"area":       area,
							"path":       tn.Path,
						}
						tn.Process.RouteTracer.LogExit(ExitReasonOutsidePort, tn.Node.Name(), hopMap["interface"].(string), tn.InVrf, true, "", details)
					}
					return
				}

				// 不需要再创建新的TraverseNode，因为已经在findMatchingOutsideNode中创建了
				tn.logger.Info("继续处理Outside节点",
					zap.String("节点", nextNode.Name()),
					zap.String("接口", nextPort.Name()),
					zap.String("VRF", nextPort.Vrf()))

				// 递归调用RunL3Route来处理新的Outside节点
				// return tn.Process.GetVertex(nextNode.Key()).(*TraverseNode).RunL3Route(nodeMap, traverseOnly)
			} else {
				if tn.nm.IsStubPort(tn.Node, outPort, tn.IPFamily) {
					// 记录Stub端口找到事件
					if tn.Process.RouteTracer != nil {
						tn.Process.RouteTracer.LogEvent(EventStubPortFound, map[string]interface{}{
							"node":   tn.Node.Name(),
							"port":   hopMap["interface"].(string),
							"hop_ip": hopIp,
						})
						// 记录Stub路由跳（没有出接口）
						tn.Process.RouteTracer.LogRouteHop(tn.InPort.Name(), tn.Node.Name(), hopMap["interface"].(string))

						// 记录退出信息
						details := map[string]interface{}{
							"route_type": "stub",
							"hop_ip":     hopIp,
							"path":       tn.Path,
						}
						tn.Process.RouteTracer.LogExit(ExitReasonStubPort, tn.Node.Name(), hopMap["interface"].(string), tn.InVrf, true, "", details)
					}

					tn.logger.Info("路由下一跳是Stub Port",
						zap.String("出接口", hopMap["interface"].(string)),
						zap.String("下一跳IP", hopIp),
						zap.String("节点", tn.Node.Name()),
						zap.Any("意图", translateIntent))
					return
				} else {
					// 记录错误事件
					if tn.Process.RouteTracer != nil {
						tn.Process.RouteTracer.LogError(EventRouteQueryEnd, tn.Node.Name(),
							"路由下一跳不在NodeMap中", map[string]interface{}{
								"out_interface": hopMap["interface"].(string),
								"hop_ip":        hopIp,
							})

						// 记录失败决策
						details := map[string]interface{}{
							"out_interface": hopMap["interface"].(string),
							"hop_ip":        hopIp,
						}
						tn.Process.RouteTracer.LogFailure(tn.Node.Name(), hopMap["interface"].(string), tn.InVrf, "NextHopNotFound", "路由下一跳不在NodeMap中", details)

						// 记录退出信息
						exitDetails := map[string]interface{}{
							"out_interface": hopMap["interface"].(string),
							"hop_ip":        hopIp,
							"path":          tn.Path,
						}
						tn.Process.RouteTracer.LogExit(ExitReasonNextHopNotFound, tn.Node.Name(), hopMap["interface"].(string), tn.InVrf, false, "路由下一跳不在NodeMap中", exitDetails)
					}

					// 路由下一跳不在NodeMap中 - 转换为警告
					// 这是配置/环境问题，不是代码错误：下一跳设备可能未在NodeMap中配置，或者网络拓扑不完整
					warning := model.WarningInfo{
						Type:      model.WarningNextHopNotInNodeMap,
						Message:   fmt.Sprintf("路由下一跳设备未在NodeMap中配置（配置/环境问题）: 节点=%s, 出接口=%s, 下一跳IP=%s, 目标网络=%s", tn.Node.Name(), hopMap["interface"], hopIp, dstNetworkList.String()),
						Timestamp: time.Now(),
						Details: map[string]interface{}{
							"out_interface":       hopMap["interface"].(string),
							"next_hop_ip":         hopIp,
							"node":                tn.Node.Name(),
							"path":                tn.Path,
							"destination_network": dstNetworkList.String(),
							"in_port":             tn.InPort.Name(),
							"vrf":                 tn.InVrf,
							"issue_type":          "配置/环境问题",
							"description":         "路由查询成功，但下一跳设备未在NodeMap中配置。这通常表示：1) 下一跳设备未添加到NodeMap；2) 网络拓扑配置不完整；3) 目标网络位于NodeMap覆盖范围之外（如互联网）。",
							"suggestions": []string{
								"检查下一跳设备（IP: " + hopIp + "）是否已添加到NodeMap配置中",
								"确认网络拓扑配置是否完整，是否包含了所有中间设备",
								"如果目标网络在NodeMap覆盖范围之外（如互联网），这是正常情况",
								"检查路由表配置是否正确，确认下一跳IP地址是否有效",
							},
						},
					}
					tn.Process.AddWarning(warning)
					tn.Ok = false
					tn.logger.Warn("路由下一跳不在NodeMap中（配置/环境问题）",
						zap.String("类型", warning.Type),
						zap.String("消息", warning.Message),
						zap.String("问题类型", "配置/环境问题"),
						zap.String("节点", tn.Node.Name()),
						zap.String("出接口", hopMap["interface"].(string)),
						zap.String("下一跳IP", hopIp),
						zap.String("目标网络", dstNetworkList.String()),
						zap.Any("详情", warning.Details))
					return model.ProcessErr{}
				}
			}
		}
	}

	// 记录路由跳（循环结束后记录一次）
	if tn.Process.RouteTracer != nil && outPortName != "" {
		tn.Process.RouteTracer.LogRouteHop(tn.InPort.Name(), tn.Node.Name(), outPortName)

		// 记录退出信息（找到下一跳）
		details := map[string]interface{}{
			"out_port": outPortName,
			"hop_ip":   hopIp,
			"path":     tn.Path,
		}
		tn.Process.RouteTracer.LogExit(ExitReasonNextHopFound, tn.Node.Name(), outPortName, tn.InVrf, true, "", details)
	}

	tn.logger.Info("在下一级节点中进行路由查询")
	for it := tn.Iterator(); it.HasNext(); {
		_, nextNode := it.Next()
		processErr = nextNode.(*TraverseNode).Run(traverseOnly, ctx)
		if processErr.NotNil() {
			return
		}
	}
	return
}

func filterOutCurrentNodePorts(ports []api.Port, currentNodeName string, logger *zap.Logger) []api.Port {
	filtered := make([]api.Port, 0, len(ports))
	filteredOut := make([]api.Port, 0)

	for _, port := range ports {
		if port.Node().Name() != currentNodeName {
			filtered = append(filtered, port)
		} else {
			filteredOut = append(filteredOut, port)
		}
	}

	if len(filteredOut) > 0 {
		logger.Info("过滤掉当前节点的端口",
			zap.String("当前节点", currentNodeName),
			zap.Int("过滤掉的端口数量", len(filteredOut)),
			zap.Array("过滤掉的端口", zapcore.ArrayMarshalerFunc(func(ae zapcore.ArrayEncoder) error {
				for _, port := range filteredOut {
					ae.AppendString(port.Name())
				}
				return nil
			})))
	}

	return filtered
}

func findMatchingOutsideNode(nm *NodeMap, ports []api.Port, tn *TraverseNode) (api.Node, api.Port, bool) {
	var nextNode api.Node
	var nextPort api.Port
	var foundMatch bool

	for _, port := range ports {
		tn.logger.Debug("检查Outside节点",
			// zap.String("首选节点", fmt.Sprintf("%s:%s", nextPort.Vrf(), nextPort.Node().Name())),
			zap.String("节点", fmt.Sprintf("%s:%s", port.Vrf(), port.Node().Name())))

		ok, _, _, err := port.Node().IpRouteCheck(*tn.Intent.Dst().NetworkList(tn.IPFamily), port.Name(), port.Vrf(), tn.IPFamily)
		if ok {
			if foundMatch {
				tn.logger.Debug("发现多个匹配的Outside节点，使用第一个",
					zap.String("首选节点", nextNode.Name()),
					zap.String("当前节点", port.Node().Name()))
			} else {
				nextNode = port.Node()
				nextPort = port
				foundMatch = true

				tn.logger.Info("找到匹配的Outside节点",
					zap.String("节点", nextNode.Name()),
					zap.String("接口", nextPort.Name()))

				// 记录下一跳选择决策
				if tn.Process.RouteTracer != nil {
					// 获取端口所属区域
					area := ""
					if ok, portArea := tn.nm.IsOutsidePort(nextNode.Name(), nextPort.Name(), tn.IPFamily); ok {
						area = portArea
					}

					criteria := map[string]interface{}{
						"area":      area,
						"next_node": nextNode.Name(),
						"next_port": nextPort.Name(),
						"port_type": "Outside",
					}
					tn.Process.RouteTracer.LogNextHopSelection(tn.Node.Name(), tn.InPort.Name(), tn.InVrf, "Outside", nextNode.Name(), nextPort.Name(), criteria, "success", "成功选择Outside区域的下一个节点")
				}

				// 创建新的TraverseNode并添加到Process中
				path := fmt.Sprintf("%s:%s", tn.InVrf, tn.Node.Name())
				newNode := NewTraverseNode(nm, nextNode, tn.Intent, nextPort.Vrf(), nextPort, tn.IPFamily, tn.Path+"|"+path, tn.Process, tn.TraverseOnly)
				newNode.WithLogger(tn.logger)
				tn.Process.AddVertex(newNode)
				tn.Process.AddEdge(tn.Key(), newNode.Key())

				tn.logger.Info("添加Outside节点到遍历过程",
					zap.String("当前节点", fmt.Sprintf("%s:%s", tn.InVrf, tn.Node.Name())),
					zap.String("Outside节点", fmt.Sprintf("%s:%s", nextPort.Vrf(), nextNode.Name())),
					zap.String("Outside接口", nextPort.Name()),
					zap.Any("意图", tn.Intent))
			}
		} else {
			tn.logger.Debug("Outside节点不匹配",
				zap.String("节点", port.Node().Name()),
				zap.String("接口", port.Name()),
				zap.Error(err))
		}
	}

	return nextNode, nextPort, foundMatch
}

func (tn *TraverseNode) PrintCurrentPath() {
	var path []string
	currentKey := tn.Key()

	for {
		vertex, exists := tn.Process.Vertices[currentKey]
		if !exists {
			break
		}
		traverseNode := vertex.(*TraverseNode)
		path = append([]string{fmt.Sprintf("%s:%s", traverseNode.InVrf, traverseNode.Node.Name())}, path...)

		// 查找父节点
		var parentKey interface{}
		found := false
		for k, v := range tn.Process.Vertices {
			if v == vertex {
				continue
			}
			for it := v.Iterator(); it.HasNext(); {
				_, neighbor := it.Next()
				if neighbor.Key() == currentKey {
					parentKey = k
					found = true
					break
				}
			}
			if found {
				break
			}
		}

		if parentKey == nil {
			break
		}
		currentKey = parentKey
	}

	currentPath := strings.Join(path, " -> ")
	tn.logger.Info("当前经过的路径", zap.String("路径", currentPath))
}

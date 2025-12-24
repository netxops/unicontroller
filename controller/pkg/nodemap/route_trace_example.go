package nodemap

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/netxops/utils/policy"
	"go.uber.org/zap"
)

// RouteTraceExample 路由跟踪示例
func RouteTraceExample() {
	// 创建一个示例Intent（这里需要根据实际的policy.Intent结构来创建）
	// 由于我们不知道具体的结构，这里使用nil作为示例
	var intent *policy.Intent = nil

	// 创建NodeMap（这里需要实际的NodeMap实例）
	// nm := createExampleNodeMap()

	// 创建logger
	logger, _ := zap.NewDevelopment()

	// 创建路由跟踪器
	tracer := NewRouteTracer(logger, intent)

	// 记录一些示例事件和路由跳信息
	tracer.LogEvent(EventMakeTemplatesStart, map[string]interface{}{
		"intent": intent,
	})

	tracer.LogEvent(EventTraverseStart, map[string]interface{}{
		"src": "192.168.1.0/24",
		"dst": "10.0.0.0/8",
	})

	// 记录源节点定位决策
	criteria := map[string]interface{}{
		"src_network": "192.168.1.0/24",
		"vrf":         "default",
		"area":        "",
		"gateway":     "",
	}
	tracer.LogSourceNodeLocation("firewall-01", "eth0", "default", criteria, "success", "通过源网络地址定位到防火墙节点")

	// 记录源节点定位失败决策（示例）
	failureCriteria := map[string]interface{}{
		"src_network": "192.168.1.0/24",
		"vrf":         "default",
		"area":        "INVALID_AREA",
		"gateway":     "192.168.1.1",
		"input_node":  "firewall-01",
	}
	tracer.LogSourceNodeLocationFailure("Area not found.", failureCriteria)

	// 记录功能节点检查决策
	tracer.LogFunctionNodeCheck("firewall-01", "eth0", "default", true, "FIREWALL", "function_node", "防火墙节点，执行策略仿真")

	// 记录路由查询决策（包含输出端口信息）
	criteria = map[string]interface{}{
		"dst_network": "10.0.0.0/8",
		"in_port":     "eth0",
		"vrf":         "default",
		"hop_ip":      "192.168.1.1",
	}
	tracer.LogRouteQueryWithOutput("firewall-01", "eth0", "default", "10.0.0.0/8", "eth1", criteria, "success", "路由查询成功，找到输出端口")

	// 记录下一跳选择决策
	criteria = map[string]interface{}{
		"hop_ip":    "192.168.1.1",
		"out_port":  "eth0",
		"next_node": "router-01",
		"next_port": "eth1",
	}
	tracer.LogNextHopSelection("firewall-01", "eth0", "default", "192.168.1.1", "router-01", "eth1", criteria, "success", "成功选择路由器作为下一跳")

	// 记录区域分类决策
	criteria = map[string]interface{}{
		"port":   "eth2",
		"hop_ip": "10.0.0.1",
	}
	tracer.LogAreaClassification("router-01", "eth2", "default", "internet", criteria, "success", "端口属于Internet区域")

	// 记录路由跳信息（使用新的LogRouteHop方法）
	tracer.LogRouteHop("eth1", "router-01", "eth2")
	tracer.LogRouteHop("eth3", "server-01", "")

	// 记录退出信息
	details := map[string]interface{}{
		"route_type": "connected",
		"path":       "eth0|firewall-01|eth1|router-01|eth2|server-01",
	}
	tracer.LogExit(ExitReasonConnectedRoute, "server-01", "eth3", "default", true, "", details)

	tracer.LogEvent(EventMakeTemplatesEnd, map[string]interface{}{
		"result": "success",
	})

	// 获取路由跳信息
	routeHops := tracer.GetRouteHops()
	fmt.Println("=== 路由跳信息 ===")
	for i, hop := range routeHops {
		if hop.OutPort != "" {
			fmt.Printf("跳 %d: [%s、%s、%s]\n", i+1, hop.InPort, hop.Node, hop.OutPort)
		} else {
			fmt.Printf("跳 %d: [%s、%s]\n", i+1, hop.InPort, hop.Node)
		}
	}

	// 获取路由路径字符串
	routePath := tracer.GetRoutePathString()
	fmt.Printf("\n=== 路由路径字符串 ===\n%s\n", routePath)

	// 获取路由跳信息的JSON格式
	hopsJSON, err := tracer.GetRouteHopsJSON()
	if err != nil {
		log.Printf("获取路由跳JSON失败: %v", err)
	} else {
		fmt.Println("\n=== 路由跳信息JSON ===")
		fmt.Println(string(hopsJSON))
	}

	// 获取路由决策信息
	decisions := tracer.GetRouteDecisions()
	fmt.Println("\n=== 路由决策信息 ===")
	for i, decision := range decisions {
		fmt.Printf("决策 %d: %s\n", i+1, decision.DecisionType)
		fmt.Printf("  节点: %s, 端口: %s, VRF: %s\n", decision.Node, decision.Port, decision.VRF)
		fmt.Printf("  结果: %s, 原因: %s\n", decision.Result, decision.Reason)
		if decision.Area != "" {
			fmt.Printf("  区域: %s\n", decision.Area)
		}
		fmt.Printf("  决策依据: %v\n", decision.Criteria)
		fmt.Println()
	}

	// 获取路由决策的JSON格式
	decisionsJSON, err := tracer.GetRouteDecisionsJSON()
	if err != nil {
		log.Printf("获取路由决策JSON失败: %v", err)
	} else {
		fmt.Println("\n=== 路由决策信息JSON ===")
		fmt.Println(string(decisionsJSON))
	}

	// 获取退出信息
	exitInfo := tracer.GetExitInfo()
	if exitInfo != nil {
		fmt.Println("\n=== 退出信息 ===")
		fmt.Printf("退出原因: %s\n", exitInfo.Reason)
		fmt.Printf("节点: %s, 端口: %s, VRF: %s\n", exitInfo.Node, exitInfo.Port, exitInfo.VRF)
		fmt.Printf("成功: %t\n", exitInfo.Success)
		if exitInfo.ErrorMsg != "" {
			fmt.Printf("错误信息: %s\n", exitInfo.ErrorMsg)
		}
		fmt.Printf("详细信息: %v\n", exitInfo.Details)
	}

	// 获取退出信息的JSON格式
	exitInfoJSON, err := tracer.GetExitInfoJSON()
	if err != nil {
		log.Printf("获取退出信息JSON失败: %v", err)
	} else {
		fmt.Println("\n=== 退出信息JSON ===")
		fmt.Println(string(exitInfoJSON))
	}

	// 转换为API格式的路由跟踪信息
	routeTraceInfo := tracer.ToRouteTraceInfo()
	if routeTraceInfo != nil {
		fmt.Println("\n=== API格式路由跟踪信息 ===")
		fmt.Printf("Intent ID: %s\n", routeTraceInfo.IntentID)
		fmt.Printf("持续时间: %v\n", routeTraceInfo.Duration)
		fmt.Printf("路由路径: %s\n", routeTraceInfo.RoutePath)
		fmt.Printf("成功: %t\n", routeTraceInfo.Success)
		fmt.Printf("访问的节点: %v\n", routeTraceInfo.NodesVisited)
		fmt.Printf("决策统计: %v\n", routeTraceInfo.DecisionCounts)

		if routeTraceInfo.ExitInfo != nil {
			fmt.Printf("退出原因: %s\n", routeTraceInfo.ExitInfo.Reason)
			fmt.Printf("退出节点: %s\n", routeTraceInfo.ExitInfo.Node)
		}
	}

	// 获取跟踪摘要
	summary := tracer.GetTraceSummary()
	fmt.Println("\n=== 路由跟踪摘要 ===")
	summaryJSON, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Println(string(summaryJSON))
}

// PrintRouteTrace 打印路由跟踪信息
func (tp *TraverseProcess) PrintRouteTrace() {
	if tp.RouteTracer == nil {
		fmt.Println("没有路由跟踪信息")
		return
	}

	summary := tp.RouteTracer.GetTraceSummary()
	fmt.Println("=== 路由跟踪摘要 ===")
	fmt.Printf("Intent ID: %s\n", summary["intent_id"])
	fmt.Printf("持续时间: %v\n", summary["duration"])

	// 打印路由跳信息
	routeHops := tp.RouteTracer.GetRouteHops()
	fmt.Println("路由跳信息:")
	for i, hop := range routeHops {
		if hop.OutPort != "" {
			fmt.Printf("  跳 %d: [%s、%s、%s]\n", i+1, hop.InPort, hop.Node, hop.OutPort)
		} else {
			fmt.Printf("  跳 %d: [%s、%s]\n", i+1, hop.InPort, hop.Node)
		}
	}

	// 打印路由决策信息
	decisions := tp.RouteTracer.GetRouteDecisions()
	fmt.Println("路由决策信息:")
	for i, decision := range decisions {
		fmt.Printf("  决策 %d: %s\n", i+1, decision.DecisionType)
		fmt.Printf("    节点: %s, 端口: %s, 结果: %s\n", decision.Node, decision.Port, decision.Result)
		fmt.Printf("    原因: %s\n", decision.Reason)
		if decision.Area != "" {
			fmt.Printf("    区域: %s\n", decision.Area)
		}
	}

	// 打印路由路径字符串
	if routePath, ok := summary["route_path"].(string); ok {
		fmt.Printf("路由路径: %s\n", routePath)
	}

	if nodes, ok := summary["nodes_visited"].([]string); ok {
		fmt.Printf("访问的节点: %v\n", nodes)
	}
}

// GetRouteTraceJSON 获取路由跟踪的JSON数据
func (tp *TraverseProcess) GetRouteTraceJSON() ([]byte, error) {
	if tp.RouteTracer == nil {
		return nil, fmt.Errorf("没有路由跟踪器")
	}
	return tp.RouteTracer.GetTraceJSON()
}

// GetRouteTraceSummary 获取路由跟踪摘要
func (tp *TraverseProcess) GetRouteTraceSummary() map[string]interface{} {
	if tp.RouteTracer == nil {
		return map[string]interface{}{
			"error": "没有路由跟踪器",
		}
	}
	return tp.RouteTracer.GetTraceSummary()
}

// LogRouteDecision 记录路由决策
func (tp *TraverseProcess) LogRouteDecision(nodeName, portName, vrf, decision, reason string, details map[string]interface{}) {
	if tp.RouteTracer != nil {
		tp.RouteTracer.LogRouteDecisionOld(nodeName, portName, vrf, decision, reason, details)
	}
}

// LogPathUpdate 记录路径更新
func (tp *TraverseProcess) LogPathUpdate(path string) {
	if tp.RouteTracer != nil {
		tp.RouteTracer.LogPathUpdate(path)
	}
}

// GetRouteHops 获取路由跳信息
func (tp *TraverseProcess) GetRouteHops() []RouteHop {
	if tp.RouteTracer == nil {
		return nil
	}
	return tp.RouteTracer.GetRouteHops()
}

// GetRouteHopsJSON 获取路由跳信息的JSON格式
func (tp *TraverseProcess) GetRouteHopsJSON() ([]byte, error) {
	if tp.RouteTracer == nil {
		return nil, fmt.Errorf("没有路由跟踪器")
	}
	return tp.RouteTracer.GetRouteHopsJSON()
}

// GetRoutePathString 获取路由路径字符串
func (tp *TraverseProcess) GetRoutePathString() string {
	if tp.RouteTracer == nil {
		return "[]"
	}
	return tp.RouteTracer.GetRoutePathString()
}

// GetRouteDecisions 获取路由决策信息
func (tp *TraverseProcess) GetRouteDecisions() []RouteDecision {
	if tp.RouteTracer == nil {
		return nil
	}
	return tp.RouteTracer.GetRouteDecisions()
}

// GetRouteDecisionsJSON 获取路由决策信息的JSON格式
func (tp *TraverseProcess) GetRouteDecisionsJSON() ([]byte, error) {
	if tp.RouteTracer == nil {
		return nil, fmt.Errorf("没有路由跟踪器")
	}
	return tp.RouteTracer.GetRouteDecisionsJSON()
}

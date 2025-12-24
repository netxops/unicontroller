package nodemap

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/model"
	"github.com/netxops/utils/policy"
	"go.uber.org/zap"
)

// convertToString 将interface{}转换为string
func convertToString(value interface{}) string {
	if value == nil {
		return ""
	}

	switch v := value.(type) {
	case string:
		return v
	case int, int8, int16, int32, int64:
		return fmt.Sprintf("%d", v)
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", v)
	case float32, float64:
		return fmt.Sprintf("%.2f", v)
	case bool:
		return fmt.Sprintf("%t", v)
	default:
		// 对于复杂类型，使用JSON序列化
		if jsonBytes, err := json.Marshal(v); err == nil {
			return string(jsonBytes)
		}
		return fmt.Sprintf("%v", v)
	}
}

// convertMapToStringMap 将map[string]interface{}转换为map[string]string
func convertMapToStringMap(input map[string]interface{}) map[string]string {
	result := make(map[string]string)
	for k, v := range input {
		result[k] = convertToString(v)
	}
	return result
}

// RouteTraceEvent 路由跟踪事件类型
type RouteTraceEvent string

const (
	EventMakeTemplatesStart RouteTraceEvent = "MakeTemplatesStart"
	EventMakeTemplatesEnd   RouteTraceEvent = "MakeTemplatesEnd"
	EventTraverseStart      RouteTraceEvent = "TraverseStart"
	EventTraverseEnd        RouteTraceEvent = "TraverseEnd"
	EventLocateNodeStart    RouteTraceEvent = "LocateNodeStart"
	EventLocateNodeEnd      RouteTraceEvent = "LocateNodeEnd"
	EventRouteQueryStart    RouteTraceEvent = "RouteQueryStart"
	EventRouteQueryEnd      RouteTraceEvent = "RouteQueryEnd"
	EventNextHopFound       RouteTraceEvent = "NextHopFound"
	EventOutsidePortFound   RouteTraceEvent = "OutsidePortFound"
	EventStubPortFound      RouteTraceEvent = "StubPortFound"
	EventLoopDetected       RouteTraceEvent = "LoopDetected"
	EventRouteDecision      RouteTraceEvent = "RouteDecision"
	EventNodeProcessing     RouteTraceEvent = "NodeProcessing"
	EventPathUpdate         RouteTraceEvent = "PathUpdate"
)

// RouteHop 路由跳信息
type RouteHop struct {
	InPort  string `json:"in_port"`  // 入接口
	Node    string `json:"node"`     // 节点
	OutPort string `json:"out_port"` // 出接口（可选）
}

// RouteDecision 路由决策信息
type RouteDecision struct {
	Timestamp    time.Time         `json:"timestamp"`
	DecisionType string            `json:"decision_type"` // 决策类型
	Node         string            `json:"node"`          // 节点名称
	Port         string            `json:"port"`          // 端口名称
	VRF          string            `json:"vrf"`           // VRF
	Area         string            `json:"area"`          // 区域
	Criteria     map[string]string `json:"criteria"`      // 决策依据
	Result       string            `json:"result"`        // 决策结果
	Reason       string            `json:"reason"`        // 决策原因
	Details      map[string]string `json:"details"`       // 详细信息
}

// RouteDecisionType 路由决策类型
type RouteDecisionType string

const (
	DecisionSourceNodeLocation RouteDecisionType = "SourceNodeLocation" // 源节点定位
	DecisionFunctionNodeCheck  RouteDecisionType = "FunctionNodeCheck"  // 功能节点检查
	DecisionOutputPortMatch    RouteDecisionType = "OutputPortMatch"    // 输出端口匹配
	DecisionAreaClassification RouteDecisionType = "AreaClassification" // 区域分类
	DecisionRouteQuery         RouteDecisionType = "RouteQuery"         // 路由查询
	DecisionNextHopSelection   RouteDecisionType = "NextHopSelection"   // 下一跳选择
	DecisionFailure            RouteDecisionType = "Failure"            // 失败决策
)

// ExitReason 退出原因类型
type ExitReason string

const (
	ExitReasonConnectedRoute   ExitReason = "ConnectedRoute"   // 直连路由
	ExitReasonOutsidePort      ExitReason = "OutsidePort"      // Outside端口
	ExitReasonStubPort         ExitReason = "StubPort"         // Stub端口
	ExitReasonNextHopFound     ExitReason = "NextHopFound"     // 找到下一跳
	ExitReasonRouteQueryFailed ExitReason = "RouteQueryFailed" // 路由查询失败
	ExitReasonNextHopNotFound  ExitReason = "NextHopNotFound"  // 下一跳未找到
	ExitReasonMultiRoute       ExitReason = "MultiRoute"       // 多路由不支持
	ExitReasonProcessError     ExitReason = "ProcessError"     // 处理错误
	ExitReasonLoopDetected     ExitReason = "LoopDetected"     // 检测到环路
	ExitReasonRouteLoop        ExitReason = "RouteLoop"        // 路由环路
	ExitReasonSourceNodeFailed ExitReason = "SourceNodeFailed" // 源节点定位失败
)

// ExitInfo 退出信息
type ExitInfo struct {
	Timestamp time.Time         `json:"timestamp"`
	Reason    ExitReason        `json:"reason"`
	Node      string            `json:"node"`
	Port      string            `json:"port"`
	VRF       string            `json:"vrf"`
	Details   map[string]string `json:"details"`
	Success   bool              `json:"success"`
	ErrorMsg  string            `json:"error_msg,omitempty"`
}

// RouteTraceEntry 路由跟踪条目
type RouteTraceEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Event     RouteTraceEvent        `json:"event"`
	IntentID  string                 `json:"intent_id,omitempty"`
	NodeName  string                 `json:"node_name,omitempty"`
	PortName  string                 `json:"port_name,omitempty"`
	VRF       string                 `json:"vrf,omitempty"`
	Path      string                 `json:"path,omitempty"`
	NextHop   string                 `json:"next_hop,omitempty"`
	OutPort   string                 `json:"out_port,omitempty"`
	Area      string                 `json:"area,omitempty"`
	Decision  string                 `json:"decision,omitempty"`
	Reason    string                 `json:"reason,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Duration  time.Duration          `json:"duration,omitempty"`
}

// RouteTracer 路由跟踪器
type RouteTracer struct {
	entries   []RouteTraceEntry
	routeHops []RouteHop      // 路由跳信息列表
	decisions []RouteDecision // 路由决策信息列表
	exitInfo  *ExitInfo       // 退出信息
	logger    *zap.Logger
	intentID  string
	startTime time.Time
	context   context.Context
}

// NewRouteTracer 创建新的路由跟踪器
func NewRouteTracer(logger *zap.Logger, intent *policy.Intent) *RouteTracer {
	return &RouteTracer{
		entries:   make([]RouteTraceEntry, 0),
		routeHops: make([]RouteHop, 0),
		decisions: make([]RouteDecision, 0),
		logger:    logger,
		intentID:  generateIntentID(intent),
		startTime: time.Now(),
		context:   context.Background(),
	}
}

// generateIntentID 生成Intent的唯一ID
func generateIntentID(intent *policy.Intent) string {
	srcStr := "any"
	dstStr := "any"

	if intent != nil {
		if src := intent.Src(); src != nil {
			srcStr = src.String()
		}
		if dst := intent.Dst(); dst != nil {
			dstStr = dst.String()
		}
	}

	return fmt.Sprintf("intent_%d_%s_%s",
		time.Now().UnixNano(),
		srcStr,
		dstStr)
}

// LogEvent 记录路由跟踪事件
func (rt *RouteTracer) LogEvent(event RouteTraceEvent, details map[string]interface{}) {
	entry := RouteTraceEntry{
		Timestamp: time.Now(),
		Event:     event,
		IntentID:  rt.intentID,
		Details:   details,
	}

	// 根据事件类型填充特定字段
	switch event {
	case EventMakeTemplatesStart:
		rt.logger.Info("开始MakeTemplates处理",
			zap.String("intent_id", rt.intentID),
			zap.Any("intent", details["intent"]))

	case EventMakeTemplatesEnd:
		entry.Duration = time.Since(rt.startTime)
		rt.logger.Info("MakeTemplates处理完成",
			zap.String("intent_id", rt.intentID),
			zap.Duration("duration", entry.Duration),
			zap.Any("result", details["result"]))

	case EventTraverseStart:
		rt.logger.Info("开始路由遍历",
			zap.String("intent_id", rt.intentID),
			zap.String("src", details["src"].(string)),
			zap.String("dst", details["dst"].(string)))

	case EventLocateNodeStart:
		rt.logger.Info("开始定位源节点",
			zap.String("intent_id", rt.intentID),
			zap.String("src_network", details["src_network"].(string)),
			zap.String("vrf", details["vrf"].(string)),
			zap.String("area", details["area"].(string)))

	case EventLocateNodeEnd:
		if details["success"].(bool) {
			rt.logger.Info("源节点定位成功",
				zap.String("intent_id", rt.intentID),
				zap.String("node", details["node"].(string)),
				zap.String("port", details["port"].(string)))
		} else {
			rt.logger.Error("源节点定位失败",
				zap.String("intent_id", rt.intentID),
				zap.String("error", details["error"].(string)))
		}

	case EventRouteQueryStart:
		rt.logger.Info("开始路由查询",
			zap.String("intent_id", rt.intentID),
			zap.String("node", details["node"].(string)),
			zap.String("in_port", details["in_port"].(string)),
			zap.String("dst_network", details["dst_network"].(string)))

	case EventRouteQueryEnd:
		if details["success"].(bool) {
			rt.logger.Info("路由查询成功",
				zap.String("intent_id", rt.intentID),
				zap.String("node", details["node"].(string)),
				zap.Any("hop_table", details["hop_table"]))
		} else {
			rt.logger.Error("路由查询失败",
				zap.String("intent_id", rt.intentID),
				zap.String("node", details["node"].(string)),
				zap.String("error", details["error"].(string)))
		}

	case EventNextHopFound:
		rt.logger.Info("找到下一跳",
			zap.String("intent_id", rt.intentID),
			zap.String("current_node", details["current_node"].(string)),
			zap.String("next_node", details["next_node"].(string)),
			zap.String("next_port", details["next_port"].(string)),
			zap.String("next_hop_ip", details["next_hop_ip"].(string)))

	case EventOutsidePortFound:
		rt.logger.Info("找到Outside端口",
			zap.String("intent_id", rt.intentID),
			zap.String("node", details["node"].(string)),
			zap.String("port", details["port"].(string)),
			zap.String("area", details["area"].(string)))

	case EventStubPortFound:
		rt.logger.Info("找到Stub端口",
			zap.String("intent_id", rt.intentID),
			zap.String("node", details["node"].(string)),
			zap.String("port", details["port"].(string)))

	case EventLoopDetected:
		rt.logger.Warn("检测到路由循环",
			zap.String("intent_id", rt.intentID),
			zap.String("node", details["node"].(string)),
			zap.String("path", details["path"].(string)))

	case EventRouteDecision:
		rt.logger.Info("路由决策",
			zap.String("intent_id", rt.intentID),
			zap.String("decision", details["decision"].(string)),
			zap.String("reason", details["reason"].(string)))

	case EventPathUpdate:
		rt.logger.Info("路径更新",
			zap.String("intent_id", rt.intentID),
			zap.String("path", details["path"].(string)))
	}

	rt.entries = append(rt.entries, entry)
}

// GetTraceEntries 获取所有跟踪条目
func (rt *RouteTracer) GetTraceEntries() []RouteTraceEntry {
	return rt.entries
}

// AddRouteHop 添加路由跳信息
func (rt *RouteTracer) AddRouteHop(inPort, node, outPort string) {
	hop := RouteHop{
		InPort:  inPort,
		Node:    node,
		OutPort: outPort,
	}
	rt.routeHops = append(rt.routeHops, hop)

	rt.logger.Info("添加路由跳",
		zap.String("intent_id", rt.intentID),
		zap.String("in_port", inPort),
		zap.String("node", node),
		zap.String("out_port", outPort))
}

// AddRouteHopWithoutOutPort 添加没有出接口的路由跳信息
func (rt *RouteTracer) AddRouteHopWithoutOutPort(inPort, node string) {
	hop := RouteHop{
		InPort:  inPort,
		Node:    node,
		OutPort: "", // 空字符串表示没有出接口
	}
	rt.routeHops = append(rt.routeHops, hop)

	rt.logger.Info("添加路由跳（无出接口）",
		zap.String("intent_id", rt.intentID),
		zap.String("in_port", inPort),
		zap.String("node", node))
}

// GetRouteHops 获取所有路由跳信息
func (rt *RouteTracer) GetRouteHops() []RouteHop {
	return rt.routeHops
}

// GetRouteHopsJSON 获取路由跳信息的JSON格式
func (rt *RouteTracer) GetRouteHopsJSON() ([]byte, error) {
	return json.MarshalIndent(rt.routeHops, "", "  ")
}

// GetRoutePathString 获取路由路径的字符串表示
func (rt *RouteTracer) GetRoutePathString() string {
	if len(rt.routeHops) == 0 {
		return "[]"
	}

	var pathParts []string
	for _, hop := range rt.routeHops {
		if hop.OutPort != "" {
			pathParts = append(pathParts, fmt.Sprintf("[%s、%s、%s]", hop.InPort, hop.Node, hop.OutPort))
		} else {
			pathParts = append(pathParts, fmt.Sprintf("[%s、%s]", hop.InPort, hop.Node))
		}
	}

	return fmt.Sprintf("[%s]", strings.Join(pathParts, " "))
}

// GetTraceJSON 获取跟踪条目的JSON格式
func (rt *RouteTracer) GetTraceJSON() ([]byte, error) {
	return json.MarshalIndent(rt.entries, "", "  ")
}

// GetTraceSummary 获取跟踪摘要
func (rt *RouteTracer) GetTraceSummary() map[string]interface{} {
	summary := map[string]interface{}{
		"intent_id":       rt.intentID,
		"duration":        time.Since(rt.startTime),
		"start_time":      rt.startTime,
		"end_time":        time.Now(),
		"route_hops":      rt.routeHops,
		"route_path":      rt.GetRoutePathString(),
		"route_decisions": rt.decisions,
		"exit_info":       rt.exitInfo,
	}

	// 提取访问的节点信息
	var nodes []string
	for _, hop := range rt.routeHops {
		if !contains(nodes, hop.Node) {
			nodes = append(nodes, hop.Node)
		}
	}
	summary["nodes_visited"] = nodes

	// 统计决策类型
	decisionCounts := make(map[string]int)
	for _, decision := range rt.decisions {
		decisionCounts[decision.DecisionType]++
	}
	summary["decision_counts"] = decisionCounts

	return summary
}

// contains 检查切片中是否包含指定元素
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// LogRouteDecisionOld 记录路由决策（旧版本，保持兼容性）
func (rt *RouteTracer) LogRouteDecisionOld(nodeName, portName, vrf, decision, reason string, details map[string]interface{}) {
	decisionDetails := map[string]interface{}{
		"node":     nodeName,
		"port":     portName,
		"vrf":      vrf,
		"decision": decision,
		"reason":   reason,
	}

	// 合并额外详情
	for k, v := range details {
		decisionDetails[k] = v
	}

	rt.LogEvent(EventRouteDecision, decisionDetails)
}

// LogNextHop 记录下一跳信息（不记录路由跳，只记录事件）
func (rt *RouteTracer) LogNextHop(currentNode, nextNode, nextPort, nextHopIP, outPort string) {
	rt.LogEvent(EventNextHopFound, map[string]interface{}{
		"current_node": currentNode,
		"next_node":    nextNode,
		"next_port":    nextPort,
		"next_hop_ip":  nextHopIP,
		"out_port":     outPort,
	})

	// 不再记录路由跳信息，路由跳由 LogRouteHop 统一记录
}

// LogPathUpdate 记录路径更新
func (rt *RouteTracer) LogPathUpdate(path string) {
	rt.LogEvent(EventPathUpdate, map[string]interface{}{
		"path": path,
	})
}

// LogSourceNode 记录源节点信息（不记录路由跳，只记录决策信息）
func (rt *RouteTracer) LogSourceNode(inPort, node string) {
	// 不记录路由跳，只记录日志信息
	rt.logger.Info("记录源节点",
		zap.String("intent_id", rt.intentID),
		zap.String("in_port", inPort),
		zap.String("node", node))
}

// LogRouteHop 记录完整的路由跳（推荐使用的方法）
func (rt *RouteTracer) LogRouteHop(inPort, node, outPort string) {
	hop := RouteHop{
		InPort:  inPort,
		Node:    node,
		OutPort: outPort,
	}
	rt.routeHops = append(rt.routeHops, hop)

	rt.logger.Info("记录路由跳",
		zap.String("intent_id", rt.intentID),
		zap.String("in_port", inPort),
		zap.String("node", node),
		zap.String("out_port", outPort))
}

// LogDestinationNode 记录目标节点信息（没有出接口的终点）
func (rt *RouteTracer) LogDestinationNode(inPort, node string) {
	rt.AddRouteHopWithoutOutPort(inPort, node)

	rt.logger.Info("记录目标节点",
		zap.String("intent_id", rt.intentID),
		zap.String("in_port", inPort),
		zap.String("node", node))
}

// LogRouteDecisionNew 记录路由决策
func (rt *RouteTracer) LogRouteDecisionNew(decisionType RouteDecisionType, node, port, vrf, area, result, reason string, criteria, details map[string]interface{}) {
	decision := RouteDecision{
		Timestamp:    time.Now(),
		DecisionType: string(decisionType),
		Node:         node,
		Port:         port,
		VRF:          vrf,
		Area:         area,
		Criteria:     convertMapToStringMap(criteria),
		Result:       result,
		Reason:       reason,
		Details:      convertMapToStringMap(details),
	}

	rt.decisions = append(rt.decisions, decision)

	rt.logger.Info("记录路由决策",
		zap.String("intent_id", rt.intentID),
		zap.String("decision_type", string(decisionType)),
		zap.String("node", node),
		zap.String("port", port),
		zap.String("result", result),
		zap.String("reason", reason),
		zap.Any("criteria", criteria))
}

// LogSourceNodeLocation 记录源节点定位决策
func (rt *RouteTracer) LogSourceNodeLocation(node, port, vrf string, criteria map[string]interface{}, result, reason string) {
	rt.LogRouteDecisionNew(DecisionSourceNodeLocation, node, port, vrf, "", result, reason, criteria, nil)
}

// LogSourceNodeLocationFailure 记录源节点定位失败决策（带详细失败原因）
func (rt *RouteTracer) LogSourceNodeLocationFailure(errorMsg string, criteria map[string]interface{}) {
	// 根据错误消息分析失败原因
	failureReason := rt.analyzeSourceNodeLocationFailure(errorMsg)

	rt.LogRouteDecisionNew(DecisionSourceNodeLocation, "", "", "", "", "failed", failureReason, criteria, map[string]interface{}{
		"error_message": errorMsg,
		"failure_type":  rt.getFailureType(errorMsg),
	})
}

// analyzeSourceNodeLocationFailure 分析源节点定位失败的原因
func (rt *RouteTracer) analyzeSourceNodeLocationFailure(errorMsg string) string {
	switch {
	case strings.Contains(errorMsg, "Area not found"):
		return "指定的区域未找到"
	case strings.Contains(errorMsg, "No matching ports found"):
		return "未找到匹配的端口"
	case strings.Contains(errorMsg, "Multiple matching ports found"):
		return "找到多个匹配的端口，需要更精确的定位条件"
	case strings.Contains(errorMsg, "No outside node"):
		return "未找到外部连接节点"
	case strings.Contains(errorMsg, "current not support multiple outside interface"):
		return "当前不支持多个外部接口"
	case strings.Contains(errorMsg, "nodemap have multiple outside connections, must give area info"):
		return "网络拓扑有多个外部连接，必须提供区域信息"
	case strings.Contains(errorMsg, "No suitable node found for area"):
		return "在指定区域未找到合适的节点"
	case strings.Contains(errorMsg, "Multiple suitable nodes found for area"):
		return "在指定区域找到多个合适的节点"
	case strings.Contains(errorMsg, "Multiple nodes, but gw is empty"):
		return "找到多个节点，但网关信息为空"
	case strings.Contains(errorMsg, "Multiple nodes, but can not find node by gw"):
		return "找到多个节点，但无法通过网关找到对应节点"
	case strings.Contains(errorMsg, "port name is empty"):
		return "端口名称为空"
	case strings.Contains(errorMsg, "can not find node, port list is empty"):
		return "无法找到节点，端口列表为空"
	case strings.Contains(errorMsg, "get port failed"):
		return "获取端口失败"
	case strings.Contains(errorMsg, "Check route failed"):
		return "路由检查失败"
	default:
		return "源节点定位失败: " + errorMsg
	}
}

// getFailureType 获取失败类型
func (rt *RouteTracer) getFailureType(errorMsg string) string {
	switch {
	case strings.Contains(errorMsg, "Area not found"):
		return "AREA_NOT_FOUND"
	case strings.Contains(errorMsg, "No matching ports found"):
		return "NO_MATCHING_PORTS"
	case strings.Contains(errorMsg, "Multiple matching ports found"):
		return "MULTIPLE_MATCHING_PORTS"
	case strings.Contains(errorMsg, "No outside node"):
		return "NO_OUTSIDE_NODE"
	case strings.Contains(errorMsg, "current not support multiple outside interface"):
		return "MULTIPLE_OUTSIDE_INTERFACES"
	case strings.Contains(errorMsg, "nodemap have multiple outside connections, must give area info"):
		return "MULTIPLE_OUTSIDE_CONNECTIONS"
	case strings.Contains(errorMsg, "No suitable node found for area"):
		return "NO_SUITABLE_NODE_FOR_AREA"
	case strings.Contains(errorMsg, "Multiple suitable nodes found for area"):
		return "MULTIPLE_SUITABLE_NODES_FOR_AREA"
	case strings.Contains(errorMsg, "Multiple nodes, but gw is empty"):
		return "MULTIPLE_NODES_NO_GATEWAY"
	case strings.Contains(errorMsg, "Multiple nodes, but can not find node by gw"):
		return "MULTIPLE_NODES_GATEWAY_MISMATCH"
	case strings.Contains(errorMsg, "port name is empty"):
		return "EMPTY_PORT_NAME"
	case strings.Contains(errorMsg, "can not find node, port list is empty"):
		return "EMPTY_PORT_LIST"
	case strings.Contains(errorMsg, "get port failed"):
		return "GET_PORT_FAILED"
	case strings.Contains(errorMsg, "Check route failed"):
		return "ROUTE_CHECK_FAILED"
	default:
		return "UNKNOWN_ERROR"
	}
}

// LogFunctionNodeCheck 记录功能节点检查决策
func (rt *RouteTracer) LogFunctionNodeCheck(node, port, vrf string, isFunctionNode bool, nodeType string, result, reason string) {
	criteria := map[string]interface{}{
		"is_function_node": isFunctionNode,
		"node_type":        nodeType,
	}
	details := map[string]interface{}{
		"policy_simulation": isFunctionNode,
	}
	rt.LogRouteDecisionNew(DecisionFunctionNodeCheck, node, port, vrf, "", result, reason, criteria, details)
}

// LogOutputPortMatch 记录输出端口匹配决策
func (rt *RouteTracer) LogOutputPortMatch(node, inPort, outPort, vrf, area string, criteria map[string]interface{}, result, reason string) {
	details := map[string]interface{}{
		"in_port":  inPort,
		"out_port": outPort,
		"area":     area,
	}
	rt.LogRouteDecisionNew(DecisionOutputPortMatch, node, outPort, vrf, area, result, reason, criteria, details)
}

// LogAreaClassification 记录区域分类决策
func (rt *RouteTracer) LogAreaClassification(node, port, vrf, area string, criteria map[string]interface{}, result, reason string) {
	rt.LogRouteDecisionNew(DecisionAreaClassification, node, port, vrf, area, result, reason, criteria, nil)
}

// LogRouteQuery 记录路由查询决策
func (rt *RouteTracer) LogRouteQuery(node, port, vrf string, dstNetwork string, criteria map[string]interface{}, result, reason string) {
	details := map[string]interface{}{
		"dst_network": dstNetwork,
	}
	rt.LogRouteDecisionNew(DecisionRouteQuery, node, port, vrf, "", result, reason, criteria, details)
}

// LogRouteQueryWithOutput 记录路由查询决策（包含输出端口信息）
func (rt *RouteTracer) LogRouteQueryWithOutput(node, port, vrf string, dstNetwork, outPort string, criteria map[string]interface{}, result, reason string) {
	details := map[string]interface{}{
		"dst_network": dstNetwork,
		"out_port":    outPort,
	}
	rt.LogRouteDecisionNew(DecisionRouteQuery, node, port, vrf, "", result, reason, criteria, details)
}

// LogNextHopSelection 记录下一跳选择决策
func (rt *RouteTracer) LogNextHopSelection(node, port, vrf string, nextHop, nextNode, nextPort string, criteria map[string]interface{}, result, reason string) {
	details := map[string]interface{}{
		"next_hop":  nextHop,
		"next_node": nextNode,
		"next_port": nextPort,
	}
	rt.LogRouteDecisionNew(DecisionNextHopSelection, node, port, vrf, "", result, reason, criteria, details)
}

// LogFailure 记录失败决策
func (rt *RouteTracer) LogFailure(node, port, vrf string, failureType string, reason string, details map[string]interface{}) {
	criteria := map[string]interface{}{
		"failure_type": failureType,
	}
	rt.LogRouteDecisionNew(DecisionFailure, node, port, vrf, "", "failed", reason, criteria, details)
}

// GetRouteDecisions 获取所有路由决策
func (rt *RouteTracer) GetRouteDecisions() []RouteDecision {
	return rt.decisions
}

// GetRouteDecisionsJSON 获取路由决策的JSON格式
func (rt *RouteTracer) GetRouteDecisionsJSON() ([]byte, error) {
	return json.MarshalIndent(rt.decisions, "", "  ")
}

// LogExit 记录退出信息
func (rt *RouteTracer) LogExit(reason ExitReason, node, port, vrf string, success bool, errorMsg string, details map[string]interface{}) {
	exitInfo := &ExitInfo{
		Timestamp: time.Now(),
		Reason:    reason,
		Node:      node,
		Port:      port,
		VRF:       vrf,
		Details:   convertMapToStringMap(details),
		Success:   success,
		ErrorMsg:  errorMsg,
	}

	rt.exitInfo = exitInfo

	rt.logger.Info("记录退出信息",
		zap.String("intent_id", rt.intentID),
		zap.String("exit_reason", string(reason)),
		zap.String("node", node),
		zap.String("port", port),
		zap.Bool("success", success),
		zap.String("error_msg", errorMsg),
		zap.Any("details", details))
}

// GetExitInfo 获取退出信息
func (rt *RouteTracer) GetExitInfo() *ExitInfo {
	return rt.exitInfo
}

// GetExitInfoJSON 获取退出信息的JSON格式
func (rt *RouteTracer) GetExitInfoJSON() ([]byte, error) {
	if rt.exitInfo == nil {
		return json.Marshal(nil)
	}
	return json.MarshalIndent(rt.exitInfo, "", "  ")
}

// ToRouteTraceInfo 将RouteTracer转换为API格式的RouteTraceInfo
func (rt *RouteTracer) ToRouteTraceInfo() *model.RouteTraceInfo {
	if rt == nil {
		return nil
	}

	// 转换路由跳信息
	routeHops := make([]model.RouteHopInfo, len(rt.routeHops))
	for i, hop := range rt.routeHops {
		routeHops[i] = model.RouteHopInfo{
			InPort:  hop.InPort,
			Node:    hop.Node,
			OutPort: hop.OutPort,
		}
	}

	// 转换路由决策信息
	routeDecisions := make([]model.RouteDecisionInfo, len(rt.decisions))
	for i, decision := range rt.decisions {
		routeDecisions[i] = model.RouteDecisionInfo{
			Timestamp:    decision.Timestamp,
			DecisionType: string(decision.DecisionType),
			Node:         decision.Node,
			Port:         decision.Port,
			VRF:          decision.VRF,
			Area:         decision.Area,
			Criteria:     decision.Criteria,
			Result:       decision.Result,
			Reason:       decision.Reason,
			Details:      decision.Details,
		}
	}

	// 转换退出信息
	var exitInfo *model.ExitInfoAPI
	if rt.exitInfo != nil {
		exitInfo = &model.ExitInfoAPI{
			Timestamp: rt.exitInfo.Timestamp,
			Reason:    string(rt.exitInfo.Reason),
			Node:      rt.exitInfo.Node,
			Port:      rt.exitInfo.Port,
			VRF:       rt.exitInfo.VRF,
			Details:   rt.exitInfo.Details,
			Success:   rt.exitInfo.Success,
			ErrorMsg:  rt.exitInfo.ErrorMsg,
		}
	}

	// 提取访问的节点信息
	var nodesVisited []string
	for _, hop := range rt.routeHops {
		if !contains(nodesVisited, hop.Node) {
			nodesVisited = append(nodesVisited, hop.Node)
		}
	}

	// 统计决策类型
	decisionCounts := make(map[string]int)
	for _, decision := range rt.decisions {
		decisionCounts[string(decision.DecisionType)]++
	}

	// 判断是否成功
	success := true
	var errorMessage string
	if rt.exitInfo != nil && !rt.exitInfo.Success {
		success = false
		errorMessage = rt.exitInfo.ErrorMsg
	}

	return &model.RouteTraceInfo{
		IntentID:       rt.intentID,
		Duration:       time.Since(rt.startTime),
		StartTime:      rt.startTime,
		EndTime:        time.Now(),
		RouteHops:      routeHops,
		RoutePath:      rt.GetRoutePathString(),
		RouteDecisions: routeDecisions,
		ExitInfo:       exitInfo,
		NodesVisited:   nodesVisited,
		DecisionCounts: decisionCounts,
		Success:        success,
		ErrorMessage:   errorMessage,
	}
}

// LogError 记录错误
func (rt *RouteTracer) LogError(event RouteTraceEvent, nodeName, errorMsg string, details map[string]interface{}) {
	errorDetails := map[string]interface{}{
		"node":  nodeName,
		"error": errorMsg,
	}

	// 合并额外详情
	for k, v := range details {
		errorDetails[k] = v
	}

	entry := RouteTraceEntry{
		Timestamp: time.Now(),
		Event:     event,
		IntentID:  rt.intentID,
		NodeName:  nodeName,
		Error:     errorMsg,
		Details:   errorDetails,
	}

	rt.entries = append(rt.entries, entry)

	rt.logger.Error("路由跟踪错误",
		zap.String("intent_id", rt.intentID),
		zap.String("event", string(event)),
		zap.String("node", nodeName),
		zap.String("error", errorMsg),
		zap.Any("details", details))
}

package model

import (
	"time"

	"github.com/netxops/utils/policy"
)

type TemplatesReplay struct {
	// Results *nodemap.TraverseResult
	Results           []byte
	Result            *TemplateResult
	RouteDecisionInfo map[string][]RouteDecisionInfo `json:"route_decision_info,omitempty"` // 路由跟踪信息
}

// func (nm *NodeMap) MakeTemplates(intent *policy.Intent, vrf, area, gw, gw6 string, traverseOnly bool) *TraverseProcess {
type TemplatesArgs struct {
	Params    *policy.IntentParams
	Vrf       string
	Area      string
	Gw        string
	Gw6       string
	NodeMapId uint
}

type NodeMapInitArgs struct {
	Id uint
}

type NodeMapInitReplay struct {
}

type ProcessErr struct {
	Desc string
	Mark string
}

func NewProcessErr(desc string, mark string) ProcessErr {
	return ProcessErr{Desc: desc, Mark: mark}
}

func (pe ProcessErr) NotNil() bool {
	return pe.Desc != "" || pe.Mark != ""
}

func (pe ProcessErr) GetDesc() string {
	return pe.Desc
}
func (pe ProcessErr) GetMark() string {
	return pe.Mark
}

const (
	ConfigConflict               string = "配置冲突"
	MissRoute                    string = "路由缺失"
	SimylationVerificationFailed string = "仿真验证失败"
	PolicyDeny                   string = "Deny策略"
	RouteLoop                    string = "路由环路"
	RouteQuery                   string = "路由查询失败"
	SrcNodePoositionErr          string = "源节点定位失败"
	NextHop_Empty                string = "下一跳路由为空"
	Not_Support_Multi_Route      string = "不支持多路由"
)

// 警告类型常量
const (
	WarningMultiRouteMatch     string = "多路由匹配"
	WarningRouteQueryFailed    string = "路由查询失败"
	WarningNextHopEmpty        string = "下一跳路由为空"
	WarningRouteLoop           string = "路由环路"
	WarningNextHopNotInNodeMap string = "路由下一跳不在NodeMap中"
	WarningMissRoute           string = "路由缺失"
	WarningIncompleteRoute     string = "路由表项不完整"
)

// WarningInfo 警告信息结构体
type WarningInfo struct {
	Type      string                 `json:"type"`      // 警告类型
	Message   string                 `json:"message"`   // 警告消息
	Details   map[string]interface{} `json:"details"`   // 详细信息
	Timestamp time.Time              `json:"timestamp"` // 时间戳
}

// RouteCheckResult 路由检查结果
type RouteCheckResult struct {
	Ok                bool                   `json:"ok"`                            // 路由检查是否成功
	HopTable          interface{}            `json:"hop_table,omitempty"`           // 路由跳转表（使用 interface{} 避免循环依赖）
	PortList          []string               `json:"port_list"`                     // 出端口列表
	Warning           *WarningInfo           `json:"warning,omitempty"`             // 警告信息
	RouteMatchDetails map[string]interface{} `json:"route_match_details,omitempty"` // 路由匹配详情（用于多路由匹配场景）
}

type TemplateResult struct {
	Result []*TemplateResultItem
}

type TemplateResultItem struct {
	WorkItemId string          `json:"work_item_id" mapstructure:"work_item_id"`
	Node       NodeInfo        `json:"node" mapstructure:"node"`
	ErrInfo    ProcessErr      `json:"err_info" mapstructure:"err_info"`
	Warnings   []WarningInfo   `json:"warnings,omitempty" mapstructure:"warnings"` // 警告信息列表
	Steps      []StepInfo      `json:"steps" mapstructure:"steps"`
	LBResult   LBProcessResult `json:"lb_result" mapstructure:"lb_result"`
}

type NodeInfo struct {
	Name string `json:"name" mapstructure:"name"`
	//NodeMapName string `json:"nodeMapName" mapstructure:"nodeMapName"`
	NodeType string `json:"node_type" mapstructure:"node_type"`
	CmdIp    string `json:"cmd_ip" mapstructure:"cmd_ip"`
}

type StepInfo struct {
	FirewallPhase string     `json:"firewall_phase" mapstructure:"firewall_phase"`
	PhaseAction   string     `json:"phase_action" mapstructure:"phase_action"`
	Phase         string     `json:"phase" mapstructure:"phase"`
	Cli           string     `json:"cli" mapstructure:"cli"`
	Result        StepResult `json:"result" mapstructure:"result"`
	Cmds          CmdInfo    `json:"cmds" mapstructure:"cmds"`
	Rule          string     `json:"rule" mapstructure:"rule"`
}

type CmdInfo struct {
	Cmds []string `json:"cmds" mapstructure:"cmds"`
	Ip   string   `json:"ip" mapstructure:"ip"`
	// Force bool     `json:"force" mapstructure:"force"`
}

type StepResult struct {
	Intent           string `json:"intent" mapstructure:"intent"`
	From             string `json:"from" mapstructure:"from"`
	Out              string `json:"out" mapstructure:"out"`
	Action           string `json:"action" mapstructure:"action"`
	MeetIntentStatus string `json:"meet_intent_status" mapstructure:"meet_intent_status"`
	Rule             string `json:"rule" mapstructure:"rule"`
}

type LBProcessResult struct {
	Virtual     string
	Partition   string
	Dst         string
	Dport       string
	Pool        string
	AutoMap     bool
	State       []string
	Nodes       []string
	RouteDomain string
	NodePort    string
	ErrMsg      string
}

// RouteTraceInfo 路由跟踪信息 - 用于返回给运维平台
type RouteTraceInfo struct {
	IntentID       string              `json:"intent_id"`
	Duration       time.Duration       `json:"duration"`
	StartTime      time.Time           `json:"start_time"`
	EndTime        time.Time           `json:"end_time"`
	RouteHops      []RouteHopInfo      `json:"route_hops"`
	RoutePath      string              `json:"route_path"`
	RouteDecisions []RouteDecisionInfo `json:"route_decisions"`
	ExitInfo       *ExitInfoAPI        `json:"exit_info"`
	NodesVisited   []string            `json:"nodes_visited"`
	DecisionCounts map[string]int      `json:"decision_counts"`
	Success        bool                `json:"success"`
	ErrorMessage   string              `json:"error_message,omitempty"`
}

// RouteHopInfo 路由跳信息 - API格式
type RouteHopInfo struct {
	InPort  string `json:"in_port"`
	Node    string `json:"node"`
	OutPort string `json:"out_port"`
}

// RouteDecisionInfo 路由决策信息 - API格式
type RouteDecisionInfo struct {
	Timestamp    time.Time         `json:"timestamp"`
	DecisionType string            `json:"decision_type"`
	Node         string            `json:"node"`
	Port         string            `json:"port"`
	VRF          string            `json:"vrf"`
	Area         string            `json:"area"`
	Criteria     map[string]string `json:"criteria"`
	Result       string            `json:"result"`
	Reason       string            `json:"reason"`
	Details      map[string]string `json:"details"`
}

// ExitInfoAPI 退出信息 - API格式
type ExitInfoAPI struct {
	Timestamp time.Time         `json:"timestamp"`
	Reason    string            `json:"reason"`
	Node      string            `json:"node"`
	Port      string            `json:"port"`
	VRF       string            `json:"vrf"`
	Details   map[string]string `json:"details"`
	Success   bool              `json:"success"`
	ErrorMsg  string            `json:"error_msg,omitempty"`
}

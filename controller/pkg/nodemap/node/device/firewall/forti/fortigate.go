package forti

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	v4 "github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common/v4"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/processor"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
)

var _ firewall.FirewallNode = &FortigateNode{}

type FortigateNode struct {
	// firewall.FirewallNode
	// api.Node
	*node.DeviceNode
	objectSet      *FortiObjectSet
	policySet      *PolicySet
	nats           *Nats
	tmpData        map[string]any
	snatDesignInfo []*config.SnatDesignInfo
	//matrix    *Matrix
}

func (fgn *FortigateNode) Type() terminalmode.DeviceType {
	return terminalmode.FortiGate
}

// TypeName 实现 TypeInterface 接口
func (fgn *FortigateNode) TypeName() string {
	return "FortigateNode"
}

// fortigateNodeJSON 用于序列化和反序列化
type fortigateNodeJSON struct {
	DeviceNode     json.RawMessage          `json:"device_node"`
	ObjectSet      *FortiObjectSet          `json:"object_set"`
	PolicySet      *PolicySet               `json:"policy_set"`
	Nats           *Nats                    `json:"nats"`
	TmpData        map[string]any           `json:"tmp_data"`
	SnatDesignInfo []*config.SnatDesignInfo `json:"snat_design_info"`
}

// MarshalJSON 实现 JSON 序列化
func (fgn *FortigateNode) MarshalJSON() ([]byte, error) {
	deviceNodeJSON, err := json.Marshal(fgn.DeviceNode)
	if err != nil {
		return nil, err
	}

	return json.Marshal(fortigateNodeJSON{
		DeviceNode:     deviceNodeJSON,
		ObjectSet:      fgn.objectSet,
		PolicySet:      fgn.policySet,
		Nats:           fgn.nats,
		TmpData:        fgn.tmpData,
		SnatDesignInfo: fgn.snatDesignInfo,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (fgn *FortigateNode) UnmarshalJSON(data []byte) error {
	var fgnj fortigateNodeJSON
	if err := json.Unmarshal(data, &fgnj); err != nil {
		return err
	}

	// 反序列化 DeviceNode
	var deviceNode *node.DeviceNode
	if err := json.Unmarshal(fgnj.DeviceNode, &deviceNode); err != nil {
		return err
	}
	fgn.DeviceNode = deviceNode

	fgn.objectSet = fgnj.ObjectSet
	fgn.policySet = fgnj.PolicySet
	fgn.nats = fgnj.Nats
	fgn.tmpData = fgnj.TmpData
	fgn.snatDesignInfo = fgnj.SnatDesignInfo

	return nil
}

func (fgn *FortigateNode) InputNat(intent *policy.Intent, inPort api.Port) processor.AbstractMatchResult {
	ok, translateTo, rule := fgn.nats.inputNat(intent, inPort)
	fmt.Println(ok, translateTo, rule)

	result := firewall.NewNatResultIntent(intent)
	result.WithTranslate(translateTo)
	result.WithFromPort(inPort)
	result.WithRule(rule)
	// result.WithMeetIntentStatus(meetStatus)
	if ok {
		result.WithAction(firewall.NAT_MATCHED)
	} else {
		result.WithAction(firewall.NAT_NOMATCHED)
	}

	result.Analysis()
	return result
}

func (fgn *FortigateNode) OutputNat(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	ok, translateTo, rule := fgn.nats.outputNat(intent, inPort, outPort)

	result := firewall.NewNatResultIntent(intent)
	result.WithFromPort(inPort)
	result.WithOutPort(outPort)
	result.WithTranslate(translateTo)
	result.WithRule(rule)
	// result.WithMeetIntentStatus(meetStatus)

	if ok {
		result.WithAction(firewall.NAT_MATCHED)
	} else {
		result.WithAction(firewall.NAT_NOMATCHED)
	}
	result.Analysis()
	return result
}

func (fgn *FortigateNode) InputPolicy(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	action, rule := fgn.policySet.InPacket(inPort, outPort, intent)
	result := firewall.NewPolicyResultIntent(intent)
	result.WithFromPort(inPort)
	result.WithOutPort(outPort)
	result.WithRule(rule)
	result.WithAction(action)

	return result
}

func (fgn *FortigateNode) OutputPolicy(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	result := firewall.NewPolicyResultIntent(intent)
	result.WithFromPort(inPort)
	result.WithOutPort(outPort)
	result.WithRule(nil)
	result.WithAction(firewall.POLICY_IMPLICIT_PERMIT)
	return result
}

func (fgn *FortigateNode) DefaultStep(fp *firewall.FirewallProcess) {
	fp.RemoveStep(firewall.OUTPUT_NAT.String())
	fp.WithInputPolicy()
	// fp.WithOutputPolicy()
}

func (fgn *FortigateNode) UpdateSnatStep(in, out api.Port, intent *policy.Intent, fp *firewall.FirewallProcess) {
	inPort := in.Name()
	outPort := out.Name()

	// 检查是否需要SNAT
	needSnat := false
	for _, snatInfo := range fgn.snatDesignInfo {
		if (snatInfo.From == inPort || snatInfo.From == "any") && (snatInfo.To == outPort || snatInfo.To == "any") {
			needSnat = true
			break
		}
	}

	if needSnat {
		// 如果需要SNAT，调用fp.WithOutputNat()
		fp.WithOutputNat()
	}
}

func (fgn *FortigateNode) GetObjectByNetworkGroup(ng *network.NetworkGroup, searchType firewall.ObjectSearchType, port api.Port) (firewall.FirewallNetworkObject, bool) {
	return fgn.objectSet.GetObjectByNetworkGroup(ng, searchType)
}

func (fgn *FortigateNode) GetObjectByService(s *service.Service, searchType firewall.ObjectSearchType) (firewall.FirewallServiceObject, bool) {
	return fgn.objectSet.GetObjectByService(s, searchType)
}

func (fgn *FortigateNode) GetPoolByNetworkGroup(ng *network.NetworkGroup, natType firewall.NatType) (firewall.FirewallNetworkObject, bool) {
	if fgn.nats == nil {
		return nil, false
	}
	for _, rule := range fgn.nats.DynamicRules {
		if rule.translate != nil && rule.translate.Src() != nil {
			if rule.translate.Src().MatchNetworkGroup(ng) {
				obj := &fortiGateNetwork{
					catagory: firewall.OBJECT_POOL,
					name:     rule.Name(),
					network:  ng,
				}
				return obj, true
			}
		}
	}
	return nil, false
}

// GetSupportedNatObjectTypes 获取该防火墙支持的NAT对象类型
// FortiGate: DNAT支持VIP/MIP（特殊语法vip），SNAT支持SNAT_POOL（特殊语法ippool）
func (fgn *FortigateNode) GetSupportedNatObjectTypes(natType string) []firewall.NatObjectType {
	if natType == "DNAT" {
		// VIP和MIP都使用特殊语法vip
		return []firewall.NatObjectType{firewall.VIP, firewall.MIP}
	}
	if natType == "SNAT" {
		// SNAT_POOL使用特殊语法ippool
		return []firewall.NatObjectType{firewall.SNAT_POOL, firewall.INTERFACE, firewall.INLINE}
	}
	return []firewall.NatObjectType{}
}

// GetObjectByVipMipSnatPool 检查VIP/MIP/SNAT_POOL对象是否已存在（复用检查）
// FortiGate: 支持VIP/MIP（config firewall vip）和SNAT_POOL（config firewall ippool）
func (fgn *FortigateNode) GetObjectByVipMipSnatPool(objectType string, intent *policy.Intent) (firewall.FirewallNetworkObject, bool) {
	if (objectType == "VIP" || objectType == "MIP") && intent.RealIp != "" {
		// VIP/MIP通过config firewall vip实现
		// 查找已存在的vip对象，匹配real_ip和real_port
		realIpNg, err := network.NewNetworkGroupFromString(intent.RealIp)
		if err == nil && fgn.nats != nil {
			// 遍历VipRules，查找匹配的
			for _, vipRule := range fgn.nats.VipRules {
				if vipRule.translate != nil && vipRule.translate.Dst() != nil {
					// 检查real_ip是否匹配
					if vipRule.translate.Dst().MatchNetworkGroup(realIpNg) {
						// 检查real_port是否匹配（仅VIP需要）
						if objectType == "VIP" && intent.RealPort != "" {
							// 需要检查端口是否匹配，这里简化处理
							// 实际实现可能需要从vipRule中提取端口信息
							// 创建一个包装器来将NatRule作为FirewallNetworkObject使用
							obj := &fortiGateNetwork{
								catagory: firewall.OBJECT_POOL,
								name:     vipRule.Name(),
								network:  realIpNg,
							}
							return obj, true
						} else if objectType == "MIP" && intent.RealPort == "" {
							// MIP不需要端口匹配
							obj := &fortiGateNetwork{
								catagory: firewall.OBJECT_POOL,
								name:     vipRule.Name(),
								network:  realIpNg,
							}
							return obj, true
						}
					}
				}
			}
		}
	}
	if objectType == "SNAT_POOL" && intent.Snat != "" {
		// SNAT_POOL通过config firewall ippool实现
		// 通过GetPoolByNetworkGroup查找（已经在DynamicRules中）
		snatNg, err := network.NewNetworkGroupFromString(intent.Snat)
		if err == nil {
			return fgn.GetPoolByNetworkGroup(snatNg, firewall.DYNAMIC_NAT)
		}
	}
	return nil, false
}

// GenerateVipMipSnatPoolName 自动生成VIP/MIP/SNAT_POOL对象名称（可选）
// FortiGate: 不提供自动命名，返回空字符串使用配置模板
func (fgn *FortigateNode) GenerateVipMipSnatPoolName(objectType string, intent *policy.Intent, metaData map[string]interface{}) string {
	// FortiGate不提供自动命名，返回空字符串使用配置模板
	return ""
}

// GetReuseNatObject 获取可重用的NAT对象名称
// FortiGate:
//   - DNAT: 根据dnat_object_type配置，可能使用VIP或MIP
//   - SNAT: 根据snat_object_type配置，可能使用SNAT_POOL、INTERFACE或INLINE
//
// 通过natType和metaData配置来决定objectType，然后进行复用查询
func (fgn *FortigateNode) GetReuseNatObject(natType string, intent *policy.Intent, metaData map[string]interface{}) (name string, reused bool) {
	// 根据natType和metaData确定objectType
	// 对于DNAT和SNAT，一定会命中一种防火墙支持的对象类型清单，同时结合metaData中的配置，最终选择一种对象类型
	objectType, ok := fgn.DetermineNatObjectType(natType, metaData)
	if !ok {
		return "", false
	}

	// INTERFACE/INLINE 类型不需要生成对象，直接返回
	if objectType == firewall.INTERFACE || objectType == firewall.INLINE {
		return "", false
	}

	// 根据objectType进行复用查询
	if objectType == firewall.VIP {
		// VIP: 通过VipRules查找（仅适用于DNAT）
		// VIP需要real_ip和real_port都匹配
		realIpNg, err := network.NewNetworkGroupFromString(intent.RealIp)
		if err == nil && fgn.nats != nil {
			// 遍历VipRules，查找匹配的
			for _, vipRule := range fgn.nats.VipRules {
				if vipRule.translate != nil && vipRule.translate.Dst() != nil {
					// 检查real_ip是否匹配
					if vipRule.translate.Dst().MatchNetworkGroup(realIpNg) {
						// VIP需要检查端口，这里简化处理，如果real_ip匹配就认为可以复用
						// 实际实现可能需要从vipRule中提取端口信息进行精确匹配
						return vipRule.Name(), true
					}
				}
			}
		}

	} else if objectType == firewall.MIP {
		// MIP: 通过VipRules查找（仅适用于DNAT）
		// MIP只需要real_ip匹配，不需要real_port
		realIpNg, err := network.NewNetworkGroupFromString(intent.RealIp)
		if err == nil && fgn.nats != nil {
			// 遍历VipRules，查找匹配的
			for _, vipRule := range fgn.nats.VipRules {
				if vipRule.translate != nil && vipRule.translate.Dst() != nil {
					// 检查real_ip是否匹配
					if vipRule.translate.Dst().MatchNetworkGroup(realIpNg) {
						// MIP不需要端口匹配
						return vipRule.Name(), true
					}
				}
			}

		}
	} else if objectType == firewall.SNAT_POOL {
		// SNAT_POOL: 通过GetPoolByNetworkGroup查找（仅适用于SNAT）
		snatNg, err := network.NewNetworkGroupFromString(intent.Snat)
		if err == nil {
			obj, found := fgn.GetPoolByNetworkGroup(snatNg, firewall.DYNAMIC_NAT)
			if found {
				return obj.Name(), true
			}
		}

	}

	return "", false
}

// determineNatObjectType 根据natType和metaData确定NAT对象类型
// 所有选择都必须基于设备支持作为前提
// 对于DNAT和SNAT，一定会命中一种防火墙支持的对象类型清单，同时结合metaData中的配置，最终选择一种对象类型
func (fgn *FortigateNode) DetermineNatObjectType(natType string, metaData map[string]interface{}) (firewall.NatObjectType, bool) {
	if natType == "DNAT" {
		// FortiGate的DNAT支持VIP和MIP（都使用特殊语法vip）
		objectType := getStringFromMeta(metaData, "dnat_object_type", "VIP")
		if objectType == "VIP" {
			return firewall.VIP, true
		} else if objectType == "MIP" {
			return firewall.MIP, true
		}
		// 默认返回VIP
		return firewall.UNSUPPORTED, false
	} else if natType == "SNAT" {
		objectType := getStringFromMeta(metaData, "snat_object_type", "SNAT_POOL")
		if objectType == "SNAT_POOL" {
			return firewall.SNAT_POOL, true
		}
		// 默认返回SNAT_POOL
	}
	return firewall.UNSUPPORTED, false
}

// getStringFromMeta 从metaData中获取字符串值
func getStringFromMeta(metaData map[string]interface{}, key, defaultValue string) string {
	if metaData == nil {
		return defaultValue
	}
	if v, ok := metaData[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultValue
}

func (fgn *FortigateNode) Network(zone, name string) (*network.NetworkGroup, bool) {
	return fgn.objectSet.Network(zone, name)
}

func (fgn *FortigateNode) Service(name string) (*service.Service, bool) {
	return fgn.objectSet.Service(name)
}

func (fgn *FortigateNode) L4Port(name string) (*service.L4Port, bool) {
	return nil, false
}

// NextPoolId 返回下一个可用的 IP Pool ID
// FortiGate 使用名称而不是数字 ID，所以返回一个基于名称的 ID
func (fgn *FortigateNode) NextPoolId(id string) string {
	// 如果提供了 id，直接返回
	if id != "" {
		return id
	}

	// FortiGate 使用名称而不是数字 ID
	// 返回一个基于时间戳或递增数字的名称
	// 这里返回一个简单的递增数字，从 1 开始
	maxId := 0

	// 检查现有的 Dynamic NAT 规则（IP Pool）
	for _, rule := range fgn.nats.DynamicRules {
		// 尝试从名称中提取数字 ID
		name := rule.Name()
		// 如果名称包含数字，尝试提取
		// 例如 "SNAT_1", "pool_2" 等
		// 这里简化处理，假设名称格式为 "pool_N" 或类似格式
		// 实际实现可能需要更复杂的解析逻辑
		if len(name) > 0 {
			// 尝试提取名称中的数字部分
			// 这里简化处理，返回一个基于现有规则数量的 ID
			maxId++
		}
	}

	// 返回下一个可用的 ID（从 1 开始）
	return fmt.Sprintf("%d", maxId+1)
}

func (fgn *FortigateNode) HasObjectName(name string) bool {
	if _, ok := fgn.Network("", name); ok {
		return true
	}

	if _, ok := fgn.Service(name); ok {
		return true
	}

	_, ok := fgn.L4Port(name)
	return ok
}

func (fgn *FortigateNode) HasPolicyName(name string) bool {
	_, ok := fgn.policySet.policySet[name]
	return ok
}

// GetPolicyName 获取策略名称（FortiGate使用命名模板，返回空字符串）
func (fgn *FortigateNode) GetPolicyName(ctx *firewall.PolicyContext) (string, error) {
	// FortiGate使用命名模板生成策略名称，返回空字符串让模板系统使用命名模板
	return "", nil
}

func (fgn *FortigateNode) HasNatName(name string) bool {
	for _, n := range fgn.nats.VipRules {
		if n.name == name {
			return true
		}
	}
	return false
}

func (fgn *FortigateNode) HasPoolName(name string) bool {
	for _, n := range fgn.nats.DynamicRules {
		if n.name == name {
			return true
		}
	}
	return false
}

func (fgn *FortigateNode) InputNatTargetCheck(intent *policy.Intent, inPort, outPort api.Port) (bool, firewall.FirewallNatRule) {
	return fgn.nats.inputNatTargetCheck(intent, inPort, outPort)
}

func (fgn *FortigateNode) MakeStaticNatCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (interface{}, command.CmdList) {
	// 使用 v4 版本（Starlark 模板）
	templates, err := v4.NewCommonTemplatesV4(fgn, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(fgn.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if fgn.DeviceNode != nil {
		deviceConfig := fgn.DeviceNode.GetDeviceConfig()
		if deviceConfig != nil {
			for k, v := range deviceConfig.MetaData {
				metaData[k] = v
			}
		}
	}

	// 设置 ticket 信息
	metaData["ticket_number"] = intent.TicketNumber
	metaData["sub_ticket"] = intent.SubTicket

	// 调用 v4 的 MakeNatPolicyV4 (DNAT, isInputNat=true)
	result, err := templates.MakeNatPolicyV4(from, out, intent, ctx, metaData)
	if err != nil {
		// 如果出错，返回空结果
		cmdList := command.NewCliCmdList(fgn.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromNatResultV4(fgn, result)
}

func (fgn *FortigateNode) MakeDynamicNatCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (interface{}, command.CmdList) {
	// 使用 v4 版本（Starlark 模板）
	templates, err := v4.NewCommonTemplatesV4(fgn, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(fgn.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if fgn.DeviceNode != nil {
		deviceConfig := fgn.DeviceNode.GetDeviceConfig()
		if deviceConfig != nil {
			for k, v := range deviceConfig.MetaData {
				metaData[k] = v
			}
		}
	}

	// 设置 ticket 信息
	metaData["ticket_number"] = intent.TicketNumber
	metaData["sub_ticket"] = intent.SubTicket

	// 调用 v4 的 MakeNatPolicyV4 (SNAT, isInputNat=false)
	result, err := templates.MakeNatPolicyV4(from, out, intent, ctx, metaData)
	if err != nil {
		// 如果出错，返回空结果
		cmdList := command.NewCliCmdList(fgn.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromNatResultV4(fgn, result)
}

func (fgn *FortigateNode) MakeInputPolicyCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (interface{}, command.CmdList, []string) {
	// 使用 v4 版本（Starlark 模板）
	// 从 PolicyContext 获取模板路径，如果没有则使用默认路径
	templatePath := firewall.GetTemplatePath(ctx)
	templates, err := v4.NewCommonTemplatesV4(fgn, templatePath, nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(fgn.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList, nil
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if fgn.DeviceNode != nil {
		deviceConfig := fgn.DeviceNode.GetDeviceConfig()
		if deviceConfig != nil {
			for k, v := range deviceConfig.MetaData {
				metaData[k] = v
			}
		}
	}

	if intent.MetaData != nil {
		for k, v := range intent.MetaData {
			metaData[k] = v
		}
	}

	// 设置 ticket 信息
	metaData["ticket_number"] = intent.TicketNumber
	metaData["sub_ticket"] = intent.SubTicket

	// 调用 v4 的 MakePolicyV4
	result, err := templates.MakePolicyV4(from, out, intent, ctx, metaData)
	if err != nil {
		// 如果出错，返回空结果
		cmdList := command.NewCliCmdList(fgn.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList, nil
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromPolicyResultV4(fgn, result), nil
}

func (fgn *FortigateNode) MakeOutputPolicyCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (interface{}, command.CmdList) {
	// FortiGate uses the same policy for input and output, use v4 for consistency
	// 使用 v4 版本（Starlark 模板）
	// 从 PolicyContext 获取模板路径，如果没有则使用默认路径
	templatePath := firewall.GetTemplatePath(ctx)
	templates, err := v4.NewCommonTemplatesV4(fgn, templatePath, nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(fgn.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if fgn.DeviceNode != nil {
		deviceConfig := fgn.DeviceNode.GetDeviceConfig()
		if deviceConfig != nil {
			for k, v := range deviceConfig.MetaData {
				metaData[k] = v
			}
		}
	}

	// 设置 ticket 信息
	metaData["ticket_number"] = intent.TicketNumber
	metaData["sub_ticket"] = intent.SubTicket

	// 调用 v4 的 MakePolicyV4
	result, err := templates.MakePolicyV4(from, out, intent, ctx, metaData)
	if err != nil {
		// 如果出错，返回空结果
		cmdList := command.NewCliCmdList(fgn.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromPolicyResultV4(fgn, result)
}

// createCmdListFromNatResultV4 从 v4 的 NatPolicyResult 创建 command.CmdList
func createCmdListFromNatResultV4(fgn *FortigateNode, result *v4.NatPolicyResult) command.CmdList {
	cmdList := command.NewCliCmdList(fgn.DeviceNode.CmdIp(), true)

	// 合并 FlyObject 到 CLIString
	mergedCLI := result.CLIString
	if len(result.FlyObject) > 0 {
		var builder strings.Builder
		keys := []string{"NETWORK", "VIP", "MIP", "SERVICE", "POOL", "NAT"}
		for _, key := range keys {
			if v, ok := result.FlyObject[key]; ok && v != "" {
				builder.WriteString(v)
				builder.WriteString("\n")
			}
		}
		if builder.Len() > 0 {
			mergedCLI = strings.TrimSpace(builder.String())
		}
	}

	if mergedCLI != "" {
		cmdList.AddCmd(command.NewCliCmd(mergedCLI, "", 1, true))
	}

	return cmdList
}

// createCmdListFromPolicyResultV4 从 v4 的 PolicyResult 创建 command.CmdList
func createCmdListFromPolicyResultV4(fgn *FortigateNode, result *v4.PolicyResult) command.CmdList {
	cmdList := command.NewCliCmdList(fgn.DeviceNode.CmdIp(), true)

	// 合并 FlyObject 到 CLIString
	mergedCLI := result.CLIString
	if len(result.FlyObject) > 0 {
		var builder strings.Builder
		keys := []string{"NETWORK", "SERVICE", "SECURITY_POLICY"}
		for _, key := range keys {
			if v, ok := result.FlyObject[key]; ok && v != "" {
				builder.WriteString(v)
				builder.WriteString("\n")
			}
		}
		if builder.Len() > 0 {
			mergedCLI = strings.TrimSpace(builder.String())
		}
	}

	if mergedCLI != "" {
		cmdList.AddCmd(command.NewCliCmd(mergedCLI, "", 1, true))
	}

	return cmdList
}

func (fng *FortigateNode) Policies() []firewall.FirewallPolicy {
	policies := []firewall.FirewallPolicy{}
	for _, p := range fng.policySet.policySet {
		policies = append(policies, p)
	}

	return policies
}

package asa

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

var _ firewall.FirewallNode = &ASANode{}

type ASANode struct {
	// firewall.FirewallNode
	// api.Node
	*node.DeviceNode
	objectSet      *ASAObjectSet
	policySet      *PolicySet
	nats           *Nats
	matrix         *Matrix
	snatDesignInfo []*config.SnatDesignInfo
}

func (asa *ASANode) TypeName() string {
	return "ASANode"
}

// asaNodeJSON 用于序列化和反序列化
type asaNodeJSON struct {
	DeviceNode     json.RawMessage `json:"device_node"`
	ObjectSet      json.RawMessage `json:"object_set"`
	PolicySet      json.RawMessage `json:"policy_set"`
	Nats           json.RawMessage `json:"nats"`
	Matrix         json.RawMessage `json:"matrix"`
	SnatDesignInfo json.RawMessage `json:"snat_design_info"`
}

// MarshalJSON 实现 JSON 序列化
func (asa *ASANode) MarshalJSON() ([]byte, error) {
	deviceNode, err := json.Marshal(asa.DeviceNode)
	if err != nil {
		return nil, err
	}

	objectSet, err := json.Marshal(asa.objectSet)
	if err != nil {
		return nil, err
	}

	policySet, err := json.Marshal(asa.policySet)
	if err != nil {
		return nil, err
	}

	nats, err := json.Marshal(asa.nats)
	if err != nil {
		return nil, err
	}

	matrix, err := json.Marshal(asa.matrix)
	if err != nil {
		return nil, err
	}

	snatDesignInfo, err := json.Marshal(asa.snatDesignInfo)
	if err != nil {
		return nil, err
	}

	return json.Marshal(asaNodeJSON{
		DeviceNode:     deviceNode,
		ObjectSet:      objectSet,
		PolicySet:      policySet,
		Nats:           nats,
		Matrix:         matrix,
		SnatDesignInfo: snatDesignInfo,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (asa *ASANode) UnmarshalJSON(data []byte) error {
	var asaj asaNodeJSON
	if err := json.Unmarshal(data, &asaj); err != nil {
		return err
	}

	if err := json.Unmarshal(asaj.DeviceNode, &asa.DeviceNode); err != nil {
		return err
	}

	asa.objectSet = &ASAObjectSet{}
	if err := json.Unmarshal(asaj.ObjectSet, asa.objectSet); err != nil {
		return err
	}

	asa.policySet = &PolicySet{}
	if err := json.Unmarshal(asaj.PolicySet, asa.policySet); err != nil {
		return err
	}

	asa.nats = &Nats{}
	if err := json.Unmarshal(asaj.Nats, asa.nats); err != nil {
		return err
	}

	asa.matrix = &Matrix{}
	if err := json.Unmarshal(asaj.Matrix, asa.matrix); err != nil {
		return err
	}

	return json.Unmarshal(asaj.SnatDesignInfo, &asa.snatDesignInfo)
}

func (asa *ASANode) Type() terminalmode.DeviceType {
	return terminalmode.ASA
}

func (asa *ASANode) InputNat(intent *policy.Intent, inPort api.Port) processor.AbstractMatchResult {
	ok, translateTo, rule := asa.nats.inputNat(intent, inPort)
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

func (asa *ASANode) OutputNat(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	ok, translateTo, rule := asa.nats.outputNat(intent, inPort, outPort)

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

func (asa *ASANode) InputPolicy(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	action, rule := asa.matrix.InPacket(inPort, outPort, intent)
	result := firewall.NewPolicyResultIntent(intent)
	result.WithFromPort(inPort)
	result.WithOutPort(outPort)
	result.WithRule(rule)
	result.WithAction(action)

	return result
}

func (asa *ASANode) OutputPolicy(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	action, rule := asa.matrix.OutPacket(inPort, outPort, intent)
	result := firewall.NewPolicyResultIntent(intent)
	result.WithFromPort(inPort)
	result.WithOutPort(outPort)
	result.WithRule(rule)
	result.WithAction(action)

	return result
}

func (asa *ASANode) DefaultStep(fp *firewall.FirewallProcess) {
	fp.WithInputPolicy()
	fp.WithOutputPolicy()
}

func (asa *ASANode) UpdateSnatStep(in, out api.Port, intent *policy.Intent, fp *firewall.FirewallProcess) {
	inPort := in.(*ASAPort).Name()
	outPort := out.(*ASAPort).Name()

	// 检查是否需要SNAT
	needSnat := false
	for _, snatInfo := range asa.snatDesignInfo {
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

func (asa *ASANode) GetPoolByeNetworkGroup(ng *network.NetworkGroup, natType firewall.NatType) (firewall.FirewallNetworkObject, bool) {
	return nil, false
}

func (asa *ASANode) GetObjectByNetworkGroup(ng *network.NetworkGroup, searchType firewall.ObjectSearchType, port api.Port) (firewall.FirewallNetworkObject, bool) {
	return asa.objectSet.GetObjectByNetworkGroup(ng, searchType)
}

func (asa *ASANode) GetObjectByService(s *service.Service, searchType firewall.ObjectSearchType) (firewall.FirewallServiceObject, bool) {
	return asa.objectSet.GetObjectByService(s, searchType)
}

func (asa *ASANode) GetPoolByNetworkGroup(ng *network.NetworkGroup, natType firewall.NatType) (firewall.FirewallNetworkObject, bool) {
	return nil, false
}

// GetSupportedNatObjectTypes 获取该防火墙支持的NAT对象类型
// ASA: DNAT支持VIP/MIP（NetworkObject），SNAT支持SNAT_POOL（NetworkObject）
func (asa *ASANode) GetSupportedNatObjectTypes(natType string) []firewall.NatObjectType {
	if natType == "DNAT" {
		// VIP和MIP都使用NetworkObject
		return []firewall.NatObjectType{firewall.NETWORK_OBJECT}
	}
	if natType == "SNAT" {
		// SNAT_POOL支持多种类型
		return []firewall.NatObjectType{firewall.NETWORK_OBJECT, firewall.INTERFACE, firewall.INLINE}
	}
	return []firewall.NatObjectType{}
}

// GetObjectByVipMipSnatPool 检查VIP/MIP/SNAT_POOL对象是否已存在（复用检查）
// ASA: 不支持VIP/MIP/SNAT_POOL对象
func (asa *ASANode) GetObjectByVipMipSnatPool(objectType string, intent *policy.Intent) (firewall.FirewallNetworkObject, bool) {
	// ASA不支持VIP/MIP/SNAT_POOL对象
	return nil, false
}

// GenerateVipMipSnatPoolName 自动生成VIP/MIP/SNAT_POOL对象名称（可选）
// ASA: 不提供自动命名，返回空字符串使用配置模板
func (asa *ASANode) GenerateVipMipSnatPoolName(objectType string, intent *policy.Intent, metaData map[string]interface{}) string {
	// ASA不提供自动命名，返回空字符串使用配置模板
	return ""
}

// GetReuseNatObject 获取可重用的NAT对象名称
// ASA: VIP/MIP/SNAT_POOL都使用network object
//
// 通过natType和metaData配置来决定objectType，然后进行复用查询
func (asa *ASANode) GetReuseNatObject(natType string, intent *policy.Intent, metaData map[string]interface{}) (name string, reused bool) {
	// 根据natType和metaData确定objectType
	// 对于DNAT和SNAT，一定会命中一种防火墙支持的对象类型清单，同时结合metaData中的配置，最终选择一种对象类型
	objectType, ok := asa.DetermineNatObjectType(natType, metaData)
	if !ok {
		return "", false
	}

	// INTERFACE/INLINE 类型不需要生成对象，直接返回
	if objectType == firewall.INTERFACE || objectType == firewall.INLINE {
		return "", false
	}

	// 根据objectType进行复用查询
	// ASA的VIP/MIP/SNAT_POOL都使用network object
	if objectType == firewall.NETWORK_OBJECT {
		if natType == "DNAT" && intent.RealIp != "" {
			realIpNg, err := network.NewNetworkGroupFromString(intent.RealIp)
			if err == nil {
				obj, found := asa.GetObjectByNetworkGroup(realIpNg, firewall.SEARCH_OBJECT_OR_GROUP, nil)
				if found {
					return obj.Name(), true
				}
			}
		}
		if natType == "SNAT" && intent.Snat != "" {
			snatNg, err := network.NewNetworkGroupFromString(intent.Snat)
			if err == nil {
				obj, found := asa.GetObjectByNetworkGroup(snatNg, firewall.SEARCH_OBJECT_OR_GROUP, nil)
				if found {
					return obj.Name(), true
				}
			}
		}
	}

	return "", false
}

// determineNatObjectType 根据natType和metaData确定NAT对象类型
// 所有选择都必须基于设备支持作为前提
// 对于DNAT和SNAT，一定会命中一种防火墙支持的对象类型清单，同时结合metaData中的配置，最终选择一种对象类型
// TwiceNat的源转换支持NETWORK_OBJECT和INTERFACE，目标转换支持NETWORK_OBJECT
// ObjectNat的源转换支持NETWORK_OBJECT和INLINE
func (asa *ASANode) DetermineNatObjectType(natType string, metaData map[string]interface{}) (firewall.NatObjectType, bool) {
	switch natType {
	case "DNAT":
		objectType := getStringFromMeta(metaData, "dnat_object_type", "NETWORK_OBJECT")
		if objectType == "NETWORK_OBJECT" {
			return firewall.NETWORK_OBJECT, true
		}
		return firewall.UNSUPPORTED, false
	case "SNAT":
		// ASA的SNAT支持NETWORK_OBJECT、INTERFACE和INLINE
		objectType := getStringFromMeta(metaData, "snat_object_type", "NETWORK_OBJECT")
		switch objectType {
		case "NETWORK_OBJECT":
			return firewall.NETWORK_OBJECT, true
		case "INTERFACE":
			return firewall.INTERFACE, true
		case "INLINE":
			return firewall.INLINE, true
		}
		// 默认返回NETWORK_OBJECT
		return firewall.NETWORK_OBJECT, true
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

func (asa *ASANode) Network(zone, name string) (*network.NetworkGroup, bool) {
	n, _, ok := asa.objectSet.Network(zone, name)
	return n, ok
}

func (asa *ASANode) Service(name string) (*service.Service, bool) {
	s, _, ok := asa.objectSet.Service(name)
	return s, ok
}

func (asa *ASANode) L4Port(name string) (*service.L4Port, bool) {
	return asa.objectSet.L4Port(name)
}

func (asa *ASANode) HasObjectName(name string) bool {
	_, ok := asa.Network("", name)
	if ok {
		return true
	}

	_, ok = asa.Service(name)
	if ok {
		return true
	}

	_, ok = asa.L4Port(name)
	if ok {
		return true
	}

	return false
}

func (asa *ASANode) HasPolicyName(name string) bool {
	return false
}

func (asa *ASANode) HasNatName(name string) bool {
	return false
}

func (asa *ASANode) HasPoolName(name string) bool {
	return false
}

func (asa *ASANode) NextPoolId(id string) string {
	// 如果提供了 id，直接返回
	if id != "" {
		return id
	}
	// ASA 可能没有 pool ID 管理机制，返回一个默认值
	// 如果需要，可以从 nats 或其他地方获取下一个可用的 ID
	// 目前返回 "1"，表示第一个 pool
	return "1"
}

func (asa *ASANode) InputNatTargetCheck(intent *policy.Intent, inPort, outPort api.Port) (bool, firewall.FirewallNatRule) {
	return asa.nats.inputNatTargetCheck(intent, inPort, outPort)
}

func (asa *ASANode) MakeStaticNatCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (interface{}, command.CmdList) {
	// 使用 v4 版本（Starlark 模板）
	templates, err := v4.NewCommonTemplatesV4(asa, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(asa.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if asa.DeviceNode != nil {
		deviceConfig := asa.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(asa.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromNatResultV4(asa, result)
}

func (asa *ASANode) MakeDynamicNatCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (interface{}, command.CmdList) {
	// 使用 v4 版本（Starlark 模板）
	templates, err := v4.NewCommonTemplatesV4(asa, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(asa.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if asa.DeviceNode != nil {
		deviceConfig := asa.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(asa.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromNatResultV4(asa, result)
}

func (asa *ASANode) MakeInputPolicyCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (interface{}, command.CmdList, []string) {
	// 使用 v4 版本（Starlark 模板）
	// 从 PolicyContext 获取模板路径，如果没有则使用默认路径
	templatePath := firewall.GetTemplatePath(ctx)
	templates, err := v4.NewCommonTemplatesV4(asa, templatePath, nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(asa.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList, nil
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if asa.DeviceNode != nil {
		deviceConfig := asa.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(asa.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList, nil
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromPolicyResultV4(asa, result), nil
}

func (asa *ASANode) MakeOutputPolicyCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (interface{}, command.CmdList) {
	// ASA uses ACL for output policy, similar to input policy
	// 使用 v4 版本（Starlark 模板）
	// 从 PolicyContext 获取模板路径，如果没有则使用默认路径
	templatePath := firewall.GetTemplatePath(ctx)
	templates, err := v4.NewCommonTemplatesV4(asa, templatePath, nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(asa.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if asa.DeviceNode != nil {
		deviceConfig := asa.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(asa.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromPolicyResultV4(asa, result)
}

func (asa *ASANode) Policies() []firewall.FirewallPolicy {
	policies := []firewall.FirewallPolicy{}
	for _, list := range asa.policySet.policySet {
		for _, policy := range list {
			policies = append(policies, policy)
		}
	}

	return policies
}

// GetPolicyName 实现FirewallNode接口，返回策略名称
// ASA使用命名模板，所以返回空字符串表示使用模板生成
func (asa *ASANode) GetPolicyName(ctx *firewall.PolicyContext) (string, error) {
	// ASA使用命名模板生成策略名称，返回空字符串表示使用模板
	return "", nil
}

// createCmdListFromNatResultV4 从 v4 的 NatPolicyResult 创建 command.CmdList
func createCmdListFromNatResultV4(asa *ASANode, result *v4.NatPolicyResult) command.CmdList {
	cmdList := command.NewCliCmdList(asa.DeviceNode.CmdIp(), true)

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
func createCmdListFromPolicyResultV4(asa *ASANode, result *v4.PolicyResult) command.CmdList {
	cmdList := command.NewCliCmdList(asa.DeviceNode.CmdIp(), true)

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

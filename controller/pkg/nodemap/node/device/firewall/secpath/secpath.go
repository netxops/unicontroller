package secpath

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	v4 "github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/common/v4"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/utils/registry"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/processor"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"

	"gorm.io/gorm"
)

var _ firewall.FirewallNode = &SecPathNode{}
var _ firewall.IteratorFirewall = &SecPathNode{}

const (
	RetryMethodNext   = "next"
	RetryMethodSuffix = "suffix"
)

const (
	StaticOutbound    = "static_outbound"
	StaticInbound     = "static_inbound"
	StaticInOut       = "static_inout"
	DynamicOutbound   = "dynamic_outbound"
	PolicyBaseSnat    = "policy_base_snat"
	PolicyBaseDnat    = "policy_base_dnat"
	ServiceObject     = "service_object"
	SourceObject      = "source_object"
	DestinationObject = "destination_object"
)

type SecPathNode struct {
	*node.DeviceNode
	AclSet         *ACLSet                  `json:"acl_set"`
	ObjectSet      *SecPathObjectSet        `json:"object_set"`
	PolicySet      *PolicySet               `json:"policy_set"`
	Nats           *Nats                    `json:"nats"`
	SnatDesignInfo []*config.SnatDesignInfo `json:"snat_design_info"`
	NatPreference  map[string]string        `json:"nat_preference"`
}

func (secpath *SecPathNode) SetNATPreference(natType, preference string) {
	if secpath.NatPreference == nil {
		secpath.NatPreference = make(map[string]string)
	}
	secpath.NatPreference[natType] = preference
}

func (secpath *SecPathNode) Type() terminalmode.DeviceType {
	return terminalmode.SecPath
}

// GetPolicyName 获取策略名称（SecPath使用命名模板，返回空字符串）
func (secpath *SecPathNode) GetPolicyName(ctx *firewall.PolicyContext) (string, error) {
	return "", nil
}

// TypeName 实现 TypeInterface 接口
func (spn *SecPathNode) TypeName() string {
	return "SecPathNode"
}

// secPathNodeJSON 用于序列化和反序列化
type secPathNodeJSON struct {
	DeviceNode     json.RawMessage          `json:"device_node"`
	AclSet         *ACLSet                  `json:"acl_set"`
	ObjectSet      *SecPathObjectSet        `json:"object_set"`
	PolicySet      *PolicySet               `json:"policy_set"`
	Nats           *Nats                    `json:"nats"`
	SnatDesignInfo []*config.SnatDesignInfo `json:"snat_design_info"`
	NatPreference  map[string]string        `json:"nat_preference"`
}

// MarshalJSON 实现 JSON 序列化
func (spn *SecPathNode) MarshalJSON() ([]byte, error) {
	deviceNodeJSON, err := json.Marshal(spn.DeviceNode)
	if err != nil {
		return nil, err
	}

	return json.Marshal(secPathNodeJSON{
		DeviceNode:     deviceNodeJSON,
		AclSet:         spn.AclSet,
		ObjectSet:      spn.ObjectSet,
		PolicySet:      spn.PolicySet,
		Nats:           spn.Nats,
		SnatDesignInfo: spn.SnatDesignInfo,
		NatPreference:  spn.NatPreference,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (spn *SecPathNode) UnmarshalJSON(data []byte) error {
	var spnj secPathNodeJSON
	if err := json.Unmarshal(data, &spnj); err != nil {
		return err
	}

	if err := json.Unmarshal(spnj.DeviceNode, &spn.DeviceNode); err != nil {
		return err
	}

	spn.AclSet = spnj.AclSet
	spn.ObjectSet = spnj.ObjectSet
	spn.PolicySet = spnj.PolicySet
	spn.Nats = spnj.Nats
	spn.SnatDesignInfo = spnj.SnatDesignInfo
	spn.NatPreference = spnj.NatPreference

	// 重新建立对象之间的关系
	if spn.AclSet != nil {
		spn.AclSet.objects = spn.ObjectSet
	}
	if spn.ObjectSet != nil {
		spn.ObjectSet.node = spn
	}
	if spn.PolicySet != nil {
		spn.PolicySet.node = spn
		spn.PolicySet.objects = spn.ObjectSet
	}
	if spn.Nats != nil {
		spn.Nats.node = spn
		spn.Nats.objects = spn.ObjectSet
	}

	// 重新建立策略和NAT规则的关系
	if spn.PolicySet != nil {
		for _, plc := range spn.PolicySet.securityPolicyAcl {
			plc.node = spn
			plc.objects = spn.ObjectSet
		}
	}

	if spn.Nats != nil {
		totalNats := [][]*NatRule{
			spn.Nats.natPolicy,
			spn.Nats.inboundStatic,
			spn.Nats.natServer,
			spn.Nats.natGlobalPolicy,
			spn.Nats.outboundStatic,
			spn.Nats.outboundDynamic,
		}

		for _, nats := range totalNats {
			for _, nat := range nats {
				nat.node = spn
				nat.objects = spn.ObjectSet
			}
		}
	}

	return nil
}

// secPathNodeJSON 用于序列化和反序列化
// type secPathNodeJSON struct {
// 	DeviceNode     json.RawMessage          `json:"device_node"`
// 	ACLSet         *ACLSet                  `json:"acl_set"`
// 	ObjectSet      *SecPathObjectSet        `json:"object_set"`
// 	PolicySet      *PolicySet               `json:"policy_set"`
// 	Nats           *Nats                    `json:"nats"`
// 	SNATDesignInfo []*config.SnatDesignInfo `json:"snat_design_info"`
// 	NATPreference  map[string]string        `json:"nat_preference"`
// }

// // MarshalJSON 实现 JSON 序列化
// func (spn *SecPathNode) MarshalJSON() ([]byte, error) {
// 	deviceNodeJSON, err := json.Marshal(spn.DeviceNode)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return json.Marshal(secPathNodeJSON{
// 		DeviceNode:     deviceNodeJSON,
// 		ACLSet:         spn.aclSet,
// 		ObjectSet:      spn.objectSet,
// 		PolicySet:      spn.policySet,
// 		Nats:           spn.nats,
// 		SNATDesignInfo: spn.snatDesignInfo,
// 		NATPreference:  spn.natPreference,
// 	})
// }

// // UnmarshalJSON 实现 JSON 反序列化
// func (spn *SecPathNode) UnmarshalJSON(data []byte) error {
// 	var spnj secPathNodeJSON
// 	if err := json.Unmarshal(data, &spnj); err != nil {
// 		return err
// 	}

// 	if err := json.Unmarshal(spnj.DeviceNode, &spn.DeviceNode); err != nil {
// 		return err
// 	}

// 	spn.aclSet = spnj.ACLSet
// 	spn.objectSet = spnj.ObjectSet
// 	spn.policySet = spnj.PolicySet
// 	spn.nats = spnj.Nats
// 	spn.snatDesignInfo = spnj.SNATDesignInfo
// 	spn.natPreference = spnj.NATPreference
// 	spn.aclSet.objects = spn.objectSet
// 	spn.objectSet.node = spn
// 	spn.policySet.node = spn
// 	spn.policySet.objects = spn.objectSet
// 	spn.nats.node = spn
// 	spn.nats.objects = spn.objectSet

// 	for _, plc := range spn.policySet.securityPolicyAcl {
// 		plc.node = spn
// 		plc.objects = spn.objectSet
// 	}

// 	totalNats := [][]*NatRule{
// 		spn.nats.natPolicy,
// 		spn.nats.inboundStatic,
// 		spn.nats.natServer,
// 		spn.nats.natGlobalPolicy,
// 		spn.nats.outboundStatic,
// 		spn.nats.outboundDynamic,
// 	}

// 	for _, nats := range totalNats {
// 		for _, nat := range nats {
// 			nat.node = spn
// 			nat.objects = spn.objectSet
// 		}
// 	}

// 	return nil
// }

func (secpath *SecPathNode) InputNat(intent *policy.Intent, inPort api.Port) processor.AbstractMatchResult {
	ok, translateTo, rule := secpath.Nats.inputNat(inPort, intent)

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

func (secpath *SecPathNode) OutputNat(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	ok, translateTo, rule := secpath.Nats.outputNat(inPort, outPort, intent)

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

func (secpath *SecPathNode) InputPolicy(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	action, rule := secpath.InPacket(inPort, outPort, intent)
	result := firewall.NewPolicyResultIntent(intent)
	result.WithFromPort(inPort)
	result.WithOutPort(outPort)
	result.WithRule(rule)
	result.WithAction(action)

	return result
}

func (secpath *SecPathNode) OutputPolicy(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	return nil
}

func (secpath *SecPathNode) DefaultStep(fp *firewall.FirewallProcess) {
	fp.WithInputPolicy()
}

func (secpath *SecPathNode) UpdateSnatStep(in, out api.Port, intent *policy.Intent, fp *firewall.FirewallProcess) {
	inZone := in.(*SecPathPort).Zone()
	outZone := out.(*SecPathPort).Zone()

	// 检查是否需要SNAT
	needSnat := false
	for _, snatInfo := range secpath.SnatDesignInfo {
		if (snatInfo.From == inZone || snatInfo.From == "any") && (snatInfo.To == outZone || snatInfo.To == "any") {
			needSnat = true
			break
		}
	}

	if needSnat {
		// 如果需要SNAT，调用fp.WithOutputNat()
		fp.WithOutputNat()
	}
}

func (secpath *SecPathNode) GetPoolByNetworkGroup(ng *network.NetworkGroup, natType firewall.NatType) (firewall.FirewallNetworkObject, bool) {
	return secpath.Nats.matchAddressGroupByNetworkGroup(ng)
}

func (secpath *SecPathNode) GetObjectByNetworkGroup(ng *network.NetworkGroup, searchType firewall.ObjectSearchType, port api.Port) (firewall.FirewallNetworkObject, bool) {
	return secpath.ObjectSet.GetObjectByNetworkGroup(ng, searchType, port)
}

func (secpath *SecPathNode) GetObjectByService(s *service.Service, searchType firewall.ObjectSearchType) (firewall.FirewallServiceObject, bool) {
	return secpath.ObjectSet.GetObjectByService(s, searchType)
}

func (secpath *SecPathNode) Network(zone, name string) (*network.NetworkGroup, bool) {
	ng, _, ok := secpath.ObjectSet.Network(zone, name)
	return ng, ok
}

func (secpath *SecPathNode) Service(name string) (*service.Service, bool) {
	so, _, ok := secpath.ObjectSet.Service(name)
	return so, ok
}

func (secpath *SecPathNode) L4Port(name string) (*service.L4Port, bool) {
	return nil, false
}

func (secpath *SecPathNode) HasObjectName(name string) bool {
	return secpath.ObjectSet.hasObjectName(name)
}

func (secpath *SecPathNode) HasPolicyName(name string) bool {
	return secpath.PolicySet.hasPolicyName(name)
}

func (secpath *SecPathNode) HasNatName(name string) bool {
	return secpath.Nats.hasRuleName(name)
}

func (secpath *SecPathNode) HasPoolName(name string) bool {
	return secpath.Nats.hasAddressGroup(name)
}

// GetSupportedNatObjectTypes 获取该防火墙支持的NAT对象类型
// SecPath: DNAT不支持VIP/MIP，SNAT支持SNAT_POOL（通过address-group，即NetworkObject）
func (secpath *SecPathNode) GetSupportedNatObjectTypes(natType string) []firewall.NatObjectType {
	if natType == "DNAT" {
		// SecPath不支持VIP/MIP，只支持NetworkObject
		return []firewall.NatObjectType{firewall.NETWORK_OBJECT, firewall.INLINE}
	}
	if natType == "SNAT" {
		// SecPath支持SNAT_POOL（通过address-group，归类为NETWORK_OBJECT），也支持INTERFACE和INLINE
		return []firewall.NatObjectType{firewall.SNAT_POOL, firewall.NETWORK_OBJECT, firewall.INTERFACE, firewall.INLINE}
	}
	return []firewall.NatObjectType{}
}

// GetObjectByVipMipSnatPool 检查VIP/MIP/SNAT_POOL对象是否已存在（复用检查）
// SecPath: 不支持VIP/MIP，SNAT_POOL通过GetPoolByNetworkGroup查找
func (secpath *SecPathNode) GetObjectByVipMipSnatPool(objectType string, intent *policy.Intent) (firewall.FirewallNetworkObject, bool) {
	if objectType == "SNAT_POOL" && intent.Snat != "" {
		snatNg, err := network.NewNetworkGroupFromString(intent.Snat)
		if err == nil {
			return secpath.GetPoolByNetworkGroup(snatNg, firewall.DYNAMIC_NAT)
		}
	}
	// VIP/MIP不支持
	return nil, false
}

// GenerateVipMipSnatPoolName 自动生成VIP/MIP/SNAT_POOL对象名称（可选）
// SecPath: 不提供自动命名，返回空字符串使用配置模板
func (secpath *SecPathNode) GenerateVipMipSnatPoolName(objectType string, intent *policy.Intent, metaData map[string]interface{}) string {
	// SecPath不提供自动命名，返回空字符串使用配置模板
	return ""
}

// GetReuseNatObject 获取可重用的NAT对象名称
// SecPath:
//   - DNAT: 根据dnat_object_type配置，可能使用NETWORK_OBJECT或INLINE
//   - SNAT: 根据snat_object_type配置，可能使用SNAT_POOL、NETWORK_OBJECT、INTERFACE或INLINE
//
// 通过natType和metaData配置来决定objectType，然后进行复用查询
func (secpath *SecPathNode) GetReuseNatObject(natType string, intent *policy.Intent, metaData map[string]interface{}) (name string, reused bool) {
	// 根据natType和metaData确定objectType
	// 对于DNAT和SNAT，一定会命中一种防火墙支持的对象类型清单，同时结合metaData中的配置，最终选择一种对象类型
	objectType, ok := secpath.DetermineNatObjectType(natType, metaData)
	if !ok {
		return "", false
	}

	// INTERFACE/INLINE 类型不需要生成对象，直接返回
	if objectType == firewall.INTERFACE || objectType == firewall.INLINE {
		return "", false
	}

	// 根据objectType进行复用查询
	if objectType == firewall.SNAT_POOL {
		// SNAT_POOL: 通过GetPoolByNetworkGroup查找address-group
		// 仅适用于SNAT类型
		if natType == "SNAT" && intent.Snat != "" {
			snatNg, err := network.NewNetworkGroupFromString(intent.Snat)
			if err == nil {
				obj, found := secpath.GetPoolByNetworkGroup(snatNg, firewall.DYNAMIC_NAT)
				if found {
					return obj.Name(), true
				}
			}
		}
	} else if objectType == firewall.NETWORK_OBJECT {
		// NETWORK_OBJECT: 通过GetObjectByNetworkGroup查找地址对象
		// 适用于DNAT（使用real_ip）和SNAT（使用snat）
		var ng *network.NetworkGroup
		var err error

		if natType == "DNAT" {
			// DNAT: 使用real_ip查找地址对象
			if intent.RealIp == "" {
				return "", false
			}
			ng, err = network.NewNetworkGroupFromString(intent.RealIp)
		} else if natType == "SNAT" {
			// SNAT: 使用snat查找地址对象
			if intent.Snat == "" {
				return "", false
			}
			ng, err = network.NewNetworkGroupFromString(intent.Snat)
		} else {
			return "", false
		}

		if err == nil {
			obj, found := secpath.GetObjectByNetworkGroup(ng, firewall.SEARCH_OBJECT_OR_GROUP, nil)
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
func (secpath *SecPathNode) DetermineNatObjectType(natType string, metaData map[string]interface{}) (firewall.NatObjectType, bool) {
	if natType == "DNAT" {
		objectType := getStringFromMeta(metaData, "dnat_object_type", "NETWORK_OBJECT")
		if objectType == "INLINE" {
			return firewall.INLINE, true
		}
		if objectType == "NETWORK_OBJECT" {
			return firewall.NETWORK_OBJECT, true
		}
	} else if natType == "SNAT" {
		objectType := getStringFromMeta(metaData, "natpolicy.snat_object_type", "SNAT_POOL")
		if objectType == "SNAT_POOL" {
			return firewall.SNAT_POOL, true
		} else if objectType == "INTERFACE" {
			return firewall.INTERFACE, true
		}
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

func (secpath *SecPathNode) InputNatTargetCheck(intent *policy.Intent, inPort, outPort api.Port) (bool, firewall.FirewallNatRule) {
	return secpath.Nats.inputNatTargetCheck(intent, inPort, outPort)
}

func (secpath *SecPathNode) MakeStaticNatCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
	// 使用 v4 版本（Starlark 模板）
	templates, err := v4.NewCommonTemplatesV4(secpath, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(secpath.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if secpath.DeviceNode != nil {
		deviceConfig := secpath.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(secpath.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromResultV4(secpath, result)
}

func (secpath *SecPathNode) MakeDynamicNatCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
	// 使用 v4 版本（Starlark 模板）
	templates, err := v4.NewCommonTemplatesV4(secpath, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(secpath.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if secpath.DeviceNode != nil {
		deviceConfig := secpath.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(secpath.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromResultV4(secpath, result)
}

func (secpath *SecPathNode) MakeInputPolicyCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList, moveRule []string) {
	// 使用 v4 版本（Starlark 模板）
	// 从 PolicyContext 获取模板路径，如果没有则使用默认路径
	templatePath := firewall.GetTemplatePath(ctx)
	templates, err := v4.NewCommonTemplatesV4(secpath, templatePath, nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(secpath.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList, nil
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if secpath.DeviceNode != nil {
		deviceConfig := secpath.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(secpath.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList, nil
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromResultForPolicyV4(secpath, result), nil
}

func (secpath *SecPathNode) MakeOutputPolicyCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
	// SecPath 的 OutputPolicy 通常为空，但为了保持一致性，也使用 v4 版本（Starlark 模板）
	// 从 PolicyContext 获取模板路径，如果没有则使用默认路径
	templatePath := firewall.GetTemplatePath(ctx)
	templates, err := v4.NewCommonTemplatesV4(secpath, templatePath, nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(secpath.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if secpath.DeviceNode != nil {
		deviceConfig := secpath.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(secpath.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromResultForPolicyV4(secpath, result)
}

// createCmdListFromResultV4 从 v4 的 NatPolicyResult 创建 command.CmdList
func createCmdListFromResultV4(secpath *SecPathNode, result *v4.NatPolicyResult) command.CmdList {
	cmdList := command.NewCliCmdList(secpath.DeviceNode.CmdIp(), true)

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

// createCmdListFromResultForPolicyV4 从 v4 的 PolicyResult 创建 command.CmdList
func createCmdListFromResultForPolicyV4(secpath *SecPathNode, result *v4.PolicyResult) command.CmdList {
	cmdList := command.NewCliCmdList(secpath.DeviceNode.CmdIp(), true)

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

func (secpath *SecPathNode) InPacket(from, to api.Port, entry policy.PolicyEntryInf) (firewall.Action, firewall.FirewallPolicy) {
	ok, rule := secpath.PolicySet.Match(from.(*SecPathPort).Zone(), to.(*SecPathPort).Zone(), entry)
	if !ok {
		return firewall.POLICY_IMPLICIT_DENY, nil
	} else {
		return rule.(*Policy).Action(), rule
	}
}

func (secpath *SecPathNode) NextPoolId(id string) string {
	// 如果提供了 id，直接返回
	if id != "" {
		return id
	}

	var max int
	for _, ag := range secpath.Nats.addrGroups {
		if ag.GroupNumber > max {
			max = ag.GroupNumber
		}
	}

	return fmt.Sprintf("%d", max+1)
}

func (secpath *SecPathNode) NextPolicyId(ipType network.IPFamily) int {
	id := 0
	for _, policy := range secpath.PolicySet.securityPolicyAcl {
		if policy.ipType == ipType {
			if policy.id > id {
				id = policy.id
			}
		}
	}

	return id + 1
}

func (secpath *SecPathNode) FirstPolicyRuleId(ipType network.IPFamily) string {
	return fmt.Sprint(secpath.PolicySet.firstRuleId(ipType))
}

func (secpath *SecPathNode) ServiceObjectToDb(db *gorm.DB, task_id uint) {
	//secpath.objectSet.ServiceObjectToDb(db, task_id)

}

func (secpath *SecPathNode) NetworkObjectToDb(db *gorm.DB, task_id uint) {
	//secpath.objectSet.NetworkObjectToDb(db, task_id)
}

func (secpath *SecPathNode) PolicyToDb(db *gorm.DB, task_id uint) {
	//secpath.policySet.PolicyToDb(db, task_id)
}

func (secpath *SecPathNode) AclToDb(db *gorm.DB, task_id uint) {
	//secpath.policySet.AclToDb(db, task_id)
}

func (secpath *SecPathNode) AddressGroupToDb(db *gorm.DB, task_id uint) {
	//secpath.nats.AddressGroupToDb(db, task_id)
}

func (secpath *SecPathNode) NatsToDb(db *gorm.DB, task_id uint) {
	//secpath.nats.NatsToDb(db, task_id)
}

func (secpath *SecPathNode) ExtraToDb(db *gorm.DB, task_id uint) {
	secpath.ServiceObjectToDb(db, task_id)
	secpath.NetworkObjectToDb(db, task_id)
	secpath.PolicyToDb(db, task_id)
	secpath.AclToDb(db, task_id)
	secpath.AddressGroupToDb(db, task_id)
	secpath.NatsToDb(db, task_id)
}

func (secppath *SecPathNode) Policies() []firewall.FirewallPolicy {
	policies := []firewall.FirewallPolicy{}
	for _, policy := range secppath.PolicySet.securityPolicyAcl {
		policies = append(policies, policy)
	}

	return policies
}

// ObjectConsistencyCheck 进行对象一致性检查
func (secpath *SecPathNode) ObjectConsistencyCheck(objectType string, name string, input interface{}) (bool, string, error) {
	switch objectType {
	case "network":
		return secpath.networkObjectCheck(name, input)
	case "service":
		return secpath.serviceObjectCheck(name, input)
	default:
		return false, "", fmt.Errorf("unsupported object type: %s", objectType)
	}
}

// networkObjectCheck 检查网络对象一致性
// networkObjectCheck 检查网络对象一致性
func (secpath *SecPathNode) networkObjectCheck(name string, input interface{}) (bool, string, error) {
	// 通过名称获取存储的网络对象
	storedNG, ok := secpath.Network("", name)
	if !ok {
		return false, "", fmt.Errorf("network object not found: %s", name)
	}

	var inputNG *network.NetworkGroup
	var err error

	switch v := input.(type) {
	case *network.NetworkGroup:
		inputNG = v
	case network.IP:
		inputNG, err = network.NewNetworkGroupFromString(v.String())
		if err != nil {
			return false, "", fmt.Errorf("invalid network group: %v", err)
		}

	case network.AbbrNet:
		inputNG = network.NewNetworkGroup()
		inputNG.Add(v)
	default:
		return false, "", fmt.Errorf("unsupported input type for network object")
	}

	// 使用 Same 函数比较存储的网络组和输入的网络组
	if storedNG.Same(inputNG) {
		return true, "", nil
	}

	// 如果不一致，生成差异信息
	diff := fmt.Sprintf("Stored: %v\nInput: %v", storedNG, inputNG)
	return false, diff, nil
}

// serviceObjectCheck 检查服务对象一致性
func (secpath *SecPathNode) serviceObjectCheck(name string, input interface{}) (bool, string, error) {
	// 通过名称获取存储的服务对象
	storedService, ok := secpath.Service(name)
	if !ok {
		return false, "", fmt.Errorf("service object not found: %s", name)
	}

	var inputService *service.Service
	var err error

	switch v := input.(type) {
	case *service.Service:
		inputService = v
	case *service.L3Protocol:
		inputService, err = service.NewServiceFromString(v.String())
		if err != nil {
			return false, "", fmt.Errorf("invalid service: %v", err)
		}
	case *service.ICMPProto:
		inputService = &service.Service{}
		inputService.Add(v)
	case *service.L4Service:
		inputService = &service.Service{}
		inputService.Add(v)
	default:
		return false, "", fmt.Errorf("unsupported input type for service object")
	}

	// 使用 Same 函数比较存储的服务和输入的服务
	if storedService.Same(inputService) {
		return true, "", nil
	}

	// 如果不一致，生成差异信息
	diff := fmt.Sprintf("Stored: %v\nInput: %v", storedService, inputService)
	return false, diff, nil
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*api.Node)(nil)).Elem(), "SecPathNode", reflect.TypeOf(SecPathNode{}))
}

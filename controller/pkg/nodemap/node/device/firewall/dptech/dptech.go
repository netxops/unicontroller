package dptech

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
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
	"github.com/netxops/utils/registry"
	"github.com/netxops/utils/service"

	"gorm.io/gorm"
)

var _ firewall.FirewallNode = &DptechNode{}
var _ firewall.IteratorFirewall = &DptechNode{}

type DptechNode struct {
	*node.DeviceNode
	ObjectSet      *DptechObjectSet
	PolicySet      *PolicySet
	Nats           *Nats
	SnatDesignInfo []*config.SnatDesignInfo
}

func (dp *DptechNode) Type() terminalmode.DeviceType {
	return terminalmode.Dptech
}

// TypeName 实现 TypeInterface 接口
func (dn *DptechNode) TypeName() string {
	return "DptechNode"
}

// dptechNodeJSON 用于序列化和反序列化
type dptechNodeJSON struct {
	DeviceNode     json.RawMessage          `json:"device_node"`
	ObjectSet      *DptechObjectSet         `json:"object_set"`
	PolicySet      *PolicySet               `json:"policy_set"`
	Nats           *Nats                    `json:"nats"`
	SnatDesignInfo []*config.SnatDesignInfo `json:"snat_design_info"`
}

// MarshalJSON 实现 JSON 序列化
func (dn *DptechNode) MarshalJSON() ([]byte, error) {
	deviceNodeJSON, err := json.Marshal(dn.DeviceNode)
	if err != nil {
		return nil, err
	}

	return json.Marshal(dptechNodeJSON{
		DeviceNode:     deviceNodeJSON,
		ObjectSet:      dn.ObjectSet,
		PolicySet:      dn.PolicySet,
		Nats:           dn.Nats,
		SnatDesignInfo: dn.SnatDesignInfo,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (dn *DptechNode) UnmarshalJSON(data []byte) error {
	var dnj dptechNodeJSON
	if err := json.Unmarshal(data, &dnj); err != nil {
		return err
	}

	if err := json.Unmarshal(dnj.DeviceNode, &dn.DeviceNode); err != nil {
		return err
	}

	dn.ObjectSet = dnj.ObjectSet
	dn.PolicySet = dnj.PolicySet
	dn.Nats = dnj.Nats
	dn.SnatDesignInfo = dnj.SnatDesignInfo

	nats := [][]*NatRuleSet{dn.Nats.StaticNatRules, dn.Nats.SourceNatRules, dn.Nats.DestinationNatRules}
	for _, ruleSets := range nats {
		for _, ruleSet := range ruleSets {
			for _, rule := range ruleSet.Rules {
				rule.objects = dn.ObjectSet
				rule.node = dn
			}
		}
	}

	for _, plc := range dn.PolicySet.policySet {
		plc.node = dn
		plc.objects = dn.ObjectSet
	}

	return nil
}

func (dp *DptechNode) InputNat(intent *policy.Intent, inPort api.Port) processor.AbstractMatchResult {
	ok, translateTo, rule := dp.Nats.inputNat(intent, inPort)
	if ok {
		fmt.Println("translate to: ", translateTo.String())
	}

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

func (dp *DptechNode) OutputNat(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	ok, translateTo, rule := dp.Nats.outputNat(intent, inPort, outPort)

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

func (dp *DptechNode) InputPolicy(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	action, rule := dp.InPacket(inPort, outPort, intent)
	// action, rule := Dptech.matrix.InPacket(inPort, outPort, intent)
	result := firewall.NewPolicyResultIntent(intent)
	result.WithFromPort(inPort)
	result.WithOutPort(outPort)
	result.WithRule(rule)
	result.WithAction(action)

	return result
}

func (dp *DptechNode) OutputPolicy(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	// func (Dptech *DptechNode) OutputPolicy(intent *policy.Intent, inPort, outPort api.Port) firewall.PolicyMatchResult {
	return nil
}

func (dp *DptechNode) DefaultStep(fp *firewall.FirewallProcess) {
	fp.WithInputPolicy()
}

func (dp *DptechNode) UpdateSnatStep(in, out api.Port, intent *policy.Intent, fp *firewall.FirewallProcess) {
	inZone := in.(*DptechPort).Zone()
	outZone := out.(*DptechPort).Zone()

	// 检查是否需要SNAT
	needSnat := false
	for _, snatInfo := range dp.SnatDesignInfo {
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

func (dp *DptechNode) GetPoolByNetworkGroup(ng *network.NetworkGroup, natType firewall.NatType) (firewall.FirewallNetworkObject, bool) {
	// 不区分 NAT 类型，动态 NAT 和 DNAT 都可以使用 address-pool
	return dp.ObjectSet.GetPoolByeNetworkGroup(ng)
}

// GetSupportedNatObjectTypes 获取该防火墙支持的NAT对象类型
// DPTech: DNAT支持MIP（特殊语法address-pool），SNAT支持SNAT_POOL（特殊语法address-pool）
func (dp *DptechNode) GetSupportedNatObjectTypes(natType string) []firewall.NatObjectType {
	if natType == "DNAT" {
		// MIP使用特殊语法address-pool
		return []firewall.NatObjectType{firewall.MIP, firewall.INLINE}
	}
	if natType == "SNAT" {
		// SNAT_POOL使用特殊语法address-pool
		return []firewall.NatObjectType{firewall.SNAT_POOL, firewall.INTERFACE}
	}
	return []firewall.NatObjectType{}
}

// GetObjectByVipMipSnatPool 检查VIP/MIP/SNAT_POOL对象是否已存在（复用检查）
// DPTech: 支持MIP和SNAT_POOL，都使用address-pool对象
func (dp *DptechNode) GetObjectByVipMipSnatPool(objectType string, intent *policy.Intent) (firewall.FirewallNetworkObject, bool) {
	if objectType == "MIP" && intent.RealIp != "" {
		// MIP通过address-pool实现，查找pool对象
		realIpNg, err := network.NewNetworkGroupFromString(intent.RealIp)
		if err == nil {
			// 查找address-pool（DNAT pool）
			return dp.GetPoolByNetworkGroup(realIpNg, firewall.DESTINATION_NAT) // natType 参数被忽略
		}
	}
	if objectType == "SNAT_POOL" && intent.Snat != "" {
		// SNAT_POOL通过address-pool实现
		snatNg, err := network.NewNetworkGroupFromString(intent.Snat)
		if err == nil {
			return dp.GetPoolByNetworkGroup(snatNg, firewall.DYNAMIC_NAT) // natType 参数被忽略
		}
	}
	// VIP不支持
	return nil, false
}

// GenerateVipMipSnatPoolName 自动生成VIP/MIP/SNAT_POOL对象名称（可选）
// DPTech: 不提供自动命名，返回空字符串使用配置模板
func (dp *DptechNode) GenerateVipMipSnatPoolName(objectType string, intent *policy.Intent, metaData map[string]interface{}) string {
	// DPTech不提供自动命名，返回空字符串使用配置模板
	return ""
}

// GetReuseNatObject 获取可重用的NAT对象名称
// DPTech:
//   - DNAT: 总是使用MIP（address-pool）
//   - SNAT: 根据snat_object_type配置，可能使用SNAT_POOL、NETWORK_OBJECT、INTERFACE或INLINE
//
// 通过natType和metaData配置来决定objectType，然后进行复用查询
func (dp *DptechNode) GetReuseNatObject(natType string, intent *policy.Intent, metaData map[string]interface{}) (name string, reused bool) {
	// 根据natType和metaData确定objectType
	// 对于DNAT和SNAT，一定会命中一种防火墙支持的对象类型清单，同时结合metaData中的配置，最终选择一种对象类型
	objectType, ok := dp.DetermineNatObjectType(natType, metaData)
	if !ok {
		return "", false
	}

	// INTERFACE/INLINE 类型不需要生成对象，直接返回
	if objectType == firewall.INTERFACE || objectType == firewall.INLINE {
		return "", false
	}

	// 根据objectType进行复用查询
	if objectType == firewall.MIP {
		// MIP: 通过GetPoolByNetworkGroup查找address-pool（仅适用于DNAT）
		realIpNg, err := network.NewNetworkGroupFromString(intent.RealIp)
		if err == nil {
			obj, found := dp.GetPoolByNetworkGroup(realIpNg, firewall.DESTINATION_NAT) // natType 参数被忽略
			if found {
				return obj.Name(), true
			}
		}
	} else if objectType == firewall.SNAT_POOL {
		// SNAT_POOL: 通过GetPoolByNetworkGroup查找address-pool（仅适用于SNAT）
		if natType == "SNAT" && intent.Snat != "" {
			snatNg, err := network.NewNetworkGroupFromString(intent.Snat)
			if err == nil {
				obj, found := dp.GetPoolByNetworkGroup(snatNg, firewall.DYNAMIC_NAT) // natType 参数被忽略
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
func (dp *DptechNode) DetermineNatObjectType(natType string, metaData map[string]interface{}) (firewall.NatObjectType, bool) {
	if natType == "DNAT" {
		objectType := getStringFromMeta(metaData, "dnat_object_type", "MIP")
		if objectType == "MIP" {
			return firewall.MIP, true
		}
	} else if natType == "SNAT" {
		objectType := getStringFromMeta(metaData, "snat_object_type", "SNAT_POOL")
		if objectType == "INTERFACE" {
			return firewall.INTERFACE, true
		} else if objectType == "SNAT_POOL" {
			return firewall.SNAT_POOL, true
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

func (dp *DptechNode) GetObjectByNetworkGroup(ng *network.NetworkGroup, searchType firewall.ObjectSearchType, port api.Port) (firewall.FirewallNetworkObject, bool) {
	return dp.ObjectSet.GetObjectByNetworkGroup(ng, searchType, port)
}

func (dp *DptechNode) GetObjectByService(s *service.Service, searchType firewall.ObjectSearchType) (firewall.FirewallServiceObject, bool) {
	return nil, false
}

func (dp *DptechNode) Network(zone, name string) (*network.NetworkGroup, bool) {
	_, ng, ok := dp.ObjectSet.Network(zone, name)
	return ng, ok
}

func (dp *DptechNode) Service(name string) (*service.Service, bool) {
	_, srv, ok := dp.ObjectSet.Service(name)
	return srv, ok
}

func (dp *DptechNode) L4Port(name string) (*service.L4Port, bool) {
	return nil, false
}

func (dp *DptechNode) HasObjectName(name string) bool {
	return dp.ObjectSet.hasObjectName(name)
}

func (dp *DptechNode) HasPolicyName(name string) bool {
	// policySet map[string]map[string][]*Policy
	for _, plc := range dp.PolicySet.policySet {
		if plc.Name() == name {
			return true
		}
	}
	return false
}

func (dp *DptechNode) HasNatName(name string) bool {
	return dp.Nats.hasRuleName(name)
}

func (dp *DptechNode) HasPoolName(name string) bool {
	_, ok := dp.ObjectSet.poolMap[name]
	return ok
}

func (dp *DptechNode) InputNatTargetCheck(intent *policy.Intent, inPort, outPort api.Port) (bool, firewall.FirewallNatRule) {
	return false, nil
}

func (dp *DptechNode) MakeStaticNatCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
	// 使用 v4 版本（Starlark 模板）
	templates, err := v4.NewCommonTemplatesV4(dp, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(dp.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if dp.DeviceNode != nil {
		deviceConfig := dp.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(dp.DeviceNode.CmdIp(), true)
		return "", cmdList
	}

	// 合并 FlyObject 到 CLIString（保持与原有接口一致）
	mergedCLI := mergeFlyObjectAndCLIStringV4(result.FlyObject, result.CLIString)
	cmdList = createCmdListFromNatResultV4(dp, result)

	return mergedCLI, cmdList
}

func (dp *DptechNode) MakeDynamicNatCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
	// 使用 v4 版本（Starlark 模板）
	templates, err := v4.NewCommonTemplatesV4(dp, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(dp.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if dp.DeviceNode != nil {
		deviceConfig := dp.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(dp.DeviceNode.CmdIp(), true)
		return "", cmdList
	}

	// 合并 FlyObject 到 CLIString（保持与原有接口一致）
	mergedCLI := mergeFlyObjectAndCLIStringV4(result.FlyObject, result.CLIString)
	cmdList = createCmdListFromNatResultV4(dp, result)

	return mergedCLI, cmdList
}

func (dp *DptechNode) MakeInputPolicyCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList, moveRule []string) {
	// 使用 v4 版本（Starlark 模板）
	// 从 PolicyContext 获取模板路径，如果没有则使用默认路径
	templatePath := firewall.GetTemplatePath(ctx)
	templates, err := v4.NewCommonTemplatesV4(dp, templatePath, nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(dp.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList, nil
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if dp.DeviceNode != nil {
		deviceConfig := dp.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(dp.DeviceNode.CmdIp(), true)
		return "", cmdList, nil
	}

	// 合并 FlyObject 到 CLIString（保持与原有接口一致）
	mergedCLI := mergeFlyObjectAndCLIStringV4(result.FlyObject, result.CLIString)
	cmdList = createCmdListFromPolicyResultV4(dp, result)

	return mergedCLI, cmdList, nil
}

func (dp *DptechNode) MakeOutputPolicyCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
	// DPTech 的 OutputPolicy 通常为空，但为了保持一致性，也使用 v4 版本（Starlark 模板）
	// 从 PolicyContext 获取模板路径，如果没有则使用默认路径
	templatePath := firewall.GetTemplatePath(ctx)
	templates, err := v4.NewCommonTemplatesV4(dp, templatePath, nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(dp.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if dp.DeviceNode != nil {
		deviceConfig := dp.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(dp.DeviceNode.CmdIp(), true)
		return "", cmdList
	}

	// 合并 FlyObject 到 CLIString（保持与原有接口一致）
	mergedCLI := mergeFlyObjectAndCLIStringV4(result.FlyObject, result.CLIString)
	cmdList = createCmdListFromPolicyResultV4(dp, result)

	return mergedCLI, cmdList
}

// mergeFlyObjectAndCLIStringV4 合并 FlyObject 和 CLIString，模拟原有 MergeFlyObjectAndCLIString 的行为
// DPTech 使用 "!" 作为分隔符
func mergeFlyObjectAndCLIStringV4(flyObject map[string]string, cliString string) string {
	var builder strings.Builder
	keys := []string{"NETWORK", "VIP", "MIP", "SERVICE", "POOL", "NAT", "SECURITY_POLICY"}

	// 首先添加 FlyObject 中的所有命令行
	for _, key := range keys {
		if v, ok := flyObject[key]; ok && v != "" {
			builder.WriteString(v)
			builder.WriteString("\n!\n")
		}
	}

	return strings.TrimSpace(builder.String())
}

// createCmdListFromNatResultV4 从 v4 的 NatPolicyResult 创建 command.CmdList
func createCmdListFromNatResultV4(dp *DptechNode, result *v4.NatPolicyResult) command.CmdList {
	cmdList := command.NewCliCmdList(dp.DeviceNode.CmdIp(), true)

	// 合并 FlyObject 到 CLIString
	mergedCLI := mergeFlyObjectAndCLIStringV4(result.FlyObject, result.CLIString)

	if mergedCLI != "" {
		cmdList.AddCmd(command.NewCliCmd(mergedCLI, "", 1, true))
	}

	return cmdList
}

// createCmdListFromPolicyResultV4 从 v4 的 PolicyResult 创建 command.CmdList
func createCmdListFromPolicyResultV4(dp *DptechNode, result *v4.PolicyResult) command.CmdList {
	cmdList := command.NewCliCmdList(dp.DeviceNode.CmdIp(), true)

	// 合并 FlyObject 到 CLIString
	mergedCLI := mergeFlyObjectAndCLIStringV4(result.FlyObject, result.CLIString)

	if mergedCLI != "" {
		cmdList.AddCmd(command.NewCliCmd(mergedCLI, "", 1, true))
	}

	return cmdList
}

// func (usg *UsgNode) MakeStaticNatCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
// 	result, cmdList := common.MakeNatCli(from, out, intent, ctx, usg, "Usg", true)
// 	return result.MergeFlyObjectAndCLIString(), cmdList
// }

// func (usg *UsgNode) MakeDynamicNatCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
// 	result, cmdList := common.MakeNatCli(from, out, intent, ctx, usg, "Usg", false)
// 	return result.MergeFlyObjectAndCLIString(), cmdList
// }

// func (usg *UsgNode) MakeInputPolicyCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList, moveRule []string) {
// 	result, cmdList, moveRule := common.MakeInputPolicyCli(from, out, intent, usg, "Usg", ctx)
// 	return result.MergeFlyObjectAndCLIString(), cmdList, moveRule
// }

func (dp *DptechNode) InPacket(from, to api.Port, entry policy.PolicyEntryInf) (firewall.Action, firewall.FirewallPolicy) {

	// func (ps *PolicySet) Match(from, to string, pe policy.PolicyEntryInf) (bool, firewall.FirewallPolicy) {
	ok, rule := dp.PolicySet.Match(from.(*DptechPort).Zone(), to.(*DptechPort).Zone(), entry)
	if !ok {
		return firewall.POLICY_IMPLICIT_DENY, nil
	} else {
		return rule.(*Policy).Action(), rule
	}

	// return firewall.POLICY_IMPLICIT_DENY, nil
}

func (dp *DptechNode) OutPacket(from, to api.Port, entry policy.PolicyEntryInf) (firewall.Action, firewall.FirewallPolicy) {

	return firewall.POLICY_IMPLICIT_PERMIT, nil
}

func (dp *DptechNode) ServiceObjectToDb(db *gorm.DB, task_id uint) {
}

func (dp *DptechNode) NetworkObjectToDb(db *gorm.DB, task_id uint) {
}

func (dp *DptechNode) PolicyToDb(db *gorm.DB, task_id uint) {
}

func (dp *DptechNode) AclToDb(db *gorm.DB, task_id uint) {
}

func (dp *DptechNode) AddressGroupToDb(db *gorm.DB, task_id uint) {
}

func (dp *DptechNode) NatsToDb(db *gorm.DB, task_id uint) {
}

func (dp *DptechNode) ExtraToDb(db *gorm.DB, task_id uint) {
}

// GetPolicyName 实现FirewallNode接口，返回策略名称
// DPTech使用命名模板，所以返回空字符串表示使用模板生成
func (dp *DptechNode) GetPolicyName(ctx *firewall.PolicyContext) (string, error) {
	// DPTech使用命名模板生成策略名称，返回空字符串表示使用模板
	return "", nil
}

func (dp *DptechNode) Policies() []firewall.FirewallPolicy {
	policies := []firewall.FirewallPolicy{}
	for _, plc := range dp.PolicySet.policySet {
		policies = append(policies, plc)
	}

	return policies
}

func (dp *DptechNode) NextPoolId(id string) string {
	// 如果提供了 id，直接返回
	if id != "" {
		return id
	}

	maxId := 0

	// 遍历所有的池
	for _, pool := range dp.ObjectSet.poolMap {
		// 假设池的 ID 是一个字符串形式的数字
		poolId, err := strconv.Atoi(pool.Name())
		if err == nil && poolId > maxId {
			maxId = poolId
		}
	}

	// 返回最大 ID + 1
	return strconv.Itoa(maxId + 1)
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*api.Node)(nil)).Elem(), "DptechNode", reflect.TypeOf(DptechNode{}))
}

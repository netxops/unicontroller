package usg

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"

	"github.com/douyu/jupiter/pkg/store/gorm"
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
)

// var _ firewall.FirewallNode = &UsgNode{}

// type UsgNode struct {
// 	node.DeviceNode
// 	objectSet *UsgObjectSet
// 	// policySet *PolicySet
// 	// nats      *Nats
// }

// func (usg *UsgNode) Type() terminalmode.DeviceType {
// 	return terminalmode.HuaWei
// }

var _ firewall.FirewallNode = &UsgNode{}
var _ firewall.FirewallTemplates = &UsgNode{}

type UsgNode struct {
	*node.DeviceNode
	objectSet      *UsgObjectSet
	policySet      *PolicySet
	nats           *Nats
	snatDesignInfo []*config.SnatDesignInfo
}

func (usg *UsgNode) Type() terminalmode.DeviceType {
	return terminalmode.HuaWei
}

// TypeName 实现 TypeInterface 接口
func (usg *UsgNode) TypeName() string {
	return "UsgNode"
}

// usgNodeJSON 用于序列化和反序列化
type usgNodeJSON struct {
	DeviceNode     json.RawMessage          `json:"device_node"`
	ObjectSet      *UsgObjectSet            `json:"object_set"`
	PolicySet      *PolicySet               `json:"policy_set"`
	Nats           *Nats                    `json:"nats"`
	SnatDesignInfo []*config.SnatDesignInfo `json:"snat_design_info"`
}

// MarshalJSON 实现 JSON 序列化
func (usg *UsgNode) MarshalJSON() ([]byte, error) {
	deviceNodeJSON, err := json.Marshal(usg.DeviceNode)
	if err != nil {
		return nil, err
	}

	return json.Marshal(usgNodeJSON{
		DeviceNode:     deviceNodeJSON,
		ObjectSet:      usg.objectSet,
		PolicySet:      usg.policySet,
		Nats:           usg.nats,
		SnatDesignInfo: usg.snatDesignInfo,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (usg *UsgNode) UnmarshalJSON(data []byte) error {
	var usgj usgNodeJSON
	if err := json.Unmarshal(data, &usgj); err != nil {
		return err
	}

	if err := json.Unmarshal(usgj.DeviceNode, &usg.DeviceNode); err != nil {
		return err
	}

	usg.objectSet = usgj.ObjectSet
	usg.policySet = usgj.PolicySet
	usg.policySet.objects = usg.objectSet
	usg.nats = usgj.Nats
	usg.snatDesignInfo = usgj.SnatDesignInfo

	for _, plc := range usg.policySet.policySet {
		plc.node = usg
		plc.objects = usg.objectSet

	}

	nats := [][]*NatRule{usg.nats.destinationNatRules, usg.nats.sourceNatRules, usg.nats.destinationNatRules, usg.nats.natPolicyRules, usg.nats.natServers}
	for _, rules := range nats {
		for _, rule := range rules {
			rule.node = usg
			rule.objects = usg.objectSet
		}
	}
	for _, mp := range usg.nats.natStaticMappings {
		mp.objects = usg.objectSet
		mp.node = usg
	}
	return nil
}

// func (usg *UsgNode) ExtraInit(adapter api.Adapter, deviceConfig *config.DeviceConfig) {
// }

func (usg *UsgNode) InputNat(intent *policy.Intent, inPort api.Port) processor.AbstractMatchResult {
	ok, translateTo, rule := usg.nats.inputNat(intent, inPort)

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

func (usg *UsgNode) OutputNat(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	ok, translateTo, rule := usg.nats.outputNat(intent, inPort, outPort)

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

func (usg *UsgNode) InputPolicy(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	action, rule := usg.InPacket(inPort, outPort, intent)
	// action, rule := usg.matrix.InPacket(inPort, outPort, intent)
	result := firewall.NewPolicyResultIntent(intent)
	result.WithFromPort(inPort)
	result.WithOutPort(outPort)
	result.WithRule(rule)
	result.WithAction(action)

	return result
}

func (usg *UsgNode) OutputPolicy(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	// func (usg *UsgNode) OutputPolicy(intent *policy.Intent, inPort, outPort api.Port) firewall.PolicyMatchResult {
	return nil
}

func (usg *UsgNode) DefaultStep(fp *firewall.FirewallProcess) {
	fp.WithInputPolicy()
}

func (usg *UsgNode) UpdateSnatStep(in, out api.Port, intent *policy.Intent, fp *firewall.FirewallProcess) {
	inZone := in.(*UsgPort).Zone()
	outZone := out.(*UsgPort).Zone()

	// 检查是否需要SNAT
	needSnat := false
	for _, snatInfo := range usg.snatDesignInfo {
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

func (usg *UsgNode) GetPoolByNetworkGroup(ng *network.NetworkGroup, natType firewall.NatType) (firewall.FirewallNetworkObject, bool) {
	return usg.objectSet.GetPoolByeNetworkGroup(ng, natType)
}

// GetSupportedNatObjectTypes 获取该防火墙支持的NAT对象类型
// USG: DNAT支持MIP（NetworkObject），SNAT支持SNAT_POOL（NetworkObject），不支持VIP
func (usg *UsgNode) GetSupportedNatObjectTypes(natType string) []firewall.NatObjectType {
	if natType == "DNAT" {
		// MIP使用NetworkObject（address-group）
		return []firewall.NatObjectType{firewall.NETWORK_OBJECT}
	}
	if natType == "SNAT" {
		// SNAT_POOL支持多种类型
		return []firewall.NatObjectType{firewall.NETWORK_OBJECT, firewall.INTERFACE, firewall.INLINE}
	}
	return []firewall.NatObjectType{}
}

// GetObjectByVipMipSnatPool 检查VIP/MIP/SNAT_POOL对象是否已存在（复用检查）
// USG: 不支持VIP，MIP和SNAT_POOL通过GetPoolByNetworkGroup查找
func (usg *UsgNode) GetObjectByVipMipSnatPool(objectType string, intent *policy.Intent) (firewall.FirewallNetworkObject, bool) {
	if objectType == "MIP" && intent.RealIp != "" {
		realIpNg, err := network.NewNetworkGroupFromString(intent.RealIp)
		if err == nil {
			// MIP通过destination-nat address-group实现，查找address-group
			return usg.GetObjectByNetworkGroup(realIpNg, firewall.SEARCH_OBJECT_OR_GROUP, nil)
		}
	}
	if objectType == "SNAT_POOL" && intent.Snat != "" {
		snatNg, err := network.NewNetworkGroupFromString(intent.Snat)
		if err == nil {
			return usg.GetPoolByNetworkGroup(snatNg, firewall.DYNAMIC_NAT)
		}
	}
	// VIP不支持
	return nil, false
}

// GenerateVipMipSnatPoolName 自动生成VIP/MIP/SNAT_POOL对象名称（可选）
// USG: 不提供自动命名，返回空字符串使用配置模板
func (usg *UsgNode) GenerateVipMipSnatPoolName(objectType string, intent *policy.Intent, metaData map[string]interface{}) string {
	// USG不提供自动命名，返回空字符串使用配置模板
	return ""
}

// GetReuseNatObject 获取可重用的NAT对象名称
// USG: 支持MIP（destination-nat address-group）和SNAT_POOL（address-group），不支持VIP
//
// 通过natType和metaData配置来决定objectType，然后进行复用查询
func (usg *UsgNode) GetReuseNatObject(natType string, intent *policy.Intent, metaData map[string]interface{}) (name string, reused bool) {
	// 根据natType和metaData确定objectType
	// 对于DNAT和SNAT，一定会命中一种防火墙支持的对象类型清单，同时结合metaData中的配置，最终选择一种对象类型
	objectType, ok := usg.DetermineNatObjectType(natType, metaData)
	if !ok {
		return "", false
	}

	// INTERFACE/INLINE 类型不需要生成对象，直接返回
	if objectType == firewall.INTERFACE || objectType == firewall.INLINE {
		return "", false
	}

	// 根据objectType进行复用查询
	if natType == "DNAT" {
		// DNAT: 处理 MIP（不支持VIP）
		// USG的DNAT只支持NETWORK_OBJECT（MIP），通过GetObjectByNetworkGroup查找address-group
		if objectType == firewall.MIP {
			realIpNg, err := network.NewNetworkGroupFromString(intent.RealIp)
			if err == nil {
				obj, found := usg.GetPoolByNetworkGroup(realIpNg, firewall.DESTINATION_NAT)
				if found {
					return obj.Name(), true
				}
			}
		}
	} else if natType == "SNAT" {
		// SNAT: 处理 NETWORK_OBJECT（SNAT_POOL）
		// USG的SNAT支持NETWORK_OBJECT，通过GetPoolByNetworkGroup查找address-group
		if objectType == firewall.SNAT_POOL {
			snatNg, err := network.NewNetworkGroupFromString(intent.Snat)
			if err == nil {
				// USG的SNAT_POOL通过address-group实现，使用GetPoolByNetworkGroup查找
				obj, found := usg.GetPoolByNetworkGroup(snatNg, firewall.DYNAMIC_NAT)
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
func (usg *UsgNode) DetermineNatObjectType(natType string, metaData map[string]interface{}) (firewall.NatObjectType, bool) {
	switch natType {
	case "DNAT":
		// USG的DNAT只支持NETWORK_OBJECT（MIP）
		objectType := getStringFromMeta(metaData, "dnat_object_type", "MIP")
		switch objectType {
		case "MIP":
			return firewall.MIP, true
		case "INLINE":
			return firewall.INLINE, true
		}

	case "SNAT":
		// USG的SNAT支持NETWORK_OBJECT（SNAT_POOL）、INTERFACE和INLINE
		objectType := getStringFromMeta(metaData, "snat_object_type", "SNAT_POOL")
		switch objectType {
		case "SNAT_POOL":
			return firewall.SNAT_POOL, true
		case "INTERFACE":
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

func (usg *UsgNode) GetObjectByNetworkGroup(ng *network.NetworkGroup, searchType firewall.ObjectSearchType, port api.Port) (firewall.FirewallNetworkObject, bool) {
	return usg.objectSet.GetObjectByNetworkGroup(ng, searchType, port)
}

func (usg *UsgNode) GetObjectByService(s *service.Service, searchType firewall.ObjectSearchType) (firewall.FirewallServiceObject, bool) {
	return usg.objectSet.GetObjectByService(s, searchType)
}

func (usg *UsgNode) Network(zone, name string) (*network.NetworkGroup, bool) {
	_, ng, ok := usg.objectSet.Network(zone, name)
	return ng, ok
}

func (usg *UsgNode) Service(name string) (*service.Service, bool) {
	_, srv, ok := usg.objectSet.Service(name)
	return srv, ok
}

func (usg *UsgNode) L4Port(name string) (*service.L4Port, bool) {
	return nil, false
}

func (usg *UsgNode) HasObjectName(name string) bool {
	return usg.objectSet.hasObjectName(name)
}

func (usg *UsgNode) HasPolicyName(name string) bool {
	// policySet map[string]map[string][]*Policy
	for _, plc := range usg.policySet.policySet {
		if plc.Name() == name {
			return true
		}
	}
	return false
}

func (usg *UsgNode) HasNatName(name string) bool {
	return usg.nats.hasRuleName(name)
}

func (usg *UsgNode) HasPoolName(name string) bool {
	if _, ok := usg.nats.addressGroups[name]; ok {
		return true
	}
	// for _, poolMap := range usg.objectSet.poolMap {
	// 	for poolName, _ := range poolMap {
	// 		if poolName == name {
	// 			return true
	// 		}
	// 	}
	// }

	return false
}

func (usg *UsgNode) InputNatTargetCheck(intent *policy.Intent, inPort, outPort api.Port) (bool, firewall.FirewallNatRule) {
	return false, nil
}

func (usg *UsgNode) MakeStaticNatCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
	// 使用 v4 版本（Starlark 模板）
	// 从 PolicyContext 获取模板路径，如果没有则使用默认路径
	templatePath := firewall.GetTemplatePath(ctx)
	templates, err := v4.NewCommonTemplatesV4(usg, templatePath, nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(usg.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if usg.DeviceNode != nil {
		deviceConfig := usg.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(usg.DeviceNode.CmdIp(), true)
		return "", cmdList
	}

	// 合并 FlyObject 到 CLIString（保持与原有接口一致）
	mergedCLI := mergeFlyObjectAndCLIStringV4(result.FlyObject, result.CLIString)
	cmdList = createCmdListFromNatResultV4(usg, result)

	return mergedCLI, cmdList
}

func (usg *UsgNode) MakeDynamicNatCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
	// 使用 v4 版本（Starlark 模板）
	// 从 PolicyContext 获取模板路径，如果没有则使用默认路径
	templatePath := firewall.GetTemplatePath(ctx)
	templates, err := v4.NewCommonTemplatesV4(usg, templatePath, nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(usg.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if usg.DeviceNode != nil {
		deviceConfig := usg.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(usg.DeviceNode.CmdIp(), true)
		return "", cmdList
	}

	// 合并 FlyObject 到 CLIString（保持与原有接口一致）
	mergedCLI := mergeFlyObjectAndCLIStringV4(result.FlyObject, result.CLIString)
	cmdList = createCmdListFromNatResultV4(usg, result)

	return mergedCLI, cmdList
}

func (usg *UsgNode) MakeInputPolicyCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList, moveRule []string) {
	// 使用 v4 版本（Starlark 模板）
	// 从 PolicyContext 获取模板路径，如果没有则使用默认路径
	templatePath := firewall.GetTemplatePath(ctx)
	templates, err := v4.NewCommonTemplatesV4(usg, templatePath, nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(usg.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList, nil
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if usg.DeviceNode != nil {
		deviceConfig := usg.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(usg.DeviceNode.CmdIp(), true)
		return "", cmdList, nil
	}

	// 合并 FlyObject 到 CLIString（保持与原有接口一致）
	mergedCLI := mergeFlyObjectAndCLIStringV4(result.FlyObject, result.CLIString)
	cmdList = createCmdListFromPolicyResultV4(usg, result)

	return mergedCLI, cmdList, nil
}

func (usg *UsgNode) MakeOutputPolicyCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
	// USG 的 OutputPolicy 通常为空，但为了保持一致性，也使用 v4 版本（Starlark 模板）
	// 从 PolicyContext 获取模板路径，如果没有则使用默认路径
	templatePath := firewall.GetTemplatePath(ctx)
	templates, err := v4.NewCommonTemplatesV4(usg, templatePath, nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(usg.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if usg.DeviceNode != nil {
		deviceConfig := usg.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(usg.DeviceNode.CmdIp(), true)
		return "", cmdList
	}

	// 合并 FlyObject 到 CLIString（保持与原有接口一致）
	mergedCLI := mergeFlyObjectAndCLIStringV4(result.FlyObject, result.CLIString)
	cmdList = createCmdListFromPolicyResultV4(usg, result)

	return mergedCLI, cmdList
}

// mergeFlyObjectAndCLIStringV4 合并 FlyObject 和 CLIString，模拟原有 MergeFlyObjectAndCLIString 的行为
func mergeFlyObjectAndCLIStringV4(flyObject map[string]string, cliString string) string {
	var builder strings.Builder
	keys := []string{"NETWORK", "VIP", "MIP", "SERVICE", "POOL", "NAT", "SECURITY_POLICY"}

	// 首先添加 FlyObject 中的所有命令行
	for _, key := range keys {
		if v, ok := flyObject[key]; ok && v != "" {
			builder.WriteString(v)
			builder.WriteString("\n#\n")
		}
	}

	return strings.TrimSpace(builder.String())
}

// createCmdListFromNatResultV4 从 v4 的 NatPolicyResult 创建 command.CmdList
func createCmdListFromNatResultV4(usg *UsgNode, result *v4.NatPolicyResult) command.CmdList {
	cmdList := command.NewCliCmdList(usg.DeviceNode.CmdIp(), true)

	// 合并 FlyObject 到 CLIString
	mergedCLI := mergeFlyObjectAndCLIStringV4(result.FlyObject, result.CLIString)

	if mergedCLI != "" {
		cmdList.AddCmd(command.NewCliCmd(mergedCLI, "", 1, true))
	}

	return cmdList
}

// createCmdListFromPolicyResultV4 从 v4 的 PolicyResult 创建 command.CmdList
func createCmdListFromPolicyResultV4(usg *UsgNode, result *v4.PolicyResult) command.CmdList {
	cmdList := command.NewCliCmdList(usg.DeviceNode.CmdIp(), true)

	// 合并 FlyObject 到 CLIString
	mergedCLI := mergeFlyObjectAndCLIStringV4(result.FlyObject, result.CLIString)

	if mergedCLI != "" {
		cmdList.AddCmd(command.NewCliCmd(mergedCLI, "", 1, true))
	}

	return cmdList
}

func (usg *UsgNode) InPacket(from, to api.Port, entry policy.PolicyEntryInf) (firewall.Action, firewall.FirewallPolicy) {

	// func (ps *PolicySet) Match(from, to string, pe policy.PolicyEntryInf) (bool, firewall.FirewallPolicy) {
	ok, rule := usg.policySet.Match(from.(*UsgPort).Zone(), to.(*UsgPort).Zone(), entry)
	if !ok {
		return firewall.POLICY_IMPLICIT_DENY, nil
	} else {
		return rule.(*Policy).Action(), rule
	}

	// return firewall.POLICY_IMPLICIT_DENY, nil
}

func (usg *UsgNode) OutPacket(from, to api.Port, entry policy.PolicyEntryInf) (firewall.Action, firewall.FirewallPolicy) {

	return firewall.POLICY_IMPLICIT_PERMIT, nil
}

func (usg *UsgNode) ServiceObjectToDb(db *gorm.DB, task_id uint) {
}

func (usg *UsgNode) NetworkObjectToDb(db *gorm.DB, task_id uint) {
}

func (usg *UsgNode) PolicyToDb(db *gorm.DB, task_id uint) {
}

func (usg *UsgNode) AclToDb(db *gorm.DB, task_id uint) {
}

func (usg *UsgNode) AddressGroupToDb(db *gorm.DB, task_id uint) {
}

func (usg *UsgNode) NatsToDb(db *gorm.DB, task_id uint) {
}

func (usg *UsgNode) ExtraToDb(db *gorm.DB, task_id uint) {
}

func (usg *UsgNode) Policies() []firewall.FirewallPolicy {
	policies := []firewall.FirewallPolicy{}
	for _, plc := range usg.policySet.policySet {
		policies = append(policies, plc)
		// for _, plcList := range toMap {
		// 	for _, policy := range plcList {
		// 		policies = append(policies, policy)
		// 	}
		// }
	}

	return policies
}

func (usg *UsgNode) NextPoolId(id string) string {
	// 如果提供了 id，直接返回
	if id != "" {
		return id
	}

	maxId := 0

	// 检查地址组
	for _, ag := range usg.nats.addressGroups {
		groupId, err := strconv.Atoi(ag.GroupNumber)
		if err == nil && groupId > maxId {
			maxId = groupId
		}
	}

	// 检查内部池
	for _, pool := range usg.nats.insidePools {
		poolId, err := strconv.Atoi(pool.PoolID)
		if err == nil && poolId > maxId {
			maxId = poolId
		}
	}

	// 检查全局池
	for _, pool := range usg.nats.globalPools {
		poolId, err := strconv.Atoi(pool.PoolID)
		if err == nil && poolId > maxId {
			maxId = poolId
		}
	}

	// 返回最大 ID + 1
	return strconv.Itoa(maxId + 1)
}

// GetPolicyName 实现FirewallNode接口，返回策略名称
// USG使用命名模板，所以返回空字符串表示使用模板生成
func (usg *UsgNode) GetPolicyName(ctx *firewall.PolicyContext) (string, error) {
	// USG使用命名模板生成策略名称，返回空字符串表示使用模板
	return "", nil
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*api.Node)(nil)).Elem(), "UsgNode", reflect.TypeOf(UsgNode{}))
}

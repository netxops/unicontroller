package srx

import (
	"encoding/json"
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
	"github.com/netxops/utils/service"

	"gorm.io/gorm"
)

var _ firewall.FirewallNode = &SRXNode{}

type SRXNode struct {
	*node.DeviceNode
	objectSet      *SRXObjectSet
	policySet      *PolicySet
	nats           *Nats
	snatDesignInfo []*config.SnatDesignInfo
}

func (srx *SRXNode) Type() terminalmode.DeviceType {
	return terminalmode.SRX
}

// TypeName 实现 TypeInterface 接口
func (srx *SRXNode) TypeName() string {
	return "SRXNode"
}

// srxNodeJSON 用于序列化和反序列化
type srxNodeJSON struct {
	DeviceNode     json.RawMessage          `json:"device_node"`
	ObjectSet      *SRXObjectSet            `json:"object_set"`
	PolicySet      *PolicySet               `json:"policy_set"`
	Nats           *Nats                    `json:"nats"`
	SnatDesignInfo []*config.SnatDesignInfo `json:"snat_design_info"`
}

// MarshalJSON 实现 JSON 序列化
func (srx *SRXNode) MarshalJSON() ([]byte, error) {
	deviceNodeJSON, err := json.Marshal(srx.DeviceNode)
	if err != nil {
		return nil, err
	}

	return json.Marshal(srxNodeJSON{
		DeviceNode:     deviceNodeJSON,
		ObjectSet:      srx.objectSet,
		PolicySet:      srx.policySet,
		Nats:           srx.nats,
		SnatDesignInfo: srx.snatDesignInfo,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (srx *SRXNode) UnmarshalJSON(data []byte) error {
	var sn srxNodeJSON
	if err := json.Unmarshal(data, &sn); err != nil {
		return err
	}

	if err := json.Unmarshal(sn.DeviceNode, &srx.DeviceNode); err != nil {
		return err
	}

	srx.objectSet = sn.ObjectSet
	srx.policySet = sn.PolicySet
	srx.nats = sn.Nats
	srx.snatDesignInfo = sn.SnatDesignInfo

	return nil
}

// func (srx *SRXNode) ExtraInit(adapter api.Adapter, deviceConfig *config.DeviceConfig) {
// }

func (srx *SRXNode) InputNat(intent *policy.Intent, inPort api.Port) processor.AbstractMatchResult {
	ok, translateTo, rule := srx.nats.inputNat(intent, inPort)

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

func (srx *SRXNode) OutputNat(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	ok, translateTo, rule := srx.nats.outputNat(intent, inPort, outPort)

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

func (srx *SRXNode) InputPolicy(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	action, rule := srx.InPacket(inPort, outPort, intent)
	// action, rule := srx.matrix.InPacket(inPort, outPort, intent)
	result := firewall.NewPolicyResultIntent(intent)
	result.WithFromPort(inPort)
	result.WithOutPort(outPort)
	result.WithRule(rule)
	result.WithAction(action)

	return result
}

func (srx *SRXNode) OutputPolicy(intent *policy.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	// func (srx *SRXNode) OutputPolicy(intent *policy.Intent, inPort, outPort api.Port) firewall.PolicyMatchResult {
	return nil
}

func (srx *SRXNode) DefaultStep(fp *firewall.FirewallProcess) {
	fp.WithInputPolicy()
}

func (srx *SRXNode) UpdateSnatStep(in, out api.Port, intent *policy.Intent, fp *firewall.FirewallProcess) {
	inZone := in.(*SRXPort).Zone()
	outZone := out.(*SRXPort).Zone()

	// 检查是否需要SNAT
	needSnat := false
	for _, snatInfo := range srx.snatDesignInfo {
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

func (srx *SRXNode) GetPoolByNetworkGroup(ng *network.NetworkGroup, natType firewall.NatType) (firewall.FirewallNetworkObject, bool) {
	return srx.objectSet.GetPoolByeNetworkGroup(ng, natType)
}

// GetSupportedNatObjectTypes 获取该防火墙支持的NAT对象类型
// SRX: DNAT支持VIP（特殊语法pool），SNAT支持SNAT_POOL（特殊语法pool）
func (srx *SRXNode) GetSupportedNatObjectTypes(natType string) []firewall.NatObjectType {
	if natType == "DNAT" {
		// VIP使用特殊语法pool
		return []firewall.NatObjectType{firewall.VIP}
	}
	if natType == "SNAT" {
		// SNAT_POOL使用特殊语法pool
		return []firewall.NatObjectType{firewall.SNAT_POOL, firewall.INTERFACE, firewall.INLINE}
	}
	return []firewall.NatObjectType{}
}

// GetObjectByVipMipSnatPool 检查VIP/MIP/SNAT_POOL对象是否已存在（复用检查）
// SRX: 支持VIP和SNAT_POOL，都使用pool对象
func (srx *SRXNode) GetObjectByVipMipSnatPool(objectType string, intent *policy.Intent) (firewall.FirewallNetworkObject, bool) {
	if objectType == "VIP" && intent.RealIp != "" {
		// VIP通过destination pool实现，查找pool对象
		realIpNg, err := network.NewNetworkGroupFromString(intent.RealIp)
		if err == nil {
			// 查找destination pool（DNAT pool）
			return srx.GetPoolByNetworkGroup(realIpNg, firewall.DESTINATION_NAT)
		}
	}
	if objectType == "SNAT_POOL" && intent.Snat != "" {
		// SNAT_POOL通过pool实现
		snatNg, err := network.NewNetworkGroupFromString(intent.Snat)
		if err == nil {
			return srx.GetPoolByNetworkGroup(snatNg, firewall.DYNAMIC_NAT)
		}
	}
	// MIP不支持
	return nil, false
}

// GenerateVipMipSnatPoolName 自动生成VIP/MIP/SNAT_POOL对象名称（可选）
// SRX: 不提供自动命名，返回空字符串使用配置模板
func (srx *SRXNode) GenerateVipMipSnatPoolName(objectType string, intent *policy.Intent, metaData map[string]interface{}) string {
	// SRX不提供自动命名，返回空字符串使用配置模板
	return ""
}

// GetReuseNatObject 获取可重用的NAT对象名称
// SRX: 支持VIP（destination pool）和SNAT_POOL（dynamic pool），不支持MIP
//
// 通过natType和metaData配置来决定objectType，然后进行复用查询
func (srx *SRXNode) GetReuseNatObject(natType string, intent *policy.Intent, metaData map[string]interface{}) (name string, reused bool) {
	// 根据natType和metaData确定objectType
	// 对于DNAT和SNAT，一定会命中一种防火墙支持的对象类型清单，同时结合metaData中的配置，最终选择一种对象类型
	objectType, ok := srx.DetermineNatObjectType(natType, metaData)
	if !ok {
		return "", false
	}

	// INTERFACE/INLINE 类型不需要生成对象，直接返回
	if objectType == firewall.INTERFACE || objectType == firewall.INLINE {
		return "", false
	}

	// 根据objectType进行复用查询
	if natType == "DNAT" {
		// DNAT: 处理 VIP（不支持MIP）
		// VIP需要匹配real_ip和real_port
		if objectType == firewall.VIP {
			realIpNg, err := network.NewNetworkGroupFromString(intent.RealIp)
			if err == nil {
				obj, found := srx.GetPoolByNetworkGroup(realIpNg, firewall.DESTINATION_NAT)
				if found {
					// VIP需要检查端口是否匹配
					pool, ok := obj.(*NatPool)
					if ok {
						// 如果pool有端口配置，需要匹配real_port
						if pool.L4Port() != nil {
							// 如果intent有real_port，需要匹配
							if intent.RealPort != "" {
								realPort, err := strconv.Atoi(intent.RealPort)
								if err == nil {
									// 检查pool的端口是否包含real_port
									poolPort := pool.L4Port()
									// 遍历pool的端口范围，检查是否包含realPort
									for it := poolPort.Iterator(); it.HasNext(); {
										_, portRange := it.Next()
										if portRange.Low().Int64() <= int64(realPort) && int64(realPort) <= portRange.High().Int64() {
											return obj.Name(), true
										}
									}
								}
							}
							// 如果intent没有real_port，但pool有端口，不匹配
						} else {
							// pool没有端口配置，如果intent也没有real_port，可以匹配
							if intent.RealPort == "" {
								return obj.Name(), true
							}
						}
					} else {
						// 如果不是NatPool类型，只匹配IP
						return obj.Name(), true
					}
				}
			}
		}
		// DNAT + MIP: 查找地址对象
		if objectType == firewall.MIP {
			realIpNg, err := network.NewNetworkGroupFromString(intent.RealIp)
			if err == nil {
				obj, found := srx.GetPoolByNetworkGroup(realIpNg, firewall.DESTINATION_NAT)
				if found {
					return obj.Name(), true
				}
			}
		}

	} else if natType == "SNAT" {
		// SNAT: 处理 SNAT_POOL
		if objectType == firewall.SNAT_POOL {
			snatNg, err := network.NewNetworkGroupFromString(intent.Snat)
			if err == nil {
				obj, found := srx.GetPoolByNetworkGroup(snatNg, firewall.DYNAMIC_NAT)
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
func (srx *SRXNode) DetermineNatObjectType(natType string, metaData map[string]interface{}) (firewall.NatObjectType, bool) {
	switch natType {
	case "DNAT":
		// SRX的DNAT支持VIP（使用destination pool）
		objectType := getStringFromMeta(metaData, "dnat_object_type", "VIP")
		switch objectType {
		case "VIP":
			return firewall.VIP, true
		case "MIP":
			return firewall.MIP, true
		}
	case "SNAT":
		// SRX的SNAT支持SNAT_POOL（使用dynamic pool）、INTERFACE和INLINE
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

func (srx *SRXNode) GetObjectByNetworkGroup(ng *network.NetworkGroup, searchType firewall.ObjectSearchType, port api.Port) (firewall.FirewallNetworkObject, bool) {
	return srx.objectSet.GetObjectByNetworkGroup(ng, searchType, port)
}

func (srx *SRXNode) GetObjectByService(s *service.Service, searchType firewall.ObjectSearchType) (firewall.FirewallServiceObject, bool) {
	return nil, false
}

func (srx *SRXNode) Network(zone, name string) (*network.NetworkGroup, bool) {
	return srx.objectSet.Network(zone, name)
}

func (srx *SRXNode) Service(name string) (*service.Service, bool) {
	return srx.objectSet.Service(name)
}

func (srx *SRXNode) L4Port(name string) (*service.L4Port, bool) {
	return nil, false
}

func (srx *SRXNode) HasObjectName(name string) bool {
	return srx.objectSet.hasObjectName(name)
}

func (srx *SRXNode) HasPolicyName(name string) bool {
	// policySet map[string]map[string][]*Policy
	for policyName, _ := range srx.policySet.policySet {
		if policyName == name {
			return true
		}
	}
	return false
}

func (srx *SRXNode) HasNatName(name string) bool {
	return srx.nats.hasRuleName(name)
}

func (srx *SRXNode) HasPoolName(name string) bool {
	for _, poolMap := range srx.objectSet.poolMap {
		for poolName, _ := range poolMap {
			if poolName == name {
				return true
			}
		}
	}

	return false
}

func (srx *SRXNode) InputNatTargetCheck(intent *policy.Intent, inPort, outPort api.Port) (bool, firewall.FirewallNatRule) {
	return false, nil
}

func (srx *SRXNode) MakeStaticNatCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
	// 使用 v4 版本（Starlark 模板）
	templates, err := v4.NewCommonTemplatesV4(srx, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(srx.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if srx.DeviceNode != nil {
		deviceConfig := srx.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(srx.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromNatResultV4(srx, result)
}

func (srx *SRXNode) MakeDynamicNatCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
	// 使用 v4 版本（Starlark 模板）
	// 从 PolicyContext 获取模板路径，如果没有则使用默认路径
	templatePath := firewall.GetTemplatePath(ctx)
	templates, err := v4.NewCommonTemplatesV4(srx, templatePath, nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(srx.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if srx.DeviceNode != nil {
		deviceConfig := srx.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(srx.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromNatResultV4(srx, result)
}

func (srx *SRXNode) MakeInputPolicyCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList, moveRule []string) {
	// 使用 v4 版本（Starlark 模板）
	// 从 PolicyContext 获取模板路径，如果没有则使用默认路径
	templatePath := firewall.GetTemplatePath(ctx)
	templates, err := v4.NewCommonTemplatesV4(srx, templatePath, nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(srx.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList, nil
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if srx.DeviceNode != nil {
		deviceConfig := srx.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(srx.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList, nil
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromPolicyResultV4(srx, result), nil
}

func (srx *SRXNode) MakeOutputPolicyCli(from, out api.Port, intent *policy.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
	// SRX doesn't typically use output policy, but use v4 for consistency
	// 使用 v4 版本（Starlark 模板）
	templates, err := v4.NewCommonTemplatesV4(srx, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(srx.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if srx.DeviceNode != nil {
		deviceConfig := srx.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(srx.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromPolicyResultV4(srx, result)
}

// createCmdListFromNatResultV4 从 v4 的 NatPolicyResult 创建 command.CmdList
func createCmdListFromNatResultV4(srx *SRXNode, result *v4.NatPolicyResult) command.CmdList {
	cmdList := command.NewCliCmdList(srx.DeviceNode.CmdIp(), true)

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
func createCmdListFromPolicyResultV4(srx *SRXNode, result *v4.PolicyResult) command.CmdList {
	cmdList := command.NewCliCmdList(srx.DeviceNode.CmdIp(), true)

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

func (srx *SRXNode) InPacket(from, to api.Port, entry policy.PolicyEntryInf) (firewall.Action, firewall.FirewallPolicy) {

	// func (ps *PolicySet) Match(from, to string, pe policy.PolicyEntryInf) (bool, firewall.FirewallPolicy) {
	ok, rule := srx.policySet.Match(from.(*SRXPort).Zone(), to.(*SRXPort).Zone(), entry)
	if !ok {
		return firewall.POLICY_IMPLICIT_DENY, nil
	} else {
		return rule.(*Policy).Action(), rule
	}

	// return firewall.POLICY_IMPLICIT_DENY, nil
}

func (srx *SRXNode) OutPacket(from, to api.Port, entry policy.PolicyEntryInf) (firewall.Action, firewall.FirewallPolicy) {

	return firewall.POLICY_IMPLICIT_PERMIT, nil
}

func (srx *SRXNode) ServiceObjectToDb(db *gorm.DB, task_id uint) {
}

func (srx *SRXNode) NetworkObjectToDb(db *gorm.DB, task_id uint) {
}

func (srx *SRXNode) PolicyToDb(db *gorm.DB, task_id uint) {
}

func (srx *SRXNode) AclToDb(db *gorm.DB, task_id uint) {
}

func (srx *SRXNode) AddressGroupToDb(db *gorm.DB, task_id uint) {
}

func (srx *SRXNode) NatsToDb(db *gorm.DB, task_id uint) {
}

func (srx *SRXNode) ExtraToDb(db *gorm.DB, task_id uint) {
}

func (srx *SRXNode) Policies() []firewall.FirewallPolicy {
	policies := []firewall.FirewallPolicy{}
	for _, toMap := range srx.policySet.policySet {
		for _, plcList := range toMap {
			for _, policy := range plcList {
				policies = append(policies, policy)
			}
		}
	}

	return policies
}

// GetPolicyName 获取策略名称（SRX使用命名模板，返回空字符串）
func (srx *SRXNode) GetPolicyName(ctx *firewall.PolicyContext) (string, error) {
	// SRX使用命名模板生成策略名称，返回空字符串让模板系统使用命名模板
	return "", nil
}

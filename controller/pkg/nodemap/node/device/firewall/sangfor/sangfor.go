package sangfor

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
	policyutil "github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
)

var _ firewall.FirewallNode = &SangforNode{}
var _ firewall.FirewallTemplates = &SangforNode{}

type SangforNode struct {
	*node.DeviceNode
	objectSet      *SangforObjectSet
	policySet      *PolicySet
	nats           *Nats
	snatDesignInfo []*config.SnatDesignInfo
}

func (sangfor *SangforNode) Type() terminalmode.DeviceType {
	return terminalmode.Sangfor
}

// TypeName 实现 TypeInterface 接口
func (sangfor *SangforNode) TypeName() string {
	return "SangforNode"
}

// sangforNodeJSON 用于序列化和反序列化
type sangforNodeJSON struct {
	DeviceNode     json.RawMessage          `json:"device_node"`
	ObjectSet      *SangforObjectSet        `json:"object_set"`
	PolicySet      *PolicySet               `json:"policy_set"`
	Nats           *Nats                    `json:"nats"`
	SnatDesignInfo []*config.SnatDesignInfo `json:"snat_design_info"`
}

// MarshalJSON 实现 JSON 序列化
func (sangfor *SangforNode) MarshalJSON() ([]byte, error) {
	deviceNodeJSON, err := json.Marshal(sangfor.DeviceNode)
	if err != nil {
		return nil, err
	}

	return json.Marshal(sangforNodeJSON{
		DeviceNode:     deviceNodeJSON,
		ObjectSet:      sangfor.objectSet,
		PolicySet:      sangfor.policySet,
		Nats:           sangfor.nats,
		SnatDesignInfo: sangfor.snatDesignInfo,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (sangfor *SangforNode) UnmarshalJSON(data []byte) error {
	var sangforj sangforNodeJSON
	if err := json.Unmarshal(data, &sangforj); err != nil {
		return err
	}

	if err := json.Unmarshal(sangforj.DeviceNode, &sangfor.DeviceNode); err != nil {
		return err
	}

	sangfor.objectSet = sangforj.ObjectSet
	sangfor.policySet = sangforj.PolicySet
	if sangfor.policySet != nil {
		sangfor.policySet.objects = sangfor.objectSet
	}
	sangfor.nats = sangforj.Nats
	sangfor.snatDesignInfo = sangforj.SnatDesignInfo

	if sangfor.policySet != nil {
		for _, plc := range sangfor.policySet.policySet {
			plc.node = sangfor
			plc.objects = sangfor.objectSet
		}
	}

	if sangfor.nats != nil {
		nats := [][]*NatRule{sangfor.nats.destinationNatRules, sangfor.nats.sourceNatRules, sangfor.nats.destinationNatRules, sangfor.nats.natPolicyRules, sangfor.nats.natServers}
		for _, rules := range nats {
			for _, rule := range rules {
				rule.node = sangfor
				rule.objects = sangfor.objectSet
			}
		}
	}
	return nil
}

func (sangfor *SangforNode) InputNat(intent *policyutil.Intent, inPort api.Port) processor.AbstractMatchResult {
	ok, translateTo, rule := sangfor.nats.inputNat(intent, inPort)

	result := firewall.NewNatResultIntent(intent)
	result.WithTranslate(translateTo)
	result.WithFromPort(inPort)
	result.WithRule(rule)
	if ok {
		result.WithAction(firewall.NAT_MATCHED)
	} else {
		result.WithAction(firewall.NAT_NOMATCHED)
	}

	result.Analysis()
	return result
}

func (sangfor *SangforNode) OutputNat(intent *policyutil.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	ok, translateTo, rule := sangfor.nats.outputNat(intent, inPort, outPort)

	result := firewall.NewNatResultIntent(intent)
	result.WithFromPort(inPort)
	result.WithOutPort(outPort)
	result.WithTranslate(translateTo)
	result.WithRule(rule)

	if ok {
		result.WithAction(firewall.NAT_MATCHED)
	} else {
		result.WithAction(firewall.NAT_NOMATCHED)
	}

	result.Analysis()
	return result
}

func (sangfor *SangforNode) InputPolicy(intent *policyutil.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	fmt.Printf("[DEBUG InputPolicy] 开始处理 InputPolicy\n")
	fmt.Printf("  节点: %s\n", sangfor.Name())
	fmt.Printf("  入接口: %s, 出接口: %s\n", inPort.Name(), outPort.Name())
	if intent != nil {
		fmt.Printf("  Intent: %s\n", intent.String())
	}

	action, rule := sangfor.InPacket(inPort, outPort, intent)

	actionStr := "UNKNOWN"
	switch action {
	case firewall.POLICY_PERMIT:
		actionStr = "PERMIT"
	case firewall.POLICY_DENY:
		actionStr = "DENY"
	case firewall.POLICY_IMPLICIT_DENY:
		actionStr = "IMPLICIT_DENY"
	}
	fmt.Printf("[DEBUG InputPolicy] 匹配结果: Action=%s (%d), Rule=%v\n", actionStr, action, rule != nil)
	if rule != nil {
		if p, ok := rule.(*Policy); ok {
			fmt.Printf("  匹配的策略名称: %s\n", p.Name())
		}
	}

	result := firewall.NewPolicyResultIntent(intent)
	result.WithFromPort(inPort)
	result.WithOutPort(outPort)
	result.WithRule(rule)
	result.WithAction(action)

	return result
}

func (sangfor *SangforNode) OutputPolicy(intent *policyutil.Intent, inPort, outPort api.Port) processor.AbstractMatchResult {
	// Sangfor 默认允许输出策略，类似于 FortiGate
	result := firewall.NewPolicyResultIntent(intent)
	result.WithFromPort(inPort)
	result.WithOutPort(outPort)
	result.WithRule(nil)
	result.WithAction(firewall.POLICY_IMPLICIT_PERMIT)
	return result
}

func (sangfor *SangforNode) DefaultStep(fp *firewall.FirewallProcess) {
	fp.WithInputPolicy()
}

func (sangfor *SangforNode) UpdateSnatStep(from, to api.Port, intent *policyutil.Intent, fp *firewall.FirewallProcess) {
	fp.WithInputPolicy()
	fp.WithOutputNat()
}

func (sangfor *SangforNode) InputNatTargetCheck(intent *policyutil.Intent, inPort, outPort api.Port) (bool, firewall.FirewallNatRule) {
	return sangfor.nats.inputNatTargetCheck(intent, inPort, outPort)
}

func (sangfor *SangforNode) GetObjectByNetworkGroup(ng *network.NetworkGroup, searchType firewall.ObjectSearchType, port api.Port) (firewall.FirewallNetworkObject, bool) {
	return sangfor.objectSet.GetObjectByNetworkGroup(ng, searchType, port)
}

// NextPoolId 返回下一个可用的 IP Pool ID
// Sangfor 使用名称而不是数字 ID，所以返回一个基于名称的 ID
func (sangfor *SangforNode) NextPoolId(id string) string {
	// 如果提供了 id，直接返回
	if id != "" {
		return id
	}

	// Sangfor 使用名称而不是数字 ID
	// 返回一个基于现有池数量的递增数字，从 1 开始
	maxId := 0

	// 检查现有的网络对象，找到类型为 OBJECT_POOL 的对象
	if sangfor.objectSet != nil && sangfor.objectSet.networkMap != nil {
		for _, obj := range sangfor.objectSet.networkMap {
			if obj.objType == firewall.OBJECT_POOL {
				// 尝试从名称中提取数字 ID
				// 例如 "pool_1", "pool_2" 等
				name := obj.name
				// 如果名称包含数字，尝试提取
				// 这里简化处理，假设名称格式为 "pool_N" 或类似格式
				// 实际实现可能需要更复杂的解析逻辑
				if len(name) > 0 {
					// 尝试提取名称中的数字部分
					// 这里简化处理，返回一个基于现有池数量的 ID
					maxId++
				}
			}
		}
	}

	// 返回下一个可用的 ID（从 1 开始）
	return fmt.Sprintf("%d", maxId+1)
}

func (sangfor *SangforNode) GetObjectByService(sg *service.Service, searchType firewall.ObjectSearchType) (firewall.FirewallServiceObject, bool) {
	return sangfor.objectSet.GetObjectByService(sg, searchType)
}

func (sangfor *SangforNode) GetPoolByNetworkGroup(ng *network.NetworkGroup, natType firewall.NatType) (firewall.FirewallNetworkObject, bool) {
	return sangfor.nats.GetPoolByNetworkGroup(ng, natType)
}

// GetSupportedNatObjectTypes 获取该防火墙支持的NAT对象类型
// Sangfor: DNAT支持MIP（NetworkObject），SNAT不支持SNAT_POOL
func (sangfor *SangforNode) GetSupportedNatObjectTypes(natType string) []firewall.NatObjectType {
	if natType == "DNAT" {
		// MIP使用NetworkObject
		return []firewall.NatObjectType{firewall.NETWORK_OBJECT}
	}
	if natType == "SNAT" {
		// Sangfor不支持SNAT_POOL，只支持INTERFACE和NETWORK_OBJECT
		return []firewall.NatObjectType{firewall.INTERFACE, firewall.NETWORK_OBJECT, firewall.INLINE}
	}
	return []firewall.NatObjectType{}
}

// GetObjectByVipMipSnatPool 检查VIP/MIP/SNAT_POOL对象是否已存在（复用检查）
// Sangfor: 不支持VIP/MIP/SNAT_POOL对象，返回false
func (sangfor *SangforNode) GetObjectByVipMipSnatPool(objectType string, intent *policyutil.Intent) (firewall.FirewallNetworkObject, bool) {
	// Sangfor不支持VIP/MIP/SNAT_POOL对象
	return nil, false
}

// GenerateVipMipSnatPoolName 自动生成VIP/MIP/SNAT_POOL对象名称（可选）
// Sangfor: 不提供自动命名，返回空字符串使用配置模板
func (sangfor *SangforNode) GenerateVipMipSnatPoolName(objectType string, intent *policyutil.Intent, metaData map[string]interface{}) string {
	// Sangfor不提供自动命名，返回空字符串使用配置模板
	return ""
}

// GetReuseNatObject 获取可重用的NAT对象名称
// Sangfor: DNAT使用NETWORK_OBJECT（地址对象），SNAT根据配置可能使用NETWORK_OBJECT、INTERFACE或INLINE
// 通过natType和metaData配置来决定objectType，然后进行复用查询
func (sangfor *SangforNode) GetReuseNatObject(natType string, intent *policyutil.Intent, metaData map[string]interface{}) (name string, reused bool) {
	// 根据natType和metaData确定objectType
	// 对于DNAT和SNAT，一定会命中一种防火墙支持的对象类型清单，同时结合metaData中的配置，最终选择一种对象类型
	objectType, ok := sangfor.DetermineNatObjectType(natType, metaData)
	if !ok {
		return "", false
	}

	// INTERFACE/INLINE 类型不需要生成对象
	if objectType == firewall.INTERFACE || objectType == firewall.INLINE {
		return "", false
	}

	// NETWORK_OBJECT 类型：需要查找复用对象
	if objectType == firewall.NETWORK_OBJECT {
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
			obj, found := sangfor.GetObjectByNetworkGroup(ng, firewall.SEARCH_OBJECT_OR_GROUP, nil)
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
func (sangfor *SangforNode) DetermineNatObjectType(natType string, metaData map[string]interface{}) (firewall.NatObjectType, bool) {
	switch natType {
	case "DNAT":
		objectType := getStringFromMeta(metaData, "dnat_object_type", "NETWORK_OBJECT")
		if objectType == "NETWORK_OBJECT" {
			return firewall.NETWORK_OBJECT, true
		}
	case "SNAT":
		poolType := getStringFromMeta(metaData, "snat_pool_type", "NETWORK_OBJECT")
		if poolType == "NETWORK_OBJECT" {
			return firewall.NETWORK_OBJECT, true
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

func (sangfor *SangforNode) Network(zone, name string) (*network.NetworkGroup, bool) {
	return sangfor.objectSet.Network(zone, name)
}

func (sangfor *SangforNode) Service(name string) (*service.Service, bool) {
	return sangfor.objectSet.Service(name)
}

func (sangfor *SangforNode) L4Port(name string) (*service.L4Port, bool) {
	return sangfor.objectSet.L4Port(name)
}

func (sangfor *SangforNode) HasObjectName(name string) bool {
	return sangfor.objectSet.HasObjectName(name)
}

func (sangfor *SangforNode) HasPolicyName(name string) bool {
	return sangfor.policySet.HasPolicyName(name)
}

func (sangfor *SangforNode) HasPoolName(name string) bool {
	return sangfor.nats.HasPoolName(name)
}

func (sangfor *SangforNode) HasNatName(name string) bool {
	return sangfor.nats.HasNatName(name)
}

func (sangfor *SangforNode) Policies() []firewall.FirewallPolicy {
	return sangfor.policySet.Policies()
}

// FirewallTemplates 接口实现
func (sangfor *SangforNode) MakeStaticNatCli(from, out api.Port, intent *policyutil.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
	// 使用 v4 版本（Starlark 模板）
	templates, err := v4.NewCommonTemplatesV4(sangfor, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(sangfor.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if sangfor.DeviceNode != nil {
		deviceConfig := sangfor.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(sangfor.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromNatResultV4(sangfor, result)
}

func (sangfor *SangforNode) MakeDynamicNatCli(from, out api.Port, intent *policyutil.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
	// 使用 v4 版本（Starlark 模板）
	templates, err := v4.NewCommonTemplatesV4(sangfor, "pkg/nodemap/node/device/firewall/common/v4/templates", nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(sangfor.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if sangfor.DeviceNode != nil {
		deviceConfig := sangfor.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(sangfor.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromNatResultV4(sangfor, result)
}

func (sangfor *SangforNode) MakeInputPolicyCli(from, out api.Port, intent *policyutil.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList, moveRule []string) {
	// 使用 v4 版本（Starlark 模板）
	// 从 PolicyContext 获取模板路径，如果没有则使用默认路径
	templatePath := firewall.GetTemplatePath(ctx)
	templates, err := v4.NewCommonTemplatesV4(sangfor, templatePath, nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(sangfor.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList, nil
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if sangfor.DeviceNode != nil {
		deviceConfig := sangfor.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(sangfor.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList, nil
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromPolicyResultV4(sangfor, result), nil
}

// GetPolicyName 获取策略名称（Sangfor使用命名模板，返回空字符串）
func (sangfor *SangforNode) GetPolicyName(ctx *firewall.PolicyContext) (string, error) {
	// Sangfor使用命名模板生成策略名称，这里返回空字符串让模板系统处理
	return "", nil
}

func (sangfor *SangforNode) MakeOutputPolicyCli(from, out api.Port, intent *policyutil.Intent, ctx *firewall.PolicyContext) (flyObject interface{}, cmdList command.CmdList) {
	// 使用 v4 版本（Starlark 模板）
	// 从 PolicyContext 获取模板路径，如果没有则使用默认路径
	templatePath := firewall.GetTemplatePath(ctx)
	templates, err := v4.NewCommonTemplatesV4(sangfor, templatePath, nil)
	if err != nil {
		// 如果创建失败，返回空结果
		cmdList := command.NewCliCmdList(sangfor.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 获取 metadata
	metaData := make(map[string]interface{})
	if sangfor.DeviceNode != nil {
		deviceConfig := sangfor.DeviceNode.GetDeviceConfig()
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
		cmdList := command.NewCliCmdList(sangfor.DeviceNode.CmdIp(), true)
		return make(map[string]string), cmdList
	}

	// 返回 FlyObject
	return result.FlyObject, createCmdListFromPolicyResultV4(sangfor, result)
}

// createCmdListFromNatResultV4 从 v4 的 NatPolicyResult 创建 command.CmdList
func createCmdListFromNatResultV4(sangfor *SangforNode, result *v4.NatPolicyResult) command.CmdList {
	cmdList := command.NewCliCmdList(sangfor.DeviceNode.CmdIp(), true)

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
func createCmdListFromPolicyResultV4(sangfor *SangforNode, result *v4.PolicyResult) command.CmdList {
	cmdList := command.NewCliCmdList(sangfor.DeviceNode.CmdIp(), true)

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

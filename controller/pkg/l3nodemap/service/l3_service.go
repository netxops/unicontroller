package service

import (
	"errors"
	"fmt"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/l3nodemap/global"
	"github.com/influxdata/telegraf/controller/pkg/l3nodemap/model/meta"
	"github.com/influxdata/telegraf/controller/pkg/nodemap"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/model"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/processor"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
	"go.uber.org/zap"
)

var Logger = global.GetLogger()

type NodemapService struct {
	MNM meta.MetaNodeMap
}

func (mnm *NodemapService) MakeL3Templates(sourceInfo *structs.NodemapInfo, result *model.TemplatesReplay) error {
	if len(sourceInfo.DeviceInfos) == 0 {
		err := errors.New("source device info is empty")
		Logger.Error("l3 service request failed .. ", zap.Error(err))
		return err
	}

	if len(sourceInfo.IntentInfos) == 0 {
		err := fmt.Errorf("source intent info is empty")
		Logger.Error("l3 service request failed .. ", zap.Error(err))
		return err
	}

	// if len(sourceInfo.DeviceConfigs) == 0 {
	// 	err := fmt.Errorf("source device configs is empty")
	// 	Logger.Error("l3 service request failed .. ", zap.Error(err))
	// 	return err
	// }

	// 1.=====工单项信息构建
	intents := makeIntents(sourceInfo)
	if len(intents) == 0 {
		err := fmt.Errorf("policy intent data is empty")
		Logger.Error("l3 service request failed .. ", zap.Error(err))
		return err
	}
	Logger.Info("工单项信息：", zap.Any("intents", intents))

	// 2.=====匹配设备，构建设备用户密码信息等
	deviceConfigs := makeDeviceConfig(mnm.MNM, sourceInfo)
	if len(deviceConfigs) == 0 {
		err := fmt.Errorf("device config data is empty")
		Logger.Error("l3 service request failed .. ", zap.Error(err))
		return err
	}
	Logger.Info("设备配置信息：", zap.Any("deviceConfig", deviceConfigs))

	// 3.=====生成L3NodeMap
	nodemapId := uint(0)
	nm, ctx := nodemap.NewNodeMapFromNetwork(mnm.MNM.Name, deviceConfigs, true, 123456, &nodemapId)
	nm.WithLogger(Logger)
	Logger.Info("nodeMap result =====> ", zap.Any("nodeMap result", nm), zap.Any("context", ctx))

	//3.======开始生成结果模板
	templateResult := model.TemplateResult{
		Result: []*model.TemplateResultItem{},
	}

	others := nodemap.TraverseResult{}

	for itemId, v := range intents {
		template := *nm.MakeTemplates(&v, ctx)
		others.Items = template.Results.Items
		Logger.Info("template before perfect results =====> ", zap.Any("template before perfect results", others))
		templateResult = perfectTemplateResult(template, templateResult, itemId)
		Logger.Info("template after perfect results =====> ", zap.Any("template after perfect result", templateResult))
	}
	result.Result = &templateResult
	return nil
}

// ComparePolicyRequest 策略对比请求结构
type ComparePolicyRequest struct {
	NodeName string        `json:"node_name"` // 节点名称
	RuleName string        `json:"rule_name"` // 规则名称
	Intent   policy.Intent `json:"intent"`    // 策略意图
}

// ExcelPolicyRule Excel中的策略规则（用于展示）
type ExcelPolicyRule struct {
	RuleName        string   `json:"rule_name"`        // 规则名称
	SourceZone      []string `json:"source_zone"`      // 源区域
	DestinationZone []string `json:"destination_zone"` // 目的区域
	SourceIP        string   `json:"source_ip"`        // 源IP
	DestinationIP   string   `json:"destination_ip"`   // 目的IP
	Port            string   `json:"port"`             // 端口
	Protocol        string   `json:"protocol"`         // 协议
	Action          string   `json:"action"`           // 动作
}

// ConfigFragmentPolicy 配置中的规则片段（用于展示）
type ConfigFragmentPolicy struct {
	RuleName        string   `json:"rule_name"`        // 规则名称
	SourceZone      []string `json:"source_zone"`      // 源区域
	DestinationZone []string `json:"destination_zone"` // 目的区域
	SourceIP        string   `json:"source_ip"`        // 源IP
	DestinationIP   string   `json:"destination_ip"`   // 目的IP
	Port            string   `json:"port"`             // 端口
	Protocol        string   `json:"protocol"`         // 协议
	Action          string   `json:"action"`           // 动作
	CLI             string   `json:"cli"`              // CLI命令
}

// RuleConsistencyResult 一致性对比详细结果项
type RuleConsistencyResult struct {
	Rule                       string                `json:"rule"`                                   // 规则名称
	RuleExists                 bool                  `json:"rule_exists"`                            // 规则是否存在
	SourceZoneConsistent       bool                  `json:"source_zone_consistent"`                 // 源区域一致
	DestinationZoneConsistent  bool                  `json:"destination_zone_consistent"`            // 目的区域一致
	SourceIPConsistent         bool                  `json:"source_ip_consistent"`                   // 源IP一致
	SourceInconsistentIPs      string                `json:"source_inconsistent_ips,omitempty"`      // 源侧不一致IP（Excel中有但配置中没有的IP）
	DestinationIPConsistent    bool                  `json:"destination_ip_consistent"`              // 目的IP一致
	DestinationInconsistentIPs string                `json:"destination_inconsistent_ips,omitempty"` // 目的侧不一致IP（Excel中有但配置中没有的IP）
	PortConsistent             bool                  `json:"port_consistent"`                        // 端口一致
	DifferenceDetails          string                `json:"difference_details,omitempty"`           // 差异详情描述
	ExcelRule                  *ExcelPolicyRule      `json:"excel_rule,omitempty"`                   // Excel中的策略规则
	ConfigRule                 *ConfigFragmentPolicy `json:"config_rule,omitempty"`                  // 配置中的规则
}

// ComparePolicyResult 策略对比结果结构
type ComparePolicyResult struct {
	NodeName     string                 `json:"node_name"`               // 节点名称
	RuleName     string                 `json:"rule_name"`               // 规则名称
	PolicyFound  bool                   `json:"policy_found"`            // 是否找到策略
	Result       *RuleConsistencyResult `json:"result,omitempty"`        // 对比结果
	ErrorMessage string                 `json:"error_message,omitempty"` // 错误信息
}

// Compare 对比策略方法
// 根据 node name、rule name、intent 进行 policy 对比
func (mnm *NodemapService) Compare(nodeName, ruleName string, intent *policy.Intent, nm *nodemap.NodeMap) (*ComparePolicyResult, error) {
	if nm == nil {
		return nil, fmt.Errorf("NodeMap is nil")
	}

	if intent == nil {
		return nil, fmt.Errorf("intent is nil")
	}

	result := &ComparePolicyResult{
		NodeName:    nodeName,
		RuleName:    ruleName,
		PolicyFound: false,
	}

	// 1. 根据 node name 获取节点
	node := nm.GetNode(nodeName)
	if node == nil {
		result.ErrorMessage = fmt.Sprintf("Node not found: %s", nodeName)
		return result, fmt.Errorf("node not found: %s", nodeName)
	}

	// 2. 检查节点是否为防火墙节点
	fwNode, ok := node.(firewall.FirewallNode)
	if !ok {
		result.ErrorMessage = fmt.Sprintf("Node %s is not a firewall node", nodeName)
		return result, fmt.Errorf("node %s is not a firewall node", nodeName)
	}

	// 3. 获取所有策略
	policies := fwNode.Policies()
	if len(policies) == 0 {
		result.ErrorMessage = "No policies found in the node"
		return result, fmt.Errorf("no policies found in node %s", nodeName)
	}

	// 4. 根据 rule name 查找策略
	var targetPolicy firewall.FirewallPolicy
	for _, policy := range policies {
		if policy.Name() == ruleName || policy.Description() == ruleName || policy.ID() == ruleName {
			targetPolicy = policy
			result.PolicyFound = true
			break
		}
	}

	// 5. 根据 intent 的源地址和目标地址匹配安全区域
	sourceZones := matchSecurityZonesByAddress(nm, intent.Src(), "")
	destinationZones := matchSecurityZonesByAddress(nm, intent.Dst(), "")

	// 6. 进行策略对比（传入区域信息）
	consistencyResult := comparePolicyWithIntent(targetPolicy, intent, ruleName, sourceZones, destinationZones)
	result.Result = consistencyResult
	result.PolicyFound = consistencyResult.RuleExists

	if !result.PolicyFound {
		result.ErrorMessage = fmt.Sprintf("Policy rule '%s' not found in node '%s'", ruleName, nodeName)
	}

	Logger.Info("Policy comparison completed",
		zap.String("node_name", nodeName),
		zap.String("rule_name", ruleName),
		zap.Strings("source_zones", sourceZones),
		zap.Strings("destination_zones", destinationZones),
		zap.Any("consistency_result", consistencyResult))

	return result, nil
}

// isDefaultRoute 检查网络是否为默认路由（0.0.0.0/0 或 ::/0）
func isDefaultRoute(net network.AbbrNet, ipFamily network.IPFamily) bool {
	netStr := net.String()
	if ipFamily == network.IPv4 {
		return netStr == "0.0.0.0/0"
	}
	return netStr == "::/0"
}

// matchSecurityZonesByAddress 根据地址匹配安全区域（使用 AddressTable 实现最长匹配）
// 返回匹配到的区域名称（ConfigZoneName），只返回一个，基于最长匹配的路由
// 规则：
// 1. 默认路由不参加对比
// 2. 如果没有完整匹配到某一区域，认为不匹配
// 3. 如果有默认路由，最后匹配默认路由
func matchSecurityZonesByAddress(nm *nodemap.NodeMap, addressGroup *network.NetworkGroup, vrf string) []string {
	if addressGroup == nil {
		return nil
	}

	// 分别尝试 IPv4 和 IPv6
	for _, ipFamily := range []network.IPFamily{network.IPv4, network.IPv6} {
		var netList *network.NetworkList
		if ipFamily == network.IPv4 {
			netList = addressGroup.IPv4()
		} else {
			netList = addressGroup.IPv6()
		}

		if netList == nil || len(netList.List()) == 0 {
			continue
		}

		// 获取对应 IP 协议族的安全区域列表
		var securityZones []*config.SecurityZoneInfo
		if ipFamily == network.IPv4 {
			securityZones = nm.Ipv4SecurityZones
		} else {
			securityZones = nm.Ipv6SecurityZones
		}

		if len(securityZones) == 0 {
			continue
		}

		// 构建 AddressTable，将每个 SecurityZone 的网段作为路由条目
		// 使用 NextHop 的 Interface 字段存储 ConfigZoneName
		// 同时保存默认路由信息（用于最后匹配）
		addressTable := network.NewAddressTable(ipFamily)
		var defaultRouteZone string // 保存默认路由对应的区域名称

		for _, zoneInfo := range securityZones {
			// 如果指定了 VRF，需要匹配 VRF
			if vrf != "" && zoneInfo.Vrf != "" && zoneInfo.Vrf != vrf {
				continue
			}

			// 将 SecurityZone 的每个网段添加到 AddressTable
			for _, segmentStr := range zoneInfo.NetworkSegments {
				// 解析网段字符串
				ng, err := network.NewNetworkGroupFromString(segmentStr)
				if err != nil {
					Logger.Debug("Failed to parse security zone segment",
						zap.String("segment", segmentStr),
						zap.String("configZoneName", zoneInfo.ConfigZoneName),
						zap.Error(err))
					continue
				}

				// 获取对应 IP 协议族的网络列表
				var segmentNetList *network.NetworkList
				if ipFamily == network.IPv4 {
					segmentNetList = ng.IPv4()
				} else {
					segmentNetList = ng.IPv6()
				}

				if segmentNetList == nil || len(segmentNetList.List()) == 0 {
					continue
				}

				// 为每个网络添加路由条目，使用 ConfigZoneName 作为接口名
				for _, net := range segmentNetList.List() {
					// 检查是否为默认路由
					if isDefaultRoute(net, ipFamily) {
						// 默认路由不参加对比，但保存信息用于最后匹配
						if defaultRouteZone == "" {
							defaultRouteZone = zoneInfo.ConfigZoneName
						}
						continue
					}

					nextHop := &network.NextHop{}
					// 使用 Interface 字段存储 ConfigZoneName
					// 当 IP 为空时，需要设置 connected=true（表示直连路由）
					// 这样 NewHop 才能正常工作
					nextHop.AddHop(zoneInfo.ConfigZoneName, "", true, false, nil)
					if err := addressTable.PushRoute(net, nextHop); err != nil {
						Logger.Debug("Failed to push route to address table",
							zap.String("segment", segmentStr),
							zap.String("configZoneName", zoneInfo.ConfigZoneName),
							zap.Error(err))
						continue
					}
				}
			}
		}

		// 使用 AddressTable 进行最长匹配（不包含默认路由）
		// MatchNetList 的第二个参数为 true 表示使用最长匹配
		rmr := addressTable.MatchNetList(*netList, true, false)

		// 检查是否有未匹配的网络（Unmatch 不为空表示没有完整匹配）
		if rmr.Unmatch != nil && rmr.Unmatch.Len() > 0 {
			// 如果没有完整匹配，尝试匹配默认路由
			if defaultRouteZone != "" {
				Logger.Debug("No full match found, using default route zone",
					zap.String("defaultRouteZone", defaultRouteZone))
				return []string{defaultRouteZone}
			}
			// 如果没有默认路由，返回空（不匹配）
			return []string{}
		}

		zoneSet := map[string]bool{}

		// 从匹配结果中提取区域名称（最长匹配已经保证了前缀最长的路由）
		if rmr.Match != nil && rmr.Match.Len() > 0 {
			matchTable, err := rmr.Table()
			if err == nil && matchTable != nil {
				// 从匹配表中提取 interface 列（存储的是 ConfigZoneName）
				interfaces := matchTable.Column("interface").List().Distinct()
				for _, iface := range interfaces {
					zoneName := iface.(string)
					if zoneName != "" {
						zoneSet[zoneName] = true
					}
				}
			}
		}

		// // 如果匹配到多个不同的 zone，返回默认路由
		// if len(zoneSet) > 1 {
		// 	if defaultRouteZone != "" {
		// 		Logger.Debug("Multiple zones matched, using default route zone",
		// 			zap.Int("zoneCount", len(zoneSet)),
		// 			zap.String("defaultRouteZone", defaultRouteZone))
		// 		return []string{defaultRouteZone}
		// 	}
		// }

		zones := []string{}
		// 如果只有一个 zone，返回该 zone
		for zoneName := range zoneSet {
			zones = append(zones, zoneName)
		}
		return zones
	}

	return []string{}
}

// comparePolicyWithIntent 对比策略与意图，返回一致性结果
func comparePolicyWithIntent(policy firewall.FirewallPolicy, intent *policy.Intent, ruleName string, sourceZones, destinationZones []string) *RuleConsistencyResult {
	result := &RuleConsistencyResult{
		Rule: ruleName,
	}

	// 如果 policy 为 nil，说明规则不存在
	if policy == nil {
		result.RuleExists = false
		result.DifferenceDetails = "Policy rule not found in configuration"
		// 构建 ExcelRule（从 intent，包含区域信息）
		result.ExcelRule = buildExcelRuleFromIntent(intent, ruleName, sourceZones, destinationZones)
		return result
	}

	result.RuleExists = true

	// 构建 ExcelRule（从 intent，包含区域信息）
	// 确保在所有情况下都设置 ExcelRule，包含 sourceZones 和 destinationZones
	excelRule := buildExcelRuleFromIntent(intent, ruleName, sourceZones, destinationZones)
	result.ExcelRule = excelRule

	// 获取策略的 PolicyEntry
	policyEntry := policy.PolicyEntry()
	if policyEntry == nil {
		result.DifferenceDetails = "Policy entry is nil"
		// 即使 policyEntry 为 nil，也返回 ExcelRule（包含区域信息）
		return result
	}

	// 构建 ConfigRule（从 policy）
	configRule := buildConfigRuleFromPolicy(policy, policyEntry)
	result.ConfigRule = configRule

	// 对比源区域
	result.SourceZoneConsistent = compareZones(policy.FromZones(), excelRule.SourceZone)

	// 对比目的区域
	result.DestinationZoneConsistent = compareZones(policy.ToZones(), excelRule.DestinationZone)

	// 对比源IP
	srcConsistent, srcInconsistentIPs := compareNetworkGroups(policyEntry.Src(), intent.Src())
	result.SourceIPConsistent = srcConsistent
	if srcInconsistentIPs != "" {
		result.SourceInconsistentIPs = srcInconsistentIPs
	}

	// 对比目的IP
	dstConsistent, dstInconsistentIPs := compareNetworkGroups(policyEntry.Dst(), intent.Dst())
	result.DestinationIPConsistent = dstConsistent
	if dstInconsistentIPs != "" {
		result.DestinationInconsistentIPs = dstInconsistentIPs
	}

	// 对比端口（从服务中提取）
	result.PortConsistent = compareServices(policyEntry.Service(), intent.Service())

	// 生成差异详情
	result.DifferenceDetails = generateDifferenceDetails(result)

	return result
}

// buildExcelRuleFromIntent 从 intent 构建 ExcelPolicyRule
func buildExcelRuleFromIntent(intent *policy.Intent, ruleName string, sourceZones, destinationZones []string) *ExcelPolicyRule {
	excelRule := &ExcelPolicyRule{
		RuleName:        ruleName,
		SourceZone:      sourceZones,
		DestinationZone: destinationZones,
	}

	if intent.Src() != nil {
		excelRule.SourceIP = intent.Src().String()
	}

	if intent.Dst() != nil {
		excelRule.DestinationIP = intent.Dst().String()
	}

	if intent.Service() != nil {
		excelRule.Port = intent.Service().String()
		// 尝试提取协议和端口
		serviceStr := intent.Service().String()
		if len(serviceStr) > 0 {
			// 简单的协议提取（实际可能需要更复杂的解析）
			if len(serviceStr) > 3 {
				excelRule.Protocol = serviceStr[:3] // 假设前3个字符是协议
			}
		}
	}

	return excelRule
}

// buildConfigRuleFromPolicy 从 policy 构建 ConfigFragmentPolicy
func buildConfigRuleFromPolicy(policy firewall.FirewallPolicy, policyEntry policy.PolicyEntryInf) *ConfigFragmentPolicy {
	configRule := &ConfigFragmentPolicy{
		RuleName:        policy.Name(),
		SourceZone:      policy.FromZones(),
		DestinationZone: policy.ToZones(),
		Action:          policy.Action().String(),
		CLI:             policy.Cli(),
	}

	if policyEntry != nil {
		if policyEntry.Src() != nil {
			configRule.SourceIP = policyEntry.Src().String()
		}
		if policyEntry.Dst() != nil {
			configRule.DestinationIP = policyEntry.Dst().String()
		}
		if policyEntry.Service() != nil {
			configRule.Port = policyEntry.Service().String()
			serviceStr := policyEntry.Service().String()
			if len(serviceStr) > 0 {
				if len(serviceStr) > 3 {
					configRule.Protocol = serviceStr[:3]
				}
			}
		}
	}

	return configRule
}

// compareZones 对比区域列表
func compareZones(policyZones []string, excelZones []string) bool {
	// 对两个列表进行去重
	policyZoneMap := make(map[string]bool)
	for _, zone := range policyZones {
		if zone != "" {
			policyZoneMap[zone] = true
		}
	}

	excelZoneMap := make(map[string]bool)
	for _, zone := range excelZones {
		if zone != "" {
			excelZoneMap[zone] = true
		}
	}

	// 如果去重后都为空，返回 true
	if len(policyZoneMap) == 0 && len(excelZoneMap) == 0 {
		return true
	}

	// 如果去重后长度不同，返回 false
	if len(policyZoneMap) != len(excelZoneMap) {
		return false
	}

	// 检查是否包含相同的区域（不考虑顺序）
	for zone := range excelZoneMap {
		if !policyZoneMap[zone] {
			return false
		}
	}
	return true
}

// compareNetworkGroups 对比网络组，返回是否一致和不一致的IP
func compareNetworkGroups(policyNG, intentNG *network.NetworkGroup) (bool, string) {
	if policyNG == nil && intentNG == nil {
		return true, ""
	}
	if policyNG == nil || intentNG == nil {
		if intentNG != nil {
			return false, intentNG.String()
		}
		return false, ""
	}

	// 使用 Same 方法检查是否完全相同
	if policyNG.Same(intentNG) {
		return true, ""
	}

	left, _, right := network.NetworkGroupCmp(*policyNG, *intentNG)

	results := []string{}

	if left != nil && !left.IsEmpty() {
		results = append(results, "-"+left.String())
	}

	if right != nil && !right.IsEmpty() {
		results = append(results, "+"+right.String())
	}

	return false, strings.Join(results, ", ")
}

// compareServices 对比服务
func compareServices(policySvc, intentSvc *service.Service) bool {
	if policySvc == nil && intentSvc == nil {
		return true
	}
	if policySvc == nil || intentSvc == nil {
		return false
	}
	return policySvc.Same(intentSvc)
}

// generateDifferenceDetails 生成差异详情描述
func generateDifferenceDetails(result *RuleConsistencyResult) string {
	var differences []string

	if !result.RuleExists {
		return "Rule not found in configuration"
	}

	if !result.SourceZoneConsistent {
		differences = append(differences, "Source zone mismatch")
	}

	if !result.DestinationZoneConsistent {
		differences = append(differences, "Destination zone mismatch")
	}

	if !result.SourceIPConsistent {
		differences = append(differences, fmt.Sprintf("Source IP mismatch: %s", result.SourceInconsistentIPs))
	}

	if !result.DestinationIPConsistent {
		differences = append(differences, fmt.Sprintf("Destination IP mismatch: %s", result.DestinationInconsistentIPs))
	}

	if !result.PortConsistent {
		differences = append(differences, "Port/Service mismatch")
	}

	if len(differences) == 0 {
		return "All fields are consistent"
	}

	return strings.Join(differences, "; ")
}

// func makeIntents(info *structs.NodemapInfo) map[string]policy.Intent {
// 	intents := map[string]policy.Intent{}
// 	for _, conf := range info.DeviceConfigs {
// 		dc := constant.FindDeviceCategoryBySpecificCategory(conf.Mode)
// 		hasPolicyEntryService := constant.ContainsDeviceCategory(dc) && dc == constant.LB
// 		for _, v := range info.IntentInfos {
// 			intent := policy.NewIntent(&v.Info)
// 			if hasPolicyEntryService {
// 				intent.PolicyEntryService.MustOneServiceEntry()
// 			}
// 			intents[v.Key] = *intent
// 		}
// 	}
// 	return intents
// }

func makeIntents(info *structs.NodemapInfo) map[string]policy.Intent {
	intents := map[string]policy.Intent{}
	// for _, conf := range info.DeviceConfigs {
	// 	dc := constant.FindDeviceCategoryBySpecificCategory(conf.Mode)
	// 	hasPolicyEntryService := constant.ContainsDeviceCategory(dc) && dc == constant.LB
	for _, v := range info.IntentInfos {
		intent := policy.NewIntent(&v.Info)
		// if hasPolicyEntryService {
		// 	intent.PolicyEntryService.MustOneServiceEntry()
		// }
		intents[v.Key] = *intent
	}
	// }
	return intents
}

func makeDeviceConfig(mnm meta.MetaNodeMap, info *structs.NodemapInfo) []config.DeviceConfig {
	var deviceConfigs []config.DeviceConfig
	for _, v := range info.DeviceInfos {
		dconf := config.DeviceConfig{}
		dconf.Config = v.ConfigText
		dconf.Mode = v.DeviceBase.Mode
		dconf.MetaData = v.MetaData
		// if exist, metaNode := mnm.GetMetaNode(v.DeviceRemoteInfo.DeviceName); exist {

		dconf.Host = v.DeviceBase.Host
		dconf.Port = v.DeviceBase.Port
		dconf.Mode = v.DeviceBase.Mode
		dconf.Community = v.DeviceBase.Community
		dconf.Username = v.DeviceBase.Username
		dconf.Password = v.DeviceBase.Password
		dconf.Telnet = v.DeviceBase.Telnet
		dconf.AuthPass = v.DeviceBase.AuthPass

		for _, ipv4Area := range v.Ipv4Area {
			area := config.AreaInfo{}
			area.NodeName = v.DeviceRemoteInfo.DeviceName
			area.Name = ipv4Area.Name
			area.Interface = ipv4Area.Interface
			area.Force = true
			dconf.Ipv4Area = append(dconf.Ipv4Area, &area)
		}

		for _, ipv6Area := range v.Ipv6Area {
			area := config.AreaInfo{}
			area.NodeName = v.DeviceRemoteInfo.DeviceName
			area.Name = ipv6Area.Name
			area.Interface = ipv6Area.Interface
			area.Force = true
			dconf.Ipv6Area = append(dconf.Ipv6Area, &area)
		}

		for _, ipv4Stub := range v.Ipv4Stub {
			stub := config.StubConfigInfo{}
			// stub.NodeName = metaNode.Name
			stub.PortName = ipv4Stub.PortName
			dconf.Ipv4Stub = append(dconf.Ipv4Stub, &stub)
		}

		for _, ipv6Stub := range v.Ipv6Stub {
			stub := config.StubConfigInfo{}
			// stub.NodeName = metaNode.Name
			stub.PortName = ipv6Stub.PortName
			dconf.Ipv6Stub = append(dconf.Ipv6Stub, &stub)
		}

		// 处理 SecurityZones：将 SecurityZone 的网段信息转换为 SecurityZoneInfo，用于节点定位
		// 遍历每个 SecurityZone，将其 NetworkSegments 转换为 SecurityZoneInfo
		for _, zoneInfo := range v.SecurityZones {
			// 收集该 Zone 的所有网段
			var ipv4Segments []string
			var ipv6Segments []string

			for _, segment := range zoneInfo.NetworkSegments {
				if segment.NetworkSegment == "" {
					continue
				}
				// 判断是 IPv4 还是 IPv6（简单判断：包含 ":" 的是 IPv6）
				if strings.Contains(segment.NetworkSegment, ":") {
					ipv6Segments = append(ipv6Segments, segment.NetworkSegment)
				} else {
					ipv4Segments = append(ipv4Segments, segment.NetworkSegment)
				}
			}

			// 创建 IPv4 SecurityZoneInfo
			if len(ipv4Segments) > 0 {
				securityZoneInfo := &config.SecurityZoneInfo{
					ConfigZoneName:  zoneInfo.ConfigZoneName,       // 配置中的 Zone 名称
					NetworkSegments: ipv4Segments,                  // Zone 的所有 IPv4 网段
					NodeName:        v.DeviceRemoteInfo.DeviceName, // 关联的设备节点名称
					// Vrf 留空，使用默认 VRF
					Priority: 0, // 默认优先级
				}
				dconf.Ipv4SecurityZones = append(dconf.Ipv4SecurityZones, securityZoneInfo)
			}

			// 创建 IPv6 SecurityZoneInfo
			if len(ipv6Segments) > 0 {
				securityZoneInfo := &config.SecurityZoneInfo{
					ConfigZoneName:  zoneInfo.ConfigZoneName,       // 配置中的 Zone 名称
					NetworkSegments: ipv6Segments,                  // Zone 的所有 IPv6 网段
					NodeName:        v.DeviceRemoteInfo.DeviceName, // 关联的设备节点名称
					// Vrf 留空，使用默认 VRF
					Priority: 0, // 默认优先级
				}
				dconf.Ipv6SecurityZones = append(dconf.Ipv6SecurityZones, securityZoneInfo)
			}
		}

		// for _, vs := range v.VsRanges {
		// 	vsRange := config.VsInfo{}
		// 	vsRange.Type = vs.Type
		// 	vsRange.Network = vs.Network
		// 	vsRange.Vrf = vs.Vrf
		// 	dconf.VsRange = append(dconf.VsRange, &vsRange)
		// }

		// }
		deviceConfigs = append(deviceConfigs, dconf)
	}
	return deviceConfigs
}

func perfectTemplateResult(traverseProcess nodemap.TraverseProcess, templateResult model.TemplateResult, itemId string) model.TemplateResult {
	results := traverseProcess.Results.Items

	for _, result := range results {
		item := new(model.TemplateResultItem)
		if result.Node == nil || itemId == "" {
			continue
		}
		item.WorkItemId = itemId
		item.Node = model.NodeInfo{
			Name:     result.Node.Name(),
			NodeType: result.Node.NodeType().String(),
			CmdIp:    result.Node.CmdIp(),
		}

		if result.Node.NodeType() == api.FIREWALL {
			if result.StepProcess == nil || !result.StepProcess.Iterator().HasNext() {
				continue
			}
			iterators := result.StepProcess.Iterator()
			var steps []model.StepInfo
			for {
				if !iterators.HasNext() {
					break
				}
				stepName, step := iterators.Next()
				stepInfo := model.StepInfo{
					Phase: stepName,
					Cli:   step.GetCli(),
					Rule:  step.GetRule(),
				}

				// Convert phase action to string
				switch step.GetPhaseAction() {
				case processor.PHASE_MATCHED:
					stepInfo.PhaseAction = "MATCHED"
				case processor.PHASE_GENERATED:
					stepInfo.PhaseAction = "GENERATED"
				default:
					stepInfo.PhaseAction = "UNKNOWN"
				}

				// Convert phase to string
				stepInfo.FirewallPhase = fmt.Sprintf("%d", step.GetPhase())

				steps = append(steps, stepInfo)
			}

			item.Steps = steps
		}

		if result.Node.NodeType() == api.LB {
			lbProcessResult := model.LBProcessResult{}
			lbProcessResult.NodePort = result.LBResult.NodePort
			lbProcessResult.ErrMsg = result.LBResult.ErrMsg
			lbProcessResult.Pool = result.LBResult.Pool
			lbProcessResult.Dst = result.LBResult.Dst
			lbProcessResult.RouteDomain = result.LBResult.RouteDomain
			lbProcessResult.Nodes = result.LBResult.Nodes
			lbProcessResult.AutoMap = result.LBResult.AutoMap
			lbProcessResult.Dport = result.LBResult.Dport
			lbProcessResult.Partition = result.LBResult.Partition
			lbProcessResult.Virtual = result.LBResult.Virtual
			lbProcessResult.State = result.LBResult.State
			item.LBResult = lbProcessResult
		}
		templateResult.Result = append(templateResult.Result, item)
	}
	return templateResult
}

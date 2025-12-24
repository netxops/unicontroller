package sangfor

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	policyutil "github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
)

type Nats struct {
	objects             *SangforObjectSet
	node                *SangforNode
	destinationNatRules []*NatRule
	sourceNatRules      []*NatRule
	natPolicyRules      []*NatRule
	natServers          []*NatRule
}

type NatRule struct {
	node      *SangforNode
	objects   *SangforObjectSet
	name      string
	uuid      string
	enable    bool
	position  int32
	natType   firewall.NatType
	original  policyutil.PolicyEntryInf
	translate policyutil.PolicyEntryInf
	from      string
	to        string
}

// SangforNatPoolNetworkObject 表示 NAT 池的网络对象
type SangforNatPoolNetworkObject struct {
	name    string
	network *network.NetworkGroup
}

func (p *SangforNatPoolNetworkObject) Name() string {
	return p.name
}

func (p *SangforNatPoolNetworkObject) Network(_ firewall.FirewallNode) *network.NetworkGroup {
	return p.network
}

func (p *SangforNatPoolNetworkObject) Type() firewall.FirewallObjectType {
	return firewall.OBJECT_POOL
}

func (p *SangforNatPoolNetworkObject) Cli() string {
	// NAT 池的 CLI 由对应的 SNAT 规则生成
	return ""
}

func (p *SangforNatPoolNetworkObject) TypeName() string {
	return "SangforNatPoolNetworkObject"
}

// sangforNatPoolNetworkObjectJSON 用于序列化和反序列化
type sangforNatPoolNetworkObjectJSON struct {
	Name    string          `json:"name"`
	Network json.RawMessage `json:"network"`
}

func (p *SangforNatPoolNetworkObject) MarshalJSON() ([]byte, error) {
	networkRaw, err := json.Marshal(p.network)
	if err != nil {
		return nil, fmt.Errorf("error marshaling network: %w", err)
	}

	return json.Marshal(sangforNatPoolNetworkObjectJSON{
		Name:    p.name,
		Network: networkRaw,
	})
}

func (p *SangforNatPoolNetworkObject) UnmarshalJSON(data []byte) error {
	var jsonData sangforNatPoolNetworkObjectJSON
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return fmt.Errorf("error unmarshaling JSON: %w", err)
	}

	p.name = jsonData.Name

	var ng network.NetworkGroup
	if err := json.Unmarshal(jsonData.Network, &ng); err != nil {
		return fmt.Errorf("error unmarshaling network: %w", err)
	}
	p.network = &ng

	return nil
}

func (nr *NatRule) Name() string {
	return nr.name
}

func (nr *NatRule) Cli() string {
	var builder strings.Builder
	builder.WriteString("config\n")

	if nr.natType == firewall.DYNAMIC_NAT {
		// SNAT 规则
		builder.WriteString(fmt.Sprintf(`snat-rule "%s" bottom`, nr.name))
		builder.WriteString("\n")
	} else {
		// DNAT/BNAT 规则
		builder.WriteString(fmt.Sprintf(`dnat-rule "%s" bottom`, nr.name))
		builder.WriteString("\n")
	}

	if nr.enable {
		builder.WriteString("enable\n")
	}

	// 源区域
	if nr.from != "" {
		builder.WriteString(fmt.Sprintf(`src-zone "%s"`, nr.from))
		builder.WriteString("\n")
	}

	builder.WriteString(`schedule "all-week"`)
	builder.WriteString("\n")

	// 源 IP 组
	if nr.original != nil {
		srcNg := nr.original.Src()
		if srcNg != nil && !srcNg.IsEmpty() {
			if nr.node != nil {
				obj, found := nr.node.GetObjectByNetworkGroup(srcNg, firewall.SEARCH_OBJECT_OR_GROUP, nil)
				if found {
					builder.WriteString(fmt.Sprintf(`src-ipgroup "%s"`, obj.Name()))
					builder.WriteString("\n")
				}
			}
		}

		// 目标 IP 组（SNAT 使用）
		if nr.natType == firewall.DYNAMIC_NAT {
			dstNg := nr.original.Dst()
			if dstNg != nil && !dstNg.IsEmpty() {
				if nr.node != nil {
					obj, found := nr.node.GetObjectByNetworkGroup(dstNg, firewall.SEARCH_OBJECT_OR_GROUP, nil)
					if found {
						builder.WriteString(fmt.Sprintf(`dst-ipgroup "%s"`, obj.Name()))
						builder.WriteString("\n")
					}
				}
			}

			// 目标区域（SNAT）
			if nr.to != "" {
				builder.WriteString(fmt.Sprintf("dst-zone %s\n", nr.to))
			}
		} else {
			// DNAT 目标 IP
			dstNg := nr.original.Dst()
			if dstNg != nil && !dstNg.IsEmpty() {
				// 尝试获取第一个 IP
				var dstIP string
				dstNg.EachDataRangeEntryAsAbbrNet(func(item network.AbbrNet) bool {
					if ipNet, ok := item.(*network.IPNet); ok {
						dstIP = ipNet.IP.String()
						return false // 只取第一个
					}
					return true
				})
				if dstIP != "" {
					builder.WriteString(fmt.Sprintf("dst-ip %s\n", dstIP))
				}
			}
		}

		// 服务
		svc := nr.original.Service()
		if svc != nil && !svc.IsEmpty() {
			if nr.node != nil {
				obj, found := nr.node.GetObjectByService(svc, firewall.SEARCH_OBJECT_OR_GROUP)
				if found {
					builder.WriteString(fmt.Sprintf("service %s\n", obj.Name()))
				} else {
					builder.WriteString("service any\n")
				}
			} else {
				builder.WriteString("service any\n")
			}
		} else {
			builder.WriteString("service any\n")
		}
	}

	// 转换配置
	if nr.translate != nil {
		if nr.natType == firewall.DYNAMIC_NAT {
			// SNAT 转换
			transferNg := nr.translate.Src()
			if transferNg != nil && !transferNg.IsEmpty() {
				// 尝试查找匹配的网络对象（IPGROUP）
				if nr.node != nil {
					obj, found := nr.node.GetObjectByNetworkGroup(transferNg, firewall.SEARCH_OBJECT_OR_GROUP, nil)
					if found {
						builder.WriteString(fmt.Sprintf("transfer ipgroup %s\n", obj.Name()))
					} else {
						// 尝试生成 IP 范围
						var startIP, endIP string
						transferNg.EachDataRangeEntryAsAbbrNet(func(item network.AbbrNet) bool {
							if ipRange, ok := item.(*network.IPRange); ok {
								startIP = ipRange.Start.String()
								endIP = ipRange.End.String()
								return false
							} else if ipNet, ok := item.(*network.IPNet); ok {
								startIP = ipNet.IP.String()
								endIP = ipNet.IP.String()
								return false
							}
							return true
						})
						if startIP != "" && endIP != "" {
							if startIP == endIP {
								builder.WriteString(fmt.Sprintf("transfer ip %s\n", startIP))
							} else {
								builder.WriteString(fmt.Sprintf("transfer iprange %s-%s dynamic\n", startIP, endIP))
							}
						}
					}
				}
			}
		} else {
			// DNAT 转换
			transferNg := nr.translate.Dst()
			if transferNg != nil && !transferNg.IsEmpty() {
				// 尝试生成 IP 范围或单个 IP
				var startIP, endIP string
				transferNg.EachDataRangeEntryAsAbbrNet(func(item network.AbbrNet) bool {
					if ipRange, ok := item.(*network.IPRange); ok {
						startIP = ipRange.Start.String()
						endIP = ipRange.End.String()
						return false
					} else if ipNet, ok := item.(*network.IPNet); ok {
						startIP = ipNet.IP.String()
						endIP = ipNet.IP.String()
						return false
					}
					return true
				})
				if startIP != "" && endIP != "" {
					if startIP == endIP {
						// 检查是否有端口转换
						svc := nr.original.Service()
						if svc != nil {
							svc.EachDetailed(func(entry service.ServiceEntry) bool {
								if l4, ok := entry.(*service.L4Service); ok {
									dstPort := l4.DstPort()
									if dstPort != nil && len(dstPort.L) > 0 {
										port := dstPort.L[0].Low()
										builder.WriteString(fmt.Sprintf("transfer ip %s port %d\n", startIP, port))
										return false
									}
								}
								return true
							})
						}
						if !strings.Contains(builder.String(), "transfer ip") {
							builder.WriteString(fmt.Sprintf("transfer ip %s\n", startIP))
						}
					} else {
						builder.WriteString(fmt.Sprintf("transfer iprange %s-%s\n", startIP, endIP))
					}
				}
			}
		}
	}

	if nr.natType == firewall.STATIC_NAT {
		builder.WriteString("ignore-acl enable\n")
		builder.WriteString("log bypass-acl disable\n")
		builder.WriteString("transfer load-balance disable\n")
	}

	builder.WriteString("end\n")
	return builder.String()
}

func (nr *NatRule) Original() policyutil.PolicyEntryInf {
	return nr.original
}

func (nr *NatRule) Translate() policyutil.PolicyEntryInf {
	return nr.translate
}

func (nr *NatRule) Extended() map[string]interface{} {
	return make(map[string]interface{})
}

func (n *Nats) inputNat(intent *policyutil.Intent, inPort api.Port) (bool, *policyutil.Intent, firewall.FirewallNatRule) {
	// 按 position 排序 DNAT 规则（position 越小越优先）
	rules := make([]*NatRule, len(n.destinationNatRules))
	copy(rules, n.destinationNatRules)
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].position < rules[j].position
	})

	// 遍历所有 DNAT 规则进行匹配
	for _, rule := range rules {
		if rule.name == "NAT_POLICY" {
			fmt.Println("NAT_POLICY rule: ", rule.name)
			fmt.Println("Intent: ", intent.String())
			fmt.Println("original: ", rule.original.String())
			fmt.Println("translate: ", rule.translate.String())
			fmt.Println("--------------------------------")
		}
		if rule.original != nil && rule.original.Match(intent) {
			// 使用 Translate 方法进行转换
			if rule.translate != nil {
				// 检查 translate 是否有效（至少有一个非空字段）
				hasTranslate := false
				dstNg := rule.translate.Dst()
				if dstNg != nil && !dstNg.IsEmpty() {
					hasTranslate = true
				}
				if !hasTranslate {
					srcNg := rule.translate.Src()
					if srcNg != nil && !srcNg.IsEmpty() {
						hasTranslate = true
					}
				}
				if !hasTranslate {
					svc := rule.translate.Service()
					if svc != nil && !svc.IsEmpty() {
						hasTranslate = true
					}
				}
				if hasTranslate {
					ok, translateTo, msg := intent.Translate(rule.translate)
					if ok && translateTo != nil {
						translateIntent := intent.NewIntentWithTicket(translateTo)
						return true, translateIntent, rule
					}
					_ = msg // 忽略错误消息
				}
			}
		}
	}
	return false, nil, nil
}

func (n *Nats) outputNat(intent *policyutil.Intent, inPort, outPort api.Port) (bool, *policyutil.Intent, firewall.FirewallNatRule) {
	// 按 position 排序 SNAT 规则（position 越小越优先）
	rules := make([]*NatRule, len(n.sourceNatRules))
	copy(rules, n.sourceNatRules)
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].position < rules[j].position
	})

	// 遍历所有 SNAT 规则进行匹配
	for _, rule := range rules {
		if rule.original != nil && rule.original.Match(intent) {
			// 使用 Translate 方法进行转换
			if rule.translate != nil {
				ok, translateTo, msg := intent.Translate(rule.translate)
				if ok {
					translateIntent := intent.NewIntentWithTicket(translateTo)
					return true, translateIntent, rule
				}
				_ = msg // 忽略错误消息
			}
		}
	}
	return false, nil, nil
}

func (n *Nats) inputNatTargetCheck(intent *policyutil.Intent, inPort, outPort api.Port) (bool, firewall.FirewallNatRule) {
	// 检查目标地址是否匹配 DNAT 规则
	reverse := intent.Reverse()
	for _, rule := range n.destinationNatRules {
		if rule.original != nil && rule.original.Match(reverse) {
			return true, rule
		}
	}
	return false, nil
}

func (n *Nats) GetPoolByNetworkGroup(ng *network.NetworkGroup, natType firewall.NatType) (firewall.FirewallNetworkObject, bool) {
	// 遍历 SNAT 规则（动态 NAT），查找匹配的池
	for _, rule := range n.sourceNatRules {
		if rule.translate != nil && rule.translate.Src() != nil {
			poolNg := rule.translate.Src()
			// 检查池的网络组是否与指定的网络组匹配
			if poolNg.MatchNetworkGroup(ng) || ng.MatchNetworkGroup(poolNg) {
				// 创建一个网络对象包装器来表示池
				poolObj := &SangforNatPoolNetworkObject{
					name:    rule.name,
					network: poolNg,
				}
				return poolObj, true
			}
		}
	}
	return nil, false
}

func (n *Nats) HasPoolName(name string) bool {
	// 检查所有 SNAT 规则的名称
	for _, rule := range n.sourceNatRules {
		if rule.name == name {
			return true
		}
	}
	return false
}

func (n *Nats) HasNatName(name string) bool {
	// 检查所有 NAT 规则
	allRules := [][]*NatRule{
		n.destinationNatRules,
		n.sourceNatRules,
		n.natPolicyRules,
		n.natServers,
	}
	for _, rules := range allRules {
		for _, rule := range rules {
			if rule.Name() == name {
				return true
			}
		}
	}
	return false
}

// NewSangforNats 创建 Sangfor NAT 集合
func NewSangforNats(node *SangforNode) *Nats {
	return &Nats{
		objects:             node.objectSet,
		node:                node,
		destinationNatRules: []*NatRule{},
		sourceNatRules:      []*NatRule{},
		natPolicyRules:      []*NatRule{},
		natServers:          []*NatRule{},
	}
}

// parseRespResultForNat 解析 NAT 规则响应
func (n *Nats) parseRespResultForNat(resp map[string]interface{}) {
	// 检查响应码
	if code, ok := resp["code"].(float64); !ok || code != 0 {
		return
	}

	// 解析 data.items 数组
	if data, ok := resp["data"].(map[string]interface{}); ok {
		if items, ok := data["items"].([]interface{}); ok {
			for _, item := range items {
				if itemMap, ok := item.(map[string]interface{}); ok {
					rule := n.parseNatItem(itemMap)
					if rule != nil {
						// 根据 NAT 类型添加到相应的规则列表
						switch rule.natType {
						case firewall.STATIC_NAT:
							n.destinationNatRules = append(n.destinationNatRules, rule)
						case firewall.DYNAMIC_NAT:
							n.sourceNatRules = append(n.sourceNatRules, rule)
						}
					}
				}
			}
		}
	}
}

// parseNatItem 解析单个 NAT 规则项
func (n *Nats) parseNatItem(itemMap map[string]interface{}) *NatRule {
	fmt.Printf("[parseNatItem] 开始解析，itemMap 键: %v\n", func() []string {
		keys := make([]string, 0, len(itemMap))
		for k := range itemMap {
			keys = append(keys, k)
		}
		return keys
	}())
	name, _ := itemMap["name"].(string)
	fmt.Printf("[parseNatItem] 规则名称: %s\n", name)
	if name == "" {
		fmt.Printf("[parseNatItem] 规则名称为空，返回 nil\n")
		return nil
	}

	rule := &NatRule{
		node:    n.node,
		objects: n.objects,
		name:    name,
	}

	// 解析基础字段
	if uuid, ok := itemMap["uuid"].(string); ok {
		rule.uuid = uuid
	}
	if enable, ok := itemMap["enable"].(bool); ok {
		rule.enable = enable
	}
	if position, ok := itemMap["position"].(float64); ok {
		rule.position = int32(position)
	}

	// 解析 natType
	if natType, ok := itemMap["natType"].(string); ok {
		switch natType {
		case "SNAT":
			rule.natType = firewall.DYNAMIC_NAT
		case "DNAT":
			rule.natType = firewall.STATIC_NAT
		case "BNAT":
			rule.natType = firewall.STATIC_NAT // BNAT 可以视为静态 NAT
		default:
			return nil
		}
	} else {
		return nil
	}

	// 创建原始策略条目
	original := policyutil.NewPolicyEntry()
	translate := policyutil.NewPolicyEntry()
	// 确保 translate 的字段都被初始化（避免 nil pointer）
	// 注意：PolicyEntry 的字段在 Add* 方法调用前可能为 nil
	translate.AddSrc(network.NewNetworkGroup())
	translate.AddDst(network.NewNetworkGroup())
	// Service 字段会在后续解析时添加，这里不需要初始化

	// 根据 natType 解析不同的配置
	if rule.natType == firewall.DYNAMIC_NAT {
		// SNAT 解析
		if snat, ok := itemMap["snat"].(map[string]interface{}); ok {
			// 解析 srcZones（支持 []interface{} 和 []string 两种类型）
			if srcZonesRaw, ok := snat["srcZones"]; ok {
				var srcZones []interface{}
				if srcZonesInterface, ok := srcZonesRaw.([]interface{}); ok {
					srcZones = srcZonesInterface
				} else if srcZonesString, ok := srcZonesRaw.([]string); ok {
					// 将 []string 转换为 []interface{}
					srcZones = make([]interface{}, len(srcZonesString))
					for i, v := range srcZonesString {
						srcZones[i] = v
					}
				}
				if len(srcZones) > 0 {
					if zoneStr, ok := srcZones[0].(string); ok {
						rule.from = zoneStr
					}
				}
			}

			// 解析 srcIpGroups（支持 []interface{} 和 []string 两种类型）
			if srcIpGroupsRaw, ok := snat["srcIpGroups"]; ok {
				var srcIpGroups []interface{}
				if srcIpGroupsInterface, ok := srcIpGroupsRaw.([]interface{}); ok {
					srcIpGroups = srcIpGroupsInterface
				} else if srcIpGroupsString, ok := srcIpGroupsRaw.([]string); ok {
					// 将 []string 转换为 []interface{}
					srcIpGroups = make([]interface{}, len(srcIpGroupsString))
					for i, v := range srcIpGroupsString {
						srcIpGroups[i] = v
					}
				}
				for _, ipGroup := range srcIpGroups {
					if ipGroupName, ok := ipGroup.(string); ok {
						if n.objects != nil && n.objects.networkMap != nil {
							if objNetwork, ok := n.objects.networkMap[ipGroupName]; ok {
								ng := objNetwork.Network(n.node)
								if ng != nil {
									original.AddSrc(ng)
								}
							}
						}
					}
				}
			}

			// 解析 dstIpGroups（支持 []interface{} 和 []string 两种类型）
			if dstIpGroupsRaw, ok := snat["dstIpGroups"]; ok {
				var dstIpGroups []interface{}
				if dstIpGroupsInterface, ok := dstIpGroupsRaw.([]interface{}); ok {
					dstIpGroups = dstIpGroupsInterface
				} else if dstIpGroupsString, ok := dstIpGroupsRaw.([]string); ok {
					// 将 []string 转换为 []interface{}
					dstIpGroups = make([]interface{}, len(dstIpGroupsString))
					for i, v := range dstIpGroupsString {
						dstIpGroups[i] = v
					}
				}
				for _, ipGroup := range dstIpGroups {
					if ipGroupName, ok := ipGroup.(string); ok {
						if n.objects != nil && n.objects.networkMap != nil {
							if objNetwork, ok := n.objects.networkMap[ipGroupName]; ok {
								ng := objNetwork.Network(n.node)
								if ng != nil {
									original.AddDst(ng)
								}
							}
						}
					}
				}
			}

			// 解析 natService（支持 []interface{} 和 []string 两种类型）
			if natServiceRaw, ok := snat["natService"]; ok {
				var natService []interface{}
				if natServiceInterface, ok := natServiceRaw.([]interface{}); ok {
					natService = natServiceInterface
				} else if natServiceString, ok := natServiceRaw.([]string); ok {
					// 将 []string 转换为 []interface{}
					natService = make([]interface{}, len(natServiceString))
					for i, v := range natServiceString {
						natService[i] = v
					}
				}
				for _, serv := range natService {
					if servName, ok := serv.(string); ok {
						if n.objects != nil && n.objects.serviceMap != nil {
							if objService, ok := n.objects.serviceMap[servName]; ok {
								svc := objService.Service(n.node)
								if svc != nil {
									original.AddService(svc)
								}
							}
						}
					}
				}
			}

			// 解析 transfer（转换配置）
			// 首先检查 snat 顶层是否有 transferIP（由 parseSNATBlock 设置）
			if transferIP, ok := snat["transferIP"].(string); ok && transferIP != "" {
				ng := network.NewNetworkGroup()
				if net, err := network.NewNetworkFromString(transferIP + "/32"); err == nil {
					ng.Add(net)
					translate.AddSrc(ng)
				}
			} else if transferIPGroup, ok := snat["transferIPGroup"].(string); ok && transferIPGroup != "" {
				transferIPGroup = strings.Trim(transferIPGroup, "\"")
				if objNetwork, ok := n.objects.networkMap[transferIPGroup]; ok {
					ng := objNetwork.Network(n.node)
					if ng != nil {
						translate.AddSrc(ng)
					}
				}
			} else if transfer, ok := snat["transfer"].(map[string]interface{}); ok {
				// 解析转换类型和地址
				if transferType, ok := transfer["transferType"].(string); ok {
					switch transferType {
					case "OUTIF_IP", "IP", "IP_RANGE", "IPGROUP":
						// 解析转换后的地址
						if transferIPGroup, ok := transfer["transferIPGroup"].(string); ok && transferIPGroup != "" {
							if objNetwork, ok := n.objects.networkMap[transferIPGroup]; ok {
								ng := objNetwork.Network(n.node)
								if ng != nil {
									translate.AddSrc(ng)
								}
							}
						} else if transferIPGroups, ok := transfer["ipGroups"]; ok {
							// 处理 ipGroups 可能是 string 或 []string 的情况
							if transferIPGroupStr, ok := transferIPGroups.(string); ok && transferIPGroupStr != "" {
								if objNetwork, ok := n.objects.networkMap[transferIPGroupStr]; ok {
									ng := objNetwork.Network(n.node)
									if ng != nil {
										translate.AddSrc(ng)
									}
								}
							} else if transferIPGroupSlice, ok := transferIPGroups.([]interface{}); ok {
								// 处理 []string 或 []interface{} 的情况
								for _, item := range transferIPGroupSlice {
									if transferIPGroupStr, ok := item.(string); ok && transferIPGroupStr != "" {
										if objNetwork, ok := n.objects.networkMap[transferIPGroupStr]; ok {
											ng := objNetwork.Network(n.node)
											if ng != nil {
												translate.AddSrc(ng)
											}
										}
									}
								}
							}
						} else if transferIP, ok := transfer["transferIP"].(string); ok && transferIP != "" {
							ng := network.NewNetworkGroup()
							if net, err := network.NewNetworkFromString(transferIP + "/32"); err == nil {
								ng.Add(net)
								translate.AddSrc(ng)
							}
						} else if specifyIp, ok := transfer["specifyIp"].(string); ok && specifyIp != "" {
							// 处理 JSON API 中的 "specifyIp" 字段（小写 i）
							ng := network.NewNetworkGroup()
							if net, err := network.NewNetworkFromString(specifyIp + "/32"); err == nil {
								ng.Add(net)
								translate.AddSrc(ng)
							}
						} else if ip, ok := transfer["ip"].(string); ok && ip != "" {
							// 处理 parseTransfer 生成的 "ip" 字段
							ng := network.NewNetworkGroup()
							if net, err := network.NewNetworkFromString(ip + "/32"); err == nil {
								ng.Add(net)
								translate.AddSrc(ng)
							}
						} else if transferType == "IP_RANGE" {
							// 处理 IP 范围
							if ipRange, ok := transfer["ipRange"].(map[string]interface{}); ok {
								start, _ := ipRange["start"].(string)
								end, _ := ipRange["end"].(string)
								if start != "" && end != "" {
									ng := network.NewNetworkGroup()
									if net, err := network.NewNetworkFromString(start + "-" + end); err == nil {
										ng.Add(net)
										translate.AddSrc(ng)
									}
								}
							} else if start, ok := transfer["start"].(string); ok {
								if end, ok2 := transfer["end"].(string); ok2 {
									ng := network.NewNetworkGroup()
									if net, err := network.NewNetworkFromString(start + "-" + end); err == nil {
										ng.Add(net)
										translate.AddSrc(ng)
									}
								}
							}
						}
					}
				}
			}

			// 解析 dstNetobj（目标网络对象）
			if dstNetobj, ok := snat["dstNetobj"].(map[string]interface{}); ok {
				if dstNetobjType, ok := dstNetobj["dstNetobjType"].(string); ok {
					if dstNetobjType == "ZONE" {
						// 解析 zone（支持 []interface{} 和 []string 两种类型）
						if zonesRaw, ok := dstNetobj["zone"]; ok {
							var zones []interface{}
							if zonesInterface, ok := zonesRaw.([]interface{}); ok {
								zones = zonesInterface
							} else if zonesString, ok := zonesRaw.([]string); ok {
								// 将 []string 转换为 []interface{}
								zones = make([]interface{}, len(zonesString))
								for i, v := range zonesString {
									zones[i] = v
								}
							}
							if len(zones) > 0 {
								if zoneStr, ok := zones[0].(string); ok {
									rule.to = zoneStr
								}
							}
						}
					} else if dstNetobjType == "INTERFACE" {
						if iface, ok := dstNetobj["interface"].(string); ok {
							rule.to = iface
						}
					}
				}
			}
		}
	} else {
		// DNAT/BNAT 解析
		var dnat map[string]interface{}
		if d, ok := itemMap["dnat"].(map[string]interface{}); ok {
			dnat = d
			fmt.Printf("[parseNatItem] 找到 dnat 字段，键: %v\n", func() []string {
				keys := make([]string, 0, len(d))
				for k := range d {
					keys = append(keys, k)
				}
				return keys
			}())
		} else if b, ok := itemMap["bnat"].(map[string]interface{}); ok {
			dnat = b
			fmt.Printf("[parseNatItem] 找到 bnat 字段\n")
		} else {
			fmt.Printf("[parseNatItem] 未找到 dnat 或 bnat 字段\n")
		}

		if dnat != nil {
			// 解析 srcZones
			if srcZones, ok := dnat["srcZones"].([]interface{}); ok && len(srcZones) > 0 {
				if zoneStr, ok := srcZones[0].(string); ok {
					rule.from = zoneStr
				}
			}

			// 解析 srcIpGroups（支持 []interface{} 和 []string 两种类型）
			if srcIpGroupsRaw, ok := dnat["srcIpGroups"]; ok {
				fmt.Printf("[parseNatItem] srcIpGroups 存在，类型: %T, 值: %v\n", srcIpGroupsRaw, srcIpGroupsRaw)
				var srcIpGroups []interface{}
				if srcIpGroupsInterface, ok := srcIpGroupsRaw.([]interface{}); ok {
					srcIpGroups = srcIpGroupsInterface
					fmt.Printf("[parseNatItem] srcIpGroups 是 []interface{}，数量: %d\n", len(srcIpGroups))
				} else if srcIpGroupsString, ok := srcIpGroupsRaw.([]string); ok {
					// 将 []string 转换为 []interface{}
					srcIpGroups = make([]interface{}, len(srcIpGroupsString))
					for i, v := range srcIpGroupsString {
						srcIpGroups[i] = v
					}
					fmt.Printf("[parseNatItem] srcIpGroups 是 []string，已转换为 []interface{}，数量: %d\n", len(srcIpGroups))
				} else {
					fmt.Printf("[parseNatItem] srcIpGroups 类型不支持: %T\n", srcIpGroupsRaw)
				}
				for i, ipGroup := range srcIpGroups {
					if ipGroupName, ok := ipGroup.(string); ok {
						fmt.Printf("[parseNatItem] 处理 srcIpGroup %d: %s\n", i, ipGroupName)
						if n.objects != nil && n.objects.networkMap != nil {
							if objNetwork, ok := n.objects.networkMap[ipGroupName]; ok {
								ng := objNetwork.Network(n.node)
								if ng != nil {
									fmt.Printf("[parseNatItem] 找到网络对象 %s，Network(): %s\n", ipGroupName, ng.String())
									original.AddSrc(ng)
								} else {
									fmt.Printf("[parseNatItem] 网络对象 %s 的 Network() 返回 nil\n", ipGroupName)
								}
							} else {
								fmt.Printf("[parseNatItem] 网络对象 %s 不存在于 networkMap 中（总数: %d）\n", ipGroupName, len(n.objects.networkMap))
							}
						} else {
							fmt.Printf("[parseNatItem] n.objects 或 networkMap 为 nil\n")
						}
					} else {
						fmt.Printf("[parseNatItem] srcIpGroup %d 不是 string: %T\n", i, ipGroup)
					}
				}
			} else {
				fmt.Printf("[parseNatItem] srcIpGroups 不存在\n")
			}

			// 解析 dstIpGroups（支持 []interface{} 和 []string 两种类型）
			if dstIpGroupsRaw, ok := dnat["dstIpGroups"]; ok {
				var dstIpGroups []interface{}
				if dstIpGroupsInterface, ok := dstIpGroupsRaw.([]interface{}); ok {
					dstIpGroups = dstIpGroupsInterface
				} else if dstIpGroupsString, ok := dstIpGroupsRaw.([]string); ok {
					// 将 []string 转换为 []interface{}
					dstIpGroups = make([]interface{}, len(dstIpGroupsString))
					for i, v := range dstIpGroupsString {
						dstIpGroups[i] = v
					}
				}
				for _, ipGroup := range dstIpGroups {
					if ipGroupName, ok := ipGroup.(string); ok {
						if n.objects != nil && n.objects.networkMap != nil {
							if objNetwork, ok := n.objects.networkMap[ipGroupName]; ok {
								ng := objNetwork.Network(n.node)
								if ng != nil {
									original.AddDst(ng)
								}
							}
						}
					}
				}
			}

			// 解析 dstIpobj（目标 IP 对象）
			if dstIpobj, ok := dnat["dstIpobj"].(map[string]interface{}); ok {
				if dstIpobjType, ok := dstIpobj["dstIpobjType"].(string); ok {
					if dstIpobjType == "IP" {
						// 解析 specifyIp 数组
						if specifyIp, ok := dstIpobj["specifyIp"].([]interface{}); ok {
							for _, ip := range specifyIp {
								if ipStr, ok := ip.(string); ok && ipStr != "" {
									ng := network.NewNetworkGroup()
									if net, err := network.NewNetworkFromString(ipStr + "/32"); err == nil {
										ng.Add(net)
										original.AddDst(ng)
									}
								}
							}
						}
						// 解析 ipGroups
						if ipGroups, ok := dstIpobj["ipGroups"].([]interface{}); ok {
							for _, ipGroup := range ipGroups {
								if ipGroupName, ok := ipGroup.(string); ok {
									if objNetwork, ok := n.objects.networkMap[ipGroupName]; ok {
										ng := objNetwork.Network(n.node)
										if ng != nil {
											original.AddDst(ng)
										}
									}
								}
							}
						}
					}
				}
			}

			// 解析 natService（支持 []interface{} 和 []string 两种类型）
			if natServiceRaw, ok := dnat["natService"]; ok {
				var natService []interface{}
				if natServiceInterface, ok := natServiceRaw.([]interface{}); ok {
					natService = natServiceInterface
				} else if natServiceString, ok := natServiceRaw.([]string); ok {
					// 将 []string 转换为 []interface{}
					natService = make([]interface{}, len(natServiceString))
					for i, v := range natServiceString {
						natService[i] = v
					}
				}
				for _, serv := range natService {
					if servName, ok := serv.(string); ok {
						if n.objects != nil && n.objects.serviceMap != nil {
							if objService, ok := n.objects.serviceMap[servName]; ok {
								svc := objService.Service(n.node)
								if svc != nil {
									original.AddService(svc)
								}
							}
						}
					}
				}
			}

			// 解析 dstIp（如果存在）
			if dstIp, ok := dnat["dstIp"].(string); ok && dstIp != "" {
				// 将 dstIp 添加到 original 的 Dst
				ng := network.NewNetworkGroup()
				if net, err := network.NewNetworkFromString(dstIp + "/32"); err == nil {
					ng.Add(net)
					original.AddDst(ng)
				}
			}

			// 解析 transfer（转换配置）
			// 首先检查 dnat 顶层是否有 transferIP（由 parseDNATBlock 设置）
			transferIP, hasTransferIP := dnat["transferIP"].(string)
			transferIPGroup, hasTransferIPGroup := dnat["transferIPGroup"].(string)
			transferRaw, hasTransfer := dnat["transfer"]
			fmt.Printf("[parseNatItem] transfer 相关字段: transferIP=%v (存在: %v), transferIPGroup=%v (存在: %v), transfer=%v (存在: %v, 类型: %T)\n",
				transferIP, hasTransferIP && transferIP != "", transferIPGroup, hasTransferIPGroup && transferIPGroup != "", transferRaw, hasTransfer, transferRaw)

			if hasTransferIP && transferIP != "" {
				fmt.Printf("[parseNatItem] 使用 transferIP: %s\n", transferIP)
				ng := network.NewNetworkGroup()
				if net, err := network.NewNetworkFromString(transferIP + "/32"); err == nil {
					ng.Add(net)
					translate.AddDst(ng)
					fmt.Printf("[parseNatItem] translate.Dst 设置为: %s\n", ng.String())
				} else {
					fmt.Printf("[parseNatItem] 解析 transferIP 失败: %v\n", err)
				}
				// 解析 transferPort（如果有）
				if transferPort, ok := dnat["transferPort"].(string); ok && transferPort != "" {
					fmt.Printf("[parseNatItem] 使用 transferPort: %s\n", transferPort)
					if tcpSvc, err := service.NewServiceWithL4("tcp", "0-65535", transferPort); err == nil {
						translate.AddService(tcpSvc)
						fmt.Printf("[parseNatItem] translate.Service 设置为: %s\n", tcpSvc.String())
					} else {
						fmt.Printf("[parseNatItem] 创建服务失败: %v\n", err)
					}
				} else {
					fmt.Printf("[parseNatItem] transferPort 不存在或为空\n")
				}
			} else if hasTransferIPGroup && transferIPGroup != "" {
				fmt.Printf("[parseNatItem] 使用 transferIPGroup: %s\n", transferIPGroup)
				if objNetwork, ok := n.objects.networkMap[transferIPGroup]; ok {
					ng := objNetwork.Network(n.node)
					if ng != nil {
						translate.AddDst(ng)
					}
				}
			} else if transfer, ok := dnat["transfer"].(map[string]interface{}); ok {
				// 解析转换类型和地址
				if transferType, ok := transfer["transferType"].(string); ok {
					switch transferType {
					case "IP", "IP_RANGE", "IP_PREFIX", "IPGROUP":
						// 解析转换后的地址
						if transferIPGroup, ok := transfer["transferIPGroup"].(string); ok && transferIPGroup != "" {
							if objNetwork, ok := n.objects.networkMap[transferIPGroup]; ok {
								ng := objNetwork.Network(n.node)
								if ng != nil {
									translate.AddDst(ng)
								}
							}
						} else if transferIP, ok := transfer["transferIP"].(string); ok && transferIP != "" {
							ng := network.NewNetworkGroup()
							if net, err := network.NewNetworkFromString(transferIP + "/32"); err == nil {
								ng.Add(net)
								translate.AddDst(ng)
							}
						} else if specifyIp, ok := transfer["specifyIp"].(string); ok && specifyIp != "" {
							// 处理 JSON API 中的 "specifyIp" 字段（小写 i）
							ng := network.NewNetworkGroup()
							if net, err := network.NewNetworkFromString(specifyIp + "/32"); err == nil {
								ng.Add(net)
								translate.AddDst(ng)
							}
						} else if ip, ok := transfer["ip"].(string); ok && ip != "" {
							// 处理 parseTransfer 生成的 "ip" 字段
							ng := network.NewNetworkGroup()
							if net, err := network.NewNetworkFromString(ip + "/32"); err == nil {
								ng.Add(net)
								translate.AddDst(ng)
							}
						} else if transferType == "IP_RANGE" {
							// 处理 IP 范围
							if ipRange, ok := transfer["ipRange"].(map[string]interface{}); ok {
								start, _ := ipRange["start"].(string)
								end, _ := ipRange["end"].(string)
								if start != "" && end != "" {
									ng := network.NewNetworkGroup()
									if net, err := network.NewNetworkFromString(start + "-" + end); err == nil {
										ng.Add(net)
										translate.AddDst(ng)
									}
								}
							} else if start, ok := transfer["start"].(string); ok {
								if end, ok2 := transfer["end"].(string); ok2 {
									ng := network.NewNetworkGroup()
									if net, err := network.NewNetworkFromString(start + "-" + end); err == nil {
										ng.Add(net)
										translate.AddDst(ng)
									}
								}
							}
						}
					}
				}
				// 解析 transferPort（如果有）
				// 支持 string 和 []interface{} 两种类型
				if transferPortRaw, ok := transfer["transferPort"]; ok {
					var portStr string
					if transferPort, ok := transferPortRaw.(string); ok && transferPort != "" {
						// string 类型：直接使用
						portStr = transferPort
						fmt.Printf("[parseNatItem] 使用 transfer 中的 transferPort (string): %s\n", portStr)
					} else if transferPortArray, ok := transferPortRaw.([]interface{}); ok && len(transferPortArray) > 0 {
						// []interface{} 类型：解析端口范围数组
						var portStrs []string
						for _, portRange := range transferPortArray {
							if portRangeMap, ok := portRange.(map[string]interface{}); ok {
								start, _ := portRangeMap["start"].(float64)
								end, hasEnd := portRangeMap["end"].(float64)

								startInt := int(start)
								if hasEnd {
									endInt := int(end)
									// end 为 0 或等于 start 时，表示单个端口
									if endInt == 0 || startInt == endInt {
										portStrs = append(portStrs, fmt.Sprintf("%d", startInt))
									} else {
										portStrs = append(portStrs, fmt.Sprintf("%d-%d", startInt, endInt))
									}
								} else {
									portStrs = append(portStrs, fmt.Sprintf("%d", startInt))
								}
							}
						}
						if len(portStrs) > 0 {
							if len(portStrs) == 1 {
								portStr = portStrs[0]
							} else {
								// 多个端口范围用逗号连接
								portStr = strings.Join(portStrs, ",")
							}
							fmt.Printf("[parseNatItem] 使用 transfer 中的 transferPort (array): %s\n", portStr)
						}
					}

					// 如果成功解析到端口字符串，创建服务对象
					if portStr != "" {
						if tcpSvc, err := service.NewServiceWithL4("tcp", "0-65535", portStr); err == nil {
							translate.AddService(tcpSvc)
							fmt.Printf("[parseNatItem] translate.Service 设置为: %s\n", tcpSvc.String())
						} else {
							fmt.Printf("[parseNatItem] 创建服务失败: %v\n", err)
						}
					}
				}
			}
		}
	}

	rule.original = original
	rule.translate = translate

	// 只返回启用的规则
	if !rule.enable {
		return nil
	}

	// 验证 translate 是否为空，如果为空则记录警告
	if rule.translate != nil {
		if rule.translate.Src() != nil && rule.translate.Src().IsEmpty() &&
			rule.translate.Dst() != nil && rule.translate.Dst().IsEmpty() &&
			rule.translate.Service() != nil && rule.translate.Service().IsEmpty() {
			// translate 为空，这可能表示解析失败
			// 但为了兼容性，仍然返回规则
		}
	}

	return rule
}

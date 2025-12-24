package sangfor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	policyutil "github.com/netxops/utils/policy"
)

type PolicySet struct {
	objects   *SangforObjectSet
	node      *SangforNode
	policySet []*Policy
}

type Policy struct {
	node        *SangforNode
	objects     *SangforObjectSet
	name        string
	uuid        string
	description string
	enable      bool
	policyType  string // SERVER/INTERNET_ACCESS
	srcZones    []string
	dstZones    []string
	action      firewall.Action
	policyEntry policyutil.PolicyEntryInf
	// 扩展字段
	strategy string                 // 业务访问场景 (NOT_VIA_SNAT_CDN/VIA_SNAT_CDN)
	position uint32                 // 位置 (0-1024)
	monitor  map[string]interface{} // 评估
	defence  map[string]interface{} // 防御
	response map[string]interface{} // 检测响应
	// 用户相关字段（从 srcAddrs 中解析）
	users      []string // 源用户
	userGroups []string // 源用户组
}

func (p *Policy) Action() firewall.Action {
	return p.action
}

func (p *Policy) Name() string {
	return p.name
}

func (p *Policy) ID() string {
	return p.uuid
}

func (p *Policy) Description() string {
	return p.description
}

func (p *Policy) Cli() string {
	var builder strings.Builder
	builder.WriteString("config\n")
	builder.WriteString(fmt.Sprintf(`policy "%s" bottom`, p.name))
	builder.WriteString("\n")

	if p.enable {
		builder.WriteString("enable\n")
	}

	builder.WriteString(`group "default-policygroup"`)
	builder.WriteString("\n")

	// 源 IP 组
	if p.policyEntry != nil {
		srcNg := p.policyEntry.Src()
		if srcNg != nil && !srcNg.IsEmpty() {
			obj, found := p.node.GetObjectByNetworkGroup(srcNg, firewall.SEARCH_OBJECT_OR_GROUP, nil)
			if found {
				builder.WriteString(fmt.Sprintf(`src-ipgroup "%s"`, obj.Name()))
				builder.WriteString("\n")
			}
		}

		// 目标 IP 组
		dstNg := p.policyEntry.Dst()
		if dstNg != nil && !dstNg.IsEmpty() {
			obj, found := p.node.GetObjectByNetworkGroup(dstNg, firewall.SEARCH_OBJECT_OR_GROUP, nil)
			if found {
				builder.WriteString(fmt.Sprintf(`dst-ipgroup "%s"`, obj.Name()))
				builder.WriteString("\n")
			}
		}

		// 服务
		svc := p.policyEntry.Service()
		if svc != nil && !svc.IsEmpty() {
			obj, found := p.node.GetObjectByService(svc, firewall.SEARCH_OBJECT_OR_GROUP)
			if found {
				builder.WriteString(fmt.Sprintf(`service "%s"`, obj.Name()))
				builder.WriteString("\n")
			} else {
				builder.WriteString(`service "any"`)
				builder.WriteString("\n")
			}
		} else {
			builder.WriteString(`service "any"`)
			builder.WriteString("\n")
		}
	}

	builder.WriteString(`user-group "/"`)
	builder.WriteString("\n")
	builder.WriteString(`application "全部"`)
	builder.WriteString("\n")

	// 动作
	if p.action == firewall.POLICY_PERMIT {
		builder.WriteString("action permit\n")
	} else {
		builder.WriteString("action deny\n")
	}

	builder.WriteString(`schedule "all-week"`)
	builder.WriteString("\n")
	builder.WriteString("log session-start disable\n")
	builder.WriteString("log session-end disable\n")
	builder.WriteString("end\n")

	return builder.String()
}

func (p *Policy) PolicyEntry() policyutil.PolicyEntryInf {
	return p.policyEntry
}

func (p *Policy) Extended() map[string]interface{} {
	return make(map[string]interface{})
}

// GetSourceAddressObject 获取策略使用的源地址对象
func (p *Policy) GetSourceAddressObject() (firewall.FirewallNetworkObject, bool) {
	if p.policyEntry == nil || p.objects == nil {
		return nil, false
	}

	// 从 policyEntry 中获取源网络组，然后查找对应的对象
	if srcNg := p.policyEntry.Src(); srcNg != nil && !srcNg.IsEmpty() {
		obj, found := p.objects.GetObjectByNetworkGroup(srcNg, firewall.SEARCH_OBJECT_OR_GROUP, nil)
		if found {
			return obj, true
		}
	}

	return nil, false
}

// GetDestinationAddressObject 获取策略使用的目标地址对象
func (p *Policy) GetDestinationAddressObject() (firewall.FirewallNetworkObject, bool) {
	if p.policyEntry == nil || p.objects == nil {
		return nil, false
	}

	// 从 policyEntry 中获取目标网络组，然后查找对应的对象
	if dstNg := p.policyEntry.Dst(); dstNg != nil && !dstNg.IsEmpty() {
		obj, found := p.objects.GetObjectByNetworkGroup(dstNg, firewall.SEARCH_OBJECT_OR_GROUP, nil)
		if found {
			return obj, true
		}
	}

	return nil, false
}

// GetServiceObject 获取策略使用的服务对象
func (p *Policy) GetServiceObject() (firewall.FirewallServiceObject, bool) {
	if p.policyEntry == nil || p.objects == nil {
		return nil, false
	}

	// 从 policyEntry 中获取服务，然后查找对应的对象
	if svc := p.policyEntry.Service(); svc != nil && !svc.IsEmpty() {
		obj, found := p.objects.GetObjectByService(svc, firewall.SEARCH_OBJECT_OR_GROUP)
		if found {
			return obj, true
		}
	}

	return nil, false
}

func (p *Policy) FromZones() []string {
	return p.srcZones
}

func (p *Policy) ToZones() []string {
	return p.dstZones
}

func (p *Policy) FromPorts() []api.Port {
	return []api.Port{}
}

func (p *Policy) ToPorts() []api.Port {
	return []api.Port{}
}

func (ps *PolicySet) HasPolicyName(name string) bool {
	for _, plc := range ps.policySet {
		if plc.Name() == name {
			return true
		}
	}
	return false
}

func (ps *PolicySet) Policies() []firewall.FirewallPolicy {
	policies := []firewall.FirewallPolicy{}
	for _, plc := range ps.policySet {
		policies = append(policies, plc)
	}
	return policies
}

// addPolicy 添加策略，如果存在同名策略则合并
func (ps *PolicySet) addPolicy(plc *Policy) {
	// 查找是否存在同名策略
	for i, existingPlc := range ps.policySet {
		if existingPlc.name == plc.name {
			// 找到同名策略，进行合并
			mergePolicy(ps.policySet[i], plc)
			return
		}
	}

	// 如果没有找到同名策略，直接添加新策略
	ps.policySet = append(ps.policySet, plc)
}

// mergePolicy 合并策略的地址和服务
func mergePolicy(existing *Policy, new *Policy) {
	// 合并源地址
	if new.policyEntry != nil && new.policyEntry.Src() != nil && !new.policyEntry.Src().IsAny(true) {
		if existing.policyEntry == nil {
			existing.policyEntry = policyutil.NewPolicyEntry()
		}
		existing.policyEntry.AddSrc(new.policyEntry.Src())
	}

	// 合并目标地址
	if new.policyEntry != nil && new.policyEntry.Dst() != nil && !new.policyEntry.Dst().IsAny(true) {
		if existing.policyEntry == nil {
			existing.policyEntry = policyutil.NewPolicyEntry()
		}
		existing.policyEntry.AddDst(new.policyEntry.Dst())
	}

	// 合并服务
	if new.policyEntry != nil && new.policyEntry.Service() != nil && !new.policyEntry.Service().IsAny(true) {
		if existing.policyEntry == nil {
			existing.policyEntry = policyutil.NewPolicyEntry()
		}
		existing.policyEntry.AddService(new.policyEntry.Service())
	}
}

// parseRespResultForPolicy 解析安全策略响应
func (ps *PolicySet) parseRespResultForPolicy(resp map[string]interface{}) {
	// 检查响应码
	if code, ok := resp["code"].(float64); !ok || code != 0 {
		return
	}

	// 解析 data.items 数组
	if data, ok := resp["data"].(map[string]interface{}); ok {
		if items, ok := data["items"].([]interface{}); ok {
			for _, item := range items {
				if itemMap, ok := item.(map[string]interface{}); ok {
					policy := ps.parsePolicyItem(itemMap)
					if policy != nil {
						ps.policySet = append(ps.policySet, policy)
					}
				}
			}
		}
	}
}

// parsePolicyItem 解析单个策略项
func (ps *PolicySet) parsePolicyItem(itemMap map[string]interface{}) *Policy {
	name, _ := itemMap["name"].(string)
	if name == "" {
		return nil
	}

	policy := &Policy{
		node:    ps.node,
		objects: ps.objects,
		name:    name,
	}

	// 解析基础字段
	if uuid, ok := itemMap["uuid"].(string); ok {
		policy.uuid = uuid
	}
	if desc, ok := itemMap["description"].(string); ok {
		policy.description = desc
	}
	if enable, ok := itemMap["enable"].(bool); ok {
		policy.enable = enable
	}
	if ptype, ok := itemMap["policyType"].(string); ok {
		policy.policyType = ptype
	}

	// 解析 srcZones
	if srcZones, ok := itemMap["srcZones"].([]interface{}); ok {
		for _, zone := range srcZones {
			if zoneStr, ok := zone.(string); ok {
				policy.srcZones = append(policy.srcZones, zoneStr)
			}
		}
	}

	// 解析 dstZones
	if dstZones, ok := itemMap["dstZones"].([]interface{}); ok {
		for _, zone := range dstZones {
			if zoneStr, ok := zone.(string); ok {
				policy.dstZones = append(policy.dstZones, zoneStr)
			}
		}
	}

	// 创建策略条目
	pe := policyutil.NewPolicyEntry()

	// 支持两种数据结构：
	// 1. 安全策略（securitys）：使用 srcAddrs, dstIpGroups, services
	// 2. 应用访问策略（appcontrols）：使用 src, dst

	// 先尝试解析应用访问策略格式（src/dst）
	if src, ok := itemMap["src"].(map[string]interface{}); ok {
		// 解析 srcZones
		if srcZones, ok := src["srcZones"].([]interface{}); ok {
			for _, zone := range srcZones {
				if zoneStr, ok := zone.(string); ok {
					policy.srcZones = append(policy.srcZones, zoneStr)
				}
			}
		}
		// 解析 srcAddrs
		if srcAddrs, ok := src["srcAddrs"].(map[string]interface{}); ok {
			if srcAddrType, ok := srcAddrs["srcAddrType"].(string); ok && srcAddrType == "NETOBJECT" {
				// 解析 srcIpGroups
				if srcIpGroups, ok := srcAddrs["srcIpGroups"].([]interface{}); ok {
					for _, ipGroup := range srcIpGroups {
						if ipGroupName, ok := ipGroup.(string); ok {
							if objNetwork, ok := ps.objects.networkMap[ipGroupName]; ok {
								ng := objNetwork.Network(ps.node)
								if ng != nil {
									pe.AddSrc(ng)
								}
							}
						}
					}
				}
			}
			// 解析 users 和 userGroups
			if users, ok := srcAddrs["users"].([]interface{}); ok {
				for _, user := range users {
					if userStr, ok := user.(string); ok {
						policy.users = append(policy.users, userStr)
					}
				}
			}
			if userGroups, ok := srcAddrs["userGroups"].([]interface{}); ok {
				for _, userGroup := range userGroups {
					if userGroupStr, ok := userGroup.(string); ok {
						policy.userGroups = append(policy.userGroups, userGroupStr)
					}
				}
			}
		}
	}

	if dst, ok := itemMap["dst"].(map[string]interface{}); ok {
		// 解析 dstZones
		if dstZones, ok := dst["dstZones"].([]interface{}); ok {
			for _, zone := range dstZones {
				if zoneStr, ok := zone.(string); ok {
					policy.dstZones = append(policy.dstZones, zoneStr)
				}
			}
		}
		// 解析 dstAddrs
		if dstAddrs, ok := dst["dstAddrs"].(map[string]interface{}); ok {
			// 支持两种类型：NETOBJECT 和其他类型（如 INLINE）
			dstAddrType, _ := dstAddrs["dstAddrType"].(string)
			if dstAddrType == "NETOBJECT" {
				// 解析 dstIpGroups（支持 []interface{} 和 []string 两种类型）
				if dstIpGroupsRaw, ok := dstAddrs["dstIpGroups"]; ok {
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
							if objNetwork, ok := ps.objects.networkMap[ipGroupName]; ok {
								ng := objNetwork.Network(ps.node)
								if ng != nil {
									pe.AddDst(ng)
								}
							}
						}
					}
				}
			}
		}
		// 解析 services
		if services, ok := dst["services"].([]interface{}); ok {
			for _, serv := range services {
				if servName, ok := serv.(string); ok {
					if objService, ok := ps.objects.serviceMap[servName]; ok {
						svc := objService.Service(ps.node)
						if svc != nil {
							pe.AddService(svc)
						}
					}
				}
			}
		}
	}

	// 兼容安全策略格式（srcAddrs, dstIpGroups, services 在顶层）
	if srcAddrs, ok := itemMap["srcAddrs"].(map[string]interface{}); ok {
		if srcAddrType, ok := srcAddrs["srcAddrType"].(string); ok && srcAddrType == "NETOBJECT" {
			// 解析 srcIpGroups
			if srcIpGroups, ok := srcAddrs["srcIpGroups"].([]interface{}); ok {
				for _, ipGroup := range srcIpGroups {
					if ipGroupName, ok := ipGroup.(string); ok {
						if objNetwork, ok := ps.objects.networkMap[ipGroupName]; ok {
							ng := objNetwork.Network(ps.node)
							if ng != nil {
								pe.AddSrc(ng)
							}
						}
					}
				}
			}
		}
		// 解析 users 和 userGroups
		if users, ok := srcAddrs["users"].([]interface{}); ok {
			for _, user := range users {
				if userStr, ok := user.(string); ok {
					policy.users = append(policy.users, userStr)
				}
			}
		}
		if userGroups, ok := srcAddrs["userGroups"].([]interface{}); ok {
			for _, userGroup := range userGroups {
				if userGroupStr, ok := userGroup.(string); ok {
					policy.userGroups = append(policy.userGroups, userGroupStr)
				}
			}
		}
	}

	// 解析 dstIpGroups（安全策略格式，仅在顶层存在时处理）
	// 注意：如果已经通过 dst.dstAddrs.dstIpGroups 解析过，这里不会重复处理
	if dstIpGroupsRaw, ok := itemMap["dstIpGroups"]; ok {
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
				if objNetwork, ok := ps.objects.networkMap[ipGroupName]; ok {
					ng := objNetwork.Network(ps.node)
					if ng != nil {
						pe.AddDst(ng)
					}
				}
			}
		}
	}

	// 解析 services（安全策略格式）
	if services, ok := itemMap["services"].([]interface{}); ok {
		for _, serv := range services {
			if servName, ok := serv.(string); ok {
				if objService, ok := ps.objects.serviceMap[servName]; ok {
					svc := objService.Service(ps.node)
					if svc != nil {
						pe.AddService(svc)
					}
				}
			}
		}
	}

	// 解析 action
	// 支持两种格式：
	// 1. 字符串格式（安全策略）："ALLOW", "DENY"
	// 2. 数字格式（应用访问策略）：0=拒绝, 1=允许
	if action, ok := itemMap["action"].(string); ok {
		switch action {
		case "ALLOW":
			policy.action = firewall.POLICY_PERMIT
		case "DENY":
			policy.action = firewall.POLICY_DENY
		default:
			policy.action = firewall.POLICY_IMPLICIT_DENY
		}
	} else if actionNum, ok := itemMap["action"].(float64); ok {
		// 应用访问策略格式：0=拒绝, 1=允许
		if actionNum == 1 {
			policy.action = firewall.POLICY_PERMIT
		} else {
			policy.action = firewall.POLICY_DENY
		}
	} else {
		policy.action = firewall.POLICY_IMPLICIT_DENY
	}

	// 解析扩展字段
	if strategy, ok := itemMap["strategy"].(string); ok {
		policy.strategy = strategy
	}

	if position, ok := itemMap["position"].(float64); ok {
		policy.position = uint32(position)
	} else {
		// 如果没有 position 字段，默认设置为最大值（1024），使其在最后匹配
		// 这样默认策略（如 default-policy）会最后匹配
		policy.position = 1024
	}

	// 解析 monitor (评估)
	if monitor, ok := itemMap["monitor"].(map[string]interface{}); ok {
		policy.monitor = monitor
	}

	// 解析 defence (防御)
	if defence, ok := itemMap["defence"].(map[string]interface{}); ok {
		policy.defence = defence
	}

	// 解析 response (检测响应)
	if response, ok := itemMap["response"].(map[string]interface{}); ok {
		policy.response = response
	}

	policy.policyEntry = pe

	// 只返回启用的策略
	if !policy.enable {
		return nil
	}

	return policy
}

// Match 匹配策略，参考 FortiGate 的实现
// 策略按 position 排序后匹配，position 越小越优先
// 注意：Sangfor 的接口和 zone 没有关联关系，策略匹配时不使用 zone 信息
// 参数 from 和 to 是接口名称，仅用于日志记录，不参与匹配逻辑
func (ps *PolicySet) Match(from, to string, pe policyutil.PolicyEntryInf) (bool, firewall.FirewallPolicy) {
	fmt.Printf("[DEBUG PolicySet.Match] 开始匹配策略\n")
	fmt.Printf("  源接口: %s, 目标接口: %s (注意：接口和zone无关联，仅用于日志)\n", from, to)
	fmt.Printf("  策略总数: %d\n", len(ps.policySet))

	// 创建策略副本并按 position 排序（position 越小越优先）
	rules := make([]*Policy, len(ps.policySet))
	copy(rules, ps.policySet)
	sort.Slice(rules, func(i, j int) bool {
		// position 越小越优先
		// 如果 position 相同，则按名称排序以确保稳定性
		if rules[i].position != rules[j].position {
			return rules[i].position < rules[j].position
		}
		return rules[i].name < rules[j].name
	})

	// 打印排序后的策略列表
	fmt.Printf("[DEBUG PolicySet.Match] 排序后的策略列表:\n")
	for idx, rule := range rules {
		actionStr := "UNKNOWN"
		switch rule.action {
		case firewall.POLICY_PERMIT:
			actionStr = "PERMIT"
		case firewall.POLICY_DENY:
			actionStr = "DENY"
		case firewall.POLICY_IMPLICIT_DENY:
			actionStr = "IMPLICIT_DENY"
		}
		fmt.Printf("  [%d] 策略: %s, position: %d, action: %s, enable: %v\n",
			idx+1, rule.name, rule.position, actionStr, rule.enable)
		if rule.policyEntry != nil {
			if src := rule.policyEntry.Src(); src != nil {
				fmt.Printf("       源网络: %s\n", src.String())
			}
			if dst := rule.policyEntry.Dst(); dst != nil {
				fmt.Printf("       目标网络: %s\n", dst.String())
			}
			if svc := rule.policyEntry.Service(); svc != nil {
				fmt.Printf("       服务: %s\n", svc.String())
			}
		} else {
			fmt.Printf("       警告: policyEntry 为 nil\n")
		}
	}

	// 打印要匹配的策略条目信息
	fmt.Printf("[DEBUG PolicySet.Match] 要匹配的策略条目:\n")
	if pe != nil {
		if src := pe.Src(); src != nil {
			fmt.Printf("  源网络: %s\n", src.String())
		}
		if dst := pe.Dst(); dst != nil {
			fmt.Printf("  目标网络: %s\n", dst.String())
		}
		if svc := pe.Service(); svc != nil {
			fmt.Printf("  服务: %s\n", svc.String())
		}
	} else {
		fmt.Printf("  警告: 策略条目为 nil\n")
	}

	// 开始匹配
	fmt.Printf("[DEBUG PolicySet.Match] 开始逐个匹配策略...\n")
	for idx, rule := range rules {
		// 忽略 default-policy，因为会被拒绝，导致不再进行新策略生成
		if rule.name == "default-policy" {
			fmt.Printf("  [%d] 跳过策略 %s: 忽略 default-policy（避免阻止新策略生成）\n", idx+1, rule.name)
			continue
		}

		// 检查策略是否激活
		if rule.PolicyEntry() == nil {
			fmt.Printf("  [%d] 跳过策略 %s: policyEntry 为 nil\n", idx+1, rule.name)
			continue
		}

		// 检查策略是否启用
		if !rule.enable {
			fmt.Printf("  [%d] 跳过策略 %s: 未启用\n", idx+1, rule.name)
			continue
		}

		// 注意：Sangfor 的接口和 zone 没有关联关系
		// 策略中的 srcZones 和 dstZones 虽然被解析，但在匹配时不使用
		// 策略匹配只基于源/目标网络和服务，不基于接口或 zone

		// 匹配策略条目
		// 打印详细的匹配过程
		ruleEntry := rule.PolicyEntry()
		fmt.Printf("  [%d] 策略 %s: 开始匹配...\n", idx+1, rule.name)

		// 检查源网络匹配
		ruleSrc := ruleEntry.Src()
		peSrc := pe.Src()
		srcMatched := false
		if ruleSrc != nil && peSrc != nil {
			// 使用 MatchNetworkGroup 检查重叠
			// 策略的源网络应该与请求的源网络有重叠
			_, mid, _ := network.NetworkGroupCmp(*ruleSrc, *peSrc)
			srcMatched = mid != nil && !mid.IsEmpty()
			fmt.Printf("      源网络匹配: 策略源=%s, 请求源=%s, 重叠=%s, 匹配=%v\n",
				ruleSrc.String(), peSrc.String(), func() string {
					if mid != nil {
						return mid.String()
					}
					return "无"
				}(), srcMatched)
		} else {
			fmt.Printf("      源网络匹配: 策略源=%v, 请求源=%v\n", ruleSrc != nil, peSrc != nil)
		}

		// 检查目标网络匹配
		ruleDst := ruleEntry.Dst()
		peDst := pe.Dst()
		dstMatched := false
		if ruleDst != nil && peDst != nil {
			// 策略的目标网络应该与请求的目标网络有重叠
			_, mid, _ := network.NetworkGroupCmp(*ruleDst, *peDst)
			dstMatched = mid != nil && !mid.IsEmpty()
			fmt.Printf("      目标网络匹配: 策略目标=%s, 请求目标=%s, 重叠=%s, 匹配=%v\n",
				ruleDst.String(), peDst.String(), func() string {
					if mid != nil {
						return mid.String()
					}
					return "无"
				}(), dstMatched)
		} else {
			fmt.Printf("      目标网络匹配: 策略目标=%v, 请求目标=%v\n", ruleDst != nil, peDst != nil)
		}

		// 检查服务匹配
		ruleSvc := ruleEntry.Service()
		peSvc := pe.Service()
		svcMatched := false
		if ruleSvc != nil && peSvc != nil {
			// Service 使用 Match 方法进行匹配
			svcMatched = ruleSvc.Match(peSvc) || peSvc.Match(ruleSvc)
			fmt.Printf("      服务匹配: 策略服务=%s, 请求服务=%s, 匹配=%v\n",
				ruleSvc.String(), peSvc.String(), svcMatched)
		} else {
			fmt.Printf("      服务匹配: 策略服务=%v, 请求服务=%v\n", ruleSvc != nil, peSvc != nil)
		}

		// 正向匹配（策略只能正向匹配，不支持反向）
		matched := ruleEntry.Match(pe)
		fmt.Printf("  [%d] 策略 %s: 最终匹配结果 = %v (源=%v, 目标=%v, 服务=%v)\n",
			idx+1, rule.name, matched, srcMatched, dstMatched, svcMatched)

		if matched {
			actionStr := "UNKNOWN"
			switch rule.action {
			case firewall.POLICY_PERMIT:
				actionStr = "PERMIT"
			case firewall.POLICY_DENY:
				actionStr = "DENY"
			case firewall.POLICY_IMPLICIT_DENY:
				actionStr = "IMPLICIT_DENY"
			}
			fmt.Printf("[DEBUG PolicySet.Match] ✓ 匹配成功! 策略: %s, Action: %s\n", rule.name, actionStr)
			return true, rule
		}
	}

	fmt.Printf("[DEBUG PolicySet.Match] ✗ 未找到匹配的策略\n")
	return false, nil
}

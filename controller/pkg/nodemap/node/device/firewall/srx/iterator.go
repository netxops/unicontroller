package srx

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
)

var _ firewall.IteratorFirewall = &SRXNode{}

// PolicyIterator 实现策略迭代器
func (srx *SRXNode) PolicyIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	policies := make([]firewall.Namer, 0)

	// 遍历所有策略
	for _, toMap := range srx.policySet.policySet {
		for _, plcList := range toMap {
			for _, policy := range plcList {
				policies = append(policies, policy)
			}
		}
	}

	return firewall.NewBaseIterator(policies, options, policyFilter)
}

func policyFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	policy, ok := item.(*Policy)
	if !ok {
		return false
	}

	// 检查 FromZone
	if options.FromZone != "" {
		fromMatch := false
		for _, from := range policy.srcZone {
			if from == options.FromZone {
				fromMatch = true
				break
			}
		}
		if !fromMatch {
			return false
		}
	}

	// 检查 ToZone
	if options.ToZone != "" {
		toMatch := false
		for _, to := range policy.dstZone {
			if to == options.ToZone {
				toMatch = true
				break
			}
		}
		if !toMatch {
			return false
		}
	}

	return true
}

// NetworkIterator 实现网络对象迭代器
func (srx *SRXNode) NetworkIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	networks := make([]firewall.Namer, 0)

	// 遍历所有zone的地址对象
	for _, zoneMap := range srx.objectSet.zoneAddressBook {
		for _, obj := range zoneMap {
			networks = append(networks, obj)
		}
	}

	return firewall.NewBaseIterator(networks, options, networkFilter)
}

func networkFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	// 可以根据需要添加过滤逻辑
	return true
}

// ServiceIterator 实现服务对象迭代器
func (srx *SRXNode) ServiceIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	services := make([]firewall.Namer, 0)

	// 遍历所有服务对象
	for _, service := range srx.objectSet.serviceMap {
		services = append(services, service)
	}

	return firewall.NewBaseIterator(services, options, serviceFilter)
}

func serviceFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	service, ok := item.(firewall.FirewallServiceObject)
	if !ok {
		return false
	}
	if options.Protocol != 0 && int(service.Service(nil).Protocol()) != options.Protocol {
		return false
	}
	return true
}

// NatIterator 实现NAT规则迭代器
func (srx *SRXNode) NatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)

	var allRules []*NatRule

	switch options.NatType {
	case firewall.STATIC_NAT:
		allRules = flattenSRXNatRules(srx.nats.staticNatRules)
	case firewall.DYNAMIC_NAT:
		allRules = flattenSRXNatRules(srx.nats.sourceNatRules)
	case firewall.DESTINATION_NAT:
		allRules = flattenSRXNatRules(srx.nats.destinationNatRules)
	default:
		allRules = append(allRules, flattenSRXNatRules(srx.nats.staticNatRules)...)
		allRules = append(allRules, flattenSRXNatRules(srx.nats.sourceNatRules)...)
		allRules = append(allRules, flattenSRXNatRules(srx.nats.destinationNatRules)...)
	}

	items := make([]firewall.Namer, len(allRules))
	for i, rule := range allRules {
		items[i] = rule
	}

	return firewall.NewBaseIterator(items, options, natFilter)
}

func flattenSRXNatRules(ruleSets map[string]*NatRuleSet) []*NatRule {
	var rules []*NatRule
	for _, set := range ruleSets {
		rules = append(rules, set.rules...)
	}
	return rules
}

func natFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	rule, ok := item.(*NatRule)
	if !ok {
		return false
	}

	if options.FromZone != "" {
		fromZone := ""
		if rule.from != nil {
			fromZone = rule.from.Zone()
		}
		if fromZone != options.FromZone {
			return false
		}
	}

	if options.ToZone != "" {
		toZone := ""
		if rule.to != nil {
			toZone = rule.to.Zone()
		}
		if toZone != options.ToZone {
			return false
		}
	}

	if options.NatType != 0 && rule.natType != options.NatType {
		return false
	}

	return true
}

// SnatIterator 实现SNAT迭代器
func (srx *SRXNode) SnatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.DYNAMIC_NAT))
	return srx.NatIterator(opts...)
}

// DnatIterator 实现DNAT迭代器
func (srx *SRXNode) DnatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.DESTINATION_NAT))
	return srx.NatIterator(opts...)
}

// StaticNatIterator 实现静态NAT迭代器
func (srx *SRXNode) StaticNatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.STATIC_NAT))
	return srx.NatIterator(opts...)
}

// NatPoolIterator 实现NAT池迭代器
func (srx *SRXNode) NatPoolIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	pools := make([]firewall.Namer, 0)

	// 遍历所有NAT池
	for _, poolMap := range srx.objectSet.poolMap {
		for _, pool := range poolMap {
			pools = append(pools, pool)
		}
	}

	return firewall.NewBaseIterator(pools, options, natPoolFilter)
}

func natPoolFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	pool, ok := item.(firewall.NatPool)
	if !ok {
		return false
	}
	if options.NetworkGroup != nil && !pool.MatchNetworkGroup(options.NetworkGroup) {
		return false
	}
	return true
}

// AclIterator 实现ACL迭代器
// SRX没有独立的ACL概念，策略本身就是类似ACL的规则
func (srx *SRXNode) AclIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	acls := make([]firewall.Namer, 0)

	// SRX没有独立的ACL，返回空列表
	// 如果需要，可以将策略名称作为ACL名称
	return firewall.NewBaseIterator(acls, options, aclFilter)
}

func aclFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	// SRX没有ACL，返回true
	return true
}

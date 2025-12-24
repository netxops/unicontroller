package dptech

import (
	"reflect"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/tools"
)

// PolicyIterator
func (dp *DptechNode) PolicyIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	policies := make([]firewall.Namer, 0)
	for _, plc := range dp.PolicySet.policySet {
		policies = append(policies, plc)
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

	// // 检查 Action
	// if options.Action != firewall.ACTION_UNKNOWN && policy.action != options.Action {
	//     return false
	// }

	// // 检查 Status
	// if options.Status != firewall.POLICY_STATUS_UNKNOWN && policy.status != options.Status {
	//     return false
	// }

	// // 检查源地址
	// if options.SrcAddress != nil {
	//     if policy.policyEntry == nil || !policy.policyEntry.Src().Contains(options.SrcAddress) {
	//         return false
	//     }
	// }

	// // 检查目标地址
	// if options.DstAddress != nil {
	//     if policy.policyEntry == nil || !policy.policyEntry.Dst().Contains(options.DstAddress) {
	//         return false
	//     }
	// }

	// // 检查服务
	// if options.Service != nil {
	//     if policy.policyEntry == nil || !policy.policyEntry.Service().Contains(options.Service) {
	//         return false
	//     }
	// }

	return true
}

// NetworkIterator
func (dp *DptechNode) NetworkIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	networks := make([]firewall.Namer, 0)
	for _, obj := range dp.ObjectSet.addressObjectSet {
		networks = append(networks, obj)
	}
	for _, obj := range dp.ObjectSet.addressGroupSet {
		networks = append(networks, obj)
	}

	return firewall.NewBaseIterator(networks, options, networkFilter)
}

func networkFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	// Implement network filtering logic if needed
	return true
}

// ServiceIterator
func (dp *DptechNode) ServiceIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	services := make([]firewall.Namer, 0)
	for _, service := range dp.ObjectSet.serviceMap {
		services = append(services, service)
	}
	for _, group := range dp.ObjectSet.serviceGroup {
		services = append(services, group)
	}

	return firewall.NewBaseIterator(services, options, serviceFilter)
}

func serviceFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	service := item.(firewall.FirewallServiceObject)
	if options.Protocol != 0 && int(service.Service(nil).Protocol()) != options.Protocol {
		return false
	}
	return true
}

type NatIterator struct {
	*firewall.BaseIterator
	nats *Nats
}

// NatIterator
func (dp *DptechNode) NatIterator(options ...firewall.IteratorOption) firewall.NamerIterator {
	nats := dp.Nats
	opts := firewall.ApplyOptions(options...)

	var allRules []*NatRule

	switch opts.NatType {
	case firewall.STATIC_NAT:
		allRules = flattenRules(nats.StaticNatRules)
	case firewall.DYNAMIC_NAT:
		allRules = flattenRules(nats.SourceNatRules)
	case firewall.DESTINATION_NAT:
		allRules = flattenRules(nats.DestinationNatRules)
	default:
		allRules = append(allRules, flattenRules(nats.StaticNatRules)...)
		allRules = append(allRules, flattenRules(nats.SourceNatRules)...)
		allRules = append(allRules, flattenRules(nats.DestinationNatRules)...)
	}

	items := make([]firewall.Namer, len(allRules))
	for i, rule := range allRules {
		items[i] = rule
	}

	return &NatIterator{
		BaseIterator: firewall.NewBaseIterator(items, opts, natFilter),
		nats:         nats,
	}

}

func flattenRules(ruleSets []*NatRuleSet) []*NatRule {
	var rules []*NatRule
	for _, set := range ruleSets {
		rules = append(rules, set.Rules...)
	}
	return rules
}

func natFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	rule, ok := item.(*NatRule)
	if !ok {
		return false
	}

	if options.FromZone != "" && !tools.Contains(rule.from, options.FromZone) {
		return false
	}

	if options.ToZone != "" && !tools.Contains(rule.to, options.ToZone) {
		return false
	}

	if rule.natType != options.NatType {
		return false
	}

	// Add more filtering conditions based on IteratorOptions if needed

	return true
}

// // Helper function to check if a slice contains a string
// func contains(slice []string, str string) bool {
//     for _, v := range slice {
//         if v == str {
//             return true
//         }
//     }
//     return false
// }

// NatPoolIterator
func (dp *DptechNode) NatPoolIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	pools := make([]firewall.Namer, 0)
	for _, pool := range dp.ObjectSet.poolMap {
		pools = append(pools, pool)
	}

	return firewall.NewBaseIterator(pools, options, natPoolFilter)
}

func natPoolFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	pool := item.(firewall.NatPool)
	if options.NetworkGroup != nil && !pool.MatchNetworkGroup(options.NetworkGroup) {
		return false
	}
	return true
}

// AclIterator
func (dp *DptechNode) AclIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	acls := make([]firewall.Namer, 0)
	// 假设 DptechNode 有一个 aclSet 字段存储 ACL
	// for _, acl := range node.aclSet {
	// 	acls = append(acls, acl)
	// }

	return firewall.NewBaseIterator(acls, options, aclFilter)
}

func aclFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	// acl := item.(firewall.FirewallAcl)
	// if options.AclType != "" && acl.Type() != options.AclType {
	// 	return false
	// }
	// 可以添加更多的过滤条件
	return true
}

// SnatIterator
func (dp *DptechNode) SnatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.DYNAMIC_NAT))
	return dp.NatIterator(opts...)
}

// DnatIterator
func (dp *DptechNode) DnatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.DESTINATION_NAT))
	return dp.NatIterator(opts...)
}

// StaticNatIterator
func (dp *DptechNode) StaticNatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.STATIC_NAT))
	return dp.NatIterator(opts...)
}

// 通用的 NAT 迭代器实现
// func (node *DptechNode) natIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
// 	options := firewall.ApplyOptions(opts...)
// 	rules := node.nats

// 	return firewall.NewBaseIterator(toNamerSlice(rules), options, natFilter)
// }

// func natFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
// 	rule := item.(firewall.FirewallNatRule)
// 	if options.FromZone != "" && rule.FromZone() != options.FromZone {
// 		return false
// 	}
// 	if options.ToZone != "" && rule.ToZone() != options.ToZone {
// 		return false
// 	}
// 	if options.NatType != 0 && rule.Type() != options.NatType {
// 		return false
// 	}
// 	return true
// }

// Helper function to convert a slice to []firewall.Namer
func toNamerSlice(items interface{}) []firewall.Namer {
	value := reflect.ValueOf(items)
	if value.Kind() != reflect.Slice {
		return nil
	}

	length := value.Len()
	namers := make([]firewall.Namer, length)

	for i := 0; i < length; i++ {
		item := value.Index(i).Interface()
		if namer, ok := item.(firewall.Namer); ok {
			namers[i] = namer
		} else {
			return nil
		}
	}

	return namers
}

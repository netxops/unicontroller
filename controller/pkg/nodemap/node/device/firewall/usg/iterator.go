package usg

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
)

// PolicyIterator 实现
type PolicyIterator struct {
	*firewall.BaseIterator
	policySet *PolicySet
}

func (node *UsgNode) PolicyIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	policies := node.policySet

	return &PolicyIterator{
		BaseIterator: firewall.NewBaseIterator(toNamerSlice(policies), options, policyFilter),
		policySet:    node.policySet,
	}
}

func policyFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	policy := item.(*Policy)
	if options.FromZone != "" && !contains(policy.srcZone, options.FromZone) {
		return false
	}
	if options.ToZone != "" && !contains(policy.dstZone, options.ToZone) {
		return false
	}
	return true
}

// NetworkIterator 实现
// type NetworkIterator struct {
//     *firewall.BaseIterator
//     objectSet *UsgObjectSet
//     zones     []string
//     zoneIndex int
// }

// NetworkIterator 实现
type NetworkIterator struct {
	*firewall.BaseIterator
	objectSet *UsgObjectSet
}

func (node *UsgNode) NetworkIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)

	allObjects := make([]firewall.Namer, 0)

	// 添加地址对象
	for _, obj := range node.objectSet.addressObjectSet {
		if namer, ok := obj.(firewall.Namer); ok {
			allObjects = append(allObjects, namer)
		}
	}

	// 添加地址组对象
	for _, obj := range node.objectSet.addressGroupSet {
		if namer, ok := obj.(firewall.Namer); ok {
			allObjects = append(allObjects, namer)
		}
	}

	return &NetworkIterator{
		BaseIterator: firewall.NewBaseIterator(allObjects, options, networkFilter),
		objectSet:    node.objectSet,
	}
}

func networkFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	// 实现网络对象的过滤逻辑
	// 如果需要基于区域进行过滤，可能需要在 FirewallNetworkObject 接口中添加获取区域的方法
	if options.Zone != "" {
		if zoneAware, ok := item.(interface{ Zone() string }); ok {
			return zoneAware.Zone() == options.Zone
		}
	}
	return true
}

// 由于不再使用 zoneAddressBook，我们可以移除 getZones 函数
// 如果仍然需要获取所有区域，可以通过遍历所有对象来收集唯一的区域
func getUniqueZones(objectSet *UsgObjectSet) []string {
	zoneSet := make(map[string]struct{})

	// 假设 FirewallNetworkObject 有一个 Zone() 方法返回其所属的区域
	for _, obj := range objectSet.addressObjectSet {
		if zoneAware, ok := obj.(interface{ Zone() string }); ok {
			zoneSet[zoneAware.Zone()] = struct{}{}
		}
	}
	for _, obj := range objectSet.addressGroupSet {
		if zoneAware, ok := obj.(interface{ Zone() string }); ok {
			zoneSet[zoneAware.Zone()] = struct{}{}
		}
	}

	zones := make([]string, 0, len(zoneSet))
	for zone := range zoneSet {
		zones = append(zones, zone)
	}
	return zones
}

// ServiceIterator 实现
type ServiceIterator struct {
	*firewall.BaseIterator
	objectSet *UsgObjectSet
}

func (node *UsgNode) ServiceIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	services := make([]firewall.Namer, 0, len(node.objectSet.serviceMap))
	for _, service := range node.objectSet.serviceMap {
		services = append(services, service)
	}

	return &ServiceIterator{
		BaseIterator: firewall.NewBaseIterator(services, options, serviceFilter),
		objectSet:    node.objectSet,
	}
}

func serviceFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	service := item.(firewall.FirewallServiceObject)
	if options.Protocol != 0 && int(service.Service(nil).Protocol()) != options.Protocol {
		return false
	}
	return true
}

// 在 iterator.go 文件中添加以下代码

// NatPoolIterator 结构体定义
type NatPoolIterator struct {
	*firewall.BaseIterator
}

// UsgNode 的 NatPoolIterator 方法实现
func (node *UsgNode) NatPoolIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	pools := make([]firewall.Namer, 0)

	// 添加地址组（addressGroups）
	for _, ag := range node.nats.addressGroups {
		pools = append(pools, ag)
	}

	// 添加内部池
	for _, pool := range node.nats.insidePools {
		pools = append(pools, pool)
	}

	// 添加全局池
	for _, pool := range node.nats.globalPools {
		pools = append(pools, pool)
	}

	return &NatPoolIterator{
		BaseIterator: firewall.NewBaseIterator(pools, options, natPoolFilter),
	}
}

// natPoolFilter 函数实现
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

// NatIterator 实现
type NatIterator struct {
	*firewall.BaseIterator
	nats *Nats
}

func (node *UsgNode) NatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	rules := getNatRules(node.nats, options.NatType)
	namerRules := make([]firewall.Namer, 0, len(rules))
	for _, rule := range rules {
		namerRules = append(namerRules, rule)
	}

	return &NatIterator{
		BaseIterator: firewall.NewBaseIterator(namerRules, options, natFilter),
		nats:         node.nats,
	}
}

func natFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	rule := item.(*NatRule)
	if options.FromZone != "" && !contains(rule.from, options.FromZone) {
		return false
	}
	if options.ToZone != "" && !contains(rule.to, options.ToZone) {
		return false
	}
	return true
}

func getNatRules(nats *Nats, natType firewall.NatType) []*NatRule {
	var rules []*NatRule
	switch natType {
	case firewall.DYNAMIC_NAT:
		// for _, ruleSet := range nats.sourceNatRules {
		//     rules = append(rules, ruleSet.rules...)
		// }
		return nats.sourceNatRules
	case firewall.DESTINATION_NAT:
		// for _, ruleSet := range nats.destinationNatRules {
		//     rules = append(rules, ruleSet.rules...)
		// }
		return nats.destinationNatRules
	case firewall.STATIC_NAT:
		// for _, ruleSet := range nats.staticNatRules {
		//     rules = append(rules, ruleSet.rules...)
		// }
		return nats.staticNatRules
	}
	return rules
}

// 辅助方法
func (node *UsgNode) SnatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.DYNAMIC_NAT))
	return node.NatIterator(opts...)
}

func (node *UsgNode) DnatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.DESTINATION_NAT))
	return node.NatIterator(opts...)
}

func (node *UsgNode) StaticNatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.STATIC_NAT))
	return node.NatIterator(opts...)
}

// 在 iterator.go 文件的末尾添加以下代码

// AclIterator 实现
type AclIterator struct {
	*firewall.BaseIterator
}

func (node *UsgNode) AclIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)

	// 由于 USG 可能不使用 ACL，我们返回一个空的迭代器
	return &AclIterator{
		BaseIterator: firewall.NewBaseIterator([]firewall.Namer{}, options, aclFilter),
	}
}

func aclFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	// 由于我们返回的是空列表，这个过滤器实际上不会被调用
	// 但为了完整性，我们还是实现它
	return true
}

// 辅助函数
// func toNamerSlice(items interface{}) []firewall.Namer {
// 	value := reflect.ValueOf(items)
// 	if value.Kind() != reflect.Slice {
// 		return nil
// 	}

// 	length := value.Len()
// 	namers := make([]firewall.Namer, length)

// 	for i := 0; i < length; i++ {
// 		item := value.Index(i).Interface()
// 		if namer, ok := item.(firewall.Namer); ok {
// 			namers[i] = namer
// 		} else {
// 			return nil
// 		}
// 	}

//		return namers
//	}
func toNamerSlice(policySet *PolicySet) []firewall.Namer {
	if policySet == nil {
		return nil
	}

	var namers []firewall.Namer

	// 遍历所有的 from zones
	for _, plc := range policySet.policySet {
		namers = append(namers, plc)
	}

	return namers
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

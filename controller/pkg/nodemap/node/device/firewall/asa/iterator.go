package asa

import (
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
)

// PolicyIterator 实现
type PolicyIterator struct {
	*firewall.BaseIterator
	policySet *PolicySet
	node      *ASANode
	aclToIfc  map[string][]string // ACL 名称到接口列表的映射
}

func (node *ASANode) PolicyIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	policies := make([]firewall.Namer, 0)

	// 构建 ACL 名称到接口的映射
	aclToIfc := make(map[string][]string)
	if node.matrix != nil && node.matrix.accessGroup != nil {
		// 遍历 accessGroup，找到每个接口对应的 ACL
		for ifcName, aclMap := range node.matrix.accessGroup {
			if aclName, ok := aclMap["in"]; ok {
				aclToIfc[aclName] = append(aclToIfc[aclName], ifcName)
			}
			if aclName, ok := aclMap["out"]; ok {
				aclToIfc[aclName] = append(aclToIfc[aclName], ifcName)
			}
		}
		// 处理全局 ACL
		if node.matrix.globalAcl != "" {
			aclToIfc[node.matrix.globalAcl] = append(aclToIfc[node.matrix.globalAcl], "global")
		}
	}

	// 遍历所有的 ACL 名称下的策略
	// 为了能够过滤，我们需要存储策略和 ACL 名称的关联
	policyAclMap := make(map[*Policy]string)
	for aclName, policyList := range node.policySet.policySet {
		for _, policy := range policyList {
			policies = append(policies, policy)
			policyAclMap[policy] = aclName
		}
	}

	// 创建 filter 函数，捕获需要的上下文
	filter := func(item firewall.Namer, opts *firewall.IteratorOptions) bool {
		return policyFilter(item, opts, node, aclToIfc, policyAclMap)
	}

	return &PolicyIterator{
		BaseIterator: firewall.NewBaseIterator(policies, options, filter),
		policySet:    node.policySet,
		node:         node,
		aclToIfc:     aclToIfc,
	}
}

func policyFilter(item firewall.Namer, options *firewall.IteratorOptions, node *ASANode, aclToIfc map[string][]string, policyAclMap map[*Policy]string) bool {
	policy := item.(*Policy)

	// 如果指定了 Zone（对于 ASA，Zone 可以表示接口名称 nameif）
	if options.Zone != "" {
		// 找到策略所属的 ACL 名称
		aclName, ok := policyAclMap[policy]
		if !ok {
			return false
		}

		// 检查该 ACL 是否绑定到指定的接口
		ifcs, ok := aclToIfc[aclName]
		if !ok {
			// 如果没有找到映射，可能是策略还没有绑定到接口，或者使用了全局 ACL
			// 如果指定的是 "global"，检查是否是全局 ACL
			if options.Zone == "global" && node.matrix != nil && node.matrix.globalAcl == aclName {
				return true
			}
			return false
		}

		// 检查接口是否在列表中
		for _, ifc := range ifcs {
			if ifc == options.Zone {
				return true
			}
		}
		return false
	}

	// 如果指定了 FromZone（对于 ASA，可能表示源接口）
	// 注意：ASA 策略本身没有 from/to 字段，但可以通过 ACL 绑定的接口来推断
	if options.FromZone != "" {
		aclName, ok := policyAclMap[policy]
		if !ok {
			return false
		}
		// 检查 ACL 是否绑定到指定的源接口
		ifcs, ok := aclToIfc[aclName]
		if !ok {
			return false
		}
		fromMatch := false
		for _, ifc := range ifcs {
			if ifc == options.FromZone {
				fromMatch = true
				break
			}
		}
		if !fromMatch {
			return false
		}
	}

	// 如果指定了 ToZone（对于 ASA，可能表示目标接口）
	// 注意：ASA 策略本身没有 from/to 字段，但可以通过 ACL 绑定的接口来推断
	if options.ToZone != "" {
		aclName, ok := policyAclMap[policy]
		if !ok {
			return false
		}
		// 检查 ACL 是否绑定到指定的目标接口
		ifcs, ok := aclToIfc[aclName]
		if !ok {
			return false
		}
		toMatch := false
		for _, ifc := range ifcs {
			if ifc == options.ToZone {
				toMatch = true
				break
			}
		}
		if !toMatch {
			return false
		}
	}

	// 如果指定了 IPFamily，检查策略的源/目标地址是否包含指定 IP 协议族
	if options.IPFamily != 0 && policy.policyEntry != nil {
		pe := policy.policyEntry
		hasIPv4 := false
		hasIPv6 := false

		// 检查源地址
		if pe.Src() != nil {
			if !pe.Src().IPv4().IsEmpty() {
				hasIPv4 = true
			}
			if !pe.Src().IPv6().IsEmpty() {
				hasIPv6 = true
			}
		}

		// 检查目标地址
		if pe.Dst() != nil {
			if !pe.Dst().IPv4().IsEmpty() {
				hasIPv4 = true
			}
			if !pe.Dst().IPv6().IsEmpty() {
				hasIPv6 = true
			}
		}

		// 根据 IPFamily 过滤
		if options.IPFamily == network.IPv4 && !hasIPv4 {
			return false
		}
		if options.IPFamily == network.IPv6 && !hasIPv6 {
			return false
		}
	}

	return true
}

// NetworkIterator 实现
type NetworkIterator struct {
	*firewall.BaseIterator
	objectSet *ASAObjectSet
}

func (node *ASANode) NetworkIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)

	allObjects := make([]firewall.Namer, 0)

	// 添加网络对象
	for _, obj := range node.objectSet.networkMap {
		if namer, ok := obj.(firewall.Namer); ok {
			allObjects = append(allObjects, namer)
		}
	}

	// 创建 filter 函数，捕获 node
	filter := func(item firewall.Namer, opts *firewall.IteratorOptions) bool {
		return networkFilter(item, opts)
	}

	return &NetworkIterator{
		BaseIterator: firewall.NewBaseIterator(allObjects, options, filter),
		objectSet:    node.objectSet,
	}
}

func networkFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	networkObj := item.(firewall.FirewallNetworkObject)

	// 如果指定了 IPFamily 或 NetworkGroup，需要获取 NetworkGroup
	var ng *network.NetworkGroup
	if options.IPFamily != 0 || options.NetworkGroup != nil {
		ng = networkObj.Network(nil)
		if ng == nil {
			return false
		}
	}

	// 如果指定了 IPFamily，检查网络对象是否包含指定 IP 协议族
	if options.IPFamily != 0 {
		// 检查网络对象是否包含指定 IP 协议族
		if options.IPFamily == network.IPv4 && ng.IPv4().IsEmpty() {
			return false
		}
		if options.IPFamily == network.IPv6 && ng.IPv6().IsEmpty() {
			return false
		}
	}

	// 如果指定了 NetworkGroup，检查网络对象是否与指定网络组匹配或重叠
	if options.NetworkGroup != nil {
		// 检查网络对象是否与指定网络组匹配或重叠
		if !ng.MatchNetworkGroup(options.NetworkGroup) && !options.NetworkGroup.MatchNetworkGroup(ng) {
			return false
		}
	}

	return true
}

// ServiceIterator 实现
type ServiceIterator struct {
	*firewall.BaseIterator
	objectSet *ASAObjectSet
	node      *ASANode
}

func (node *ASANode) ServiceIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	services := make([]firewall.Namer, 0, len(node.objectSet.serviceMap))
	for _, service := range node.objectSet.serviceMap {
		services = append(services, service)
	}

	// 创建 filter 函数，捕获 node
	filter := func(item firewall.Namer, opts *firewall.IteratorOptions) bool {
		return serviceFilter(item, opts, node)
	}

	return &ServiceIterator{
		BaseIterator: firewall.NewBaseIterator(services, options, filter),
		objectSet:    node.objectSet,
		node:         node,
	}
}

func serviceFilter(item firewall.Namer, options *firewall.IteratorOptions, node *ASANode) bool {
	service := item.(firewall.FirewallServiceObject)
	if options.Protocol != 0 {
		svc := service.Service(node)
		if svc == nil {
			return false
		}
		if int(svc.Protocol()) != options.Protocol {
			return false
		}
	}

	// 如果指定了 IPFamily，检查服务对象是否包含指定 IP 协议族
	// 注意：服务对象本身不直接包含 IP 协议族信息，但可以通过策略关联来推断
	// 这里暂时不实现，因为服务对象主要关注协议类型（TCP/UDP/ICMP等）
	// 如果需要，可以通过检查服务对象关联的策略来过滤

	return true
}

// NatPoolIterator 结构体定义
type NatPoolIterator struct {
	*firewall.BaseIterator
}

// ASANode 的 NatPoolIterator 方法实现
func (node *ASANode) NatPoolIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	pools := make([]firewall.Namer, 0)

	// ASA 使用 object 或 object group 作为 NAT pool
	// 在解析 object dynamic nat 或 twice dynamic nat 时，mapped object 会作为 NAT pool
	// 从 NAT 规则中提取 mapped object
	poolMap := make(map[string]firewall.NatPool) // 使用 map 去重

	// 从 ObjectNat 规则中提取 mappedSrcObject
	for _, rule := range node.nats.ObjectNat {
		if rule.natType == firewall.DYNAMIC_NAT && rule.mappedSrcObject != "" {
			// 获取 mapped object 的网络组
			ng, objCli, ok := node.objectSet.Network("", rule.mappedSrcObject)
			if ok {
				pool := &ASANatPoolWrapper{
					id:      rule.mappedSrcObject,
					name:    rule.mappedSrcObject,
					network: ng,
					cli:     objCli,
				}
				poolMap[rule.mappedSrcObject] = pool
			}
		}
	}

	// 从 TwiceNat 规则中提取 mappedSrcObject（对于 dynamic NAT）
	for _, rule := range node.nats.TwiceNat {
		if rule.natType == firewall.DYNAMIC_NAT && rule.mappedSrcObject != "" {
			// 获取 mapped object 的网络组
			ng, objCli, ok := node.objectSet.Network("", rule.mappedSrcObject)
			if ok {
				pool := &ASANatPoolWrapper{
					id:      rule.mappedSrcObject,
					name:    rule.mappedSrcObject,
					network: ng,
					cli:     objCli,
				}
				poolMap[rule.mappedSrcObject] = pool
			}
		}
	}

	// 将 map 转换为 slice
	for _, pool := range poolMap {
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

func (node *ASANode) NatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
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

	// 如果指定了 FromZone（对于 ASA，可能表示源接口）
	if options.FromZone != "" && rule.from != "" {
		if rule.from != options.FromZone && rule.from != "any" {
			return false
		}
	}

	// 如果指定了 ToZone（对于 ASA，可能表示目标接口）
	if options.ToZone != "" && rule.to != "" {
		if rule.to != options.ToZone && rule.to != "any" {
			return false
		}
	}

	// 如果指定了 IPFamily，检查 NAT 规则的源/目标地址是否包含指定 IP 协议族
	if options.IPFamily != 0 {
		hasIPv4 := false
		hasIPv6 := false

		// 检查原始地址
		if rule.orignal != nil {
			if rule.orignal.Src() != nil {
				if !rule.orignal.Src().IPv4().IsEmpty() {
					hasIPv4 = true
				}
				if !rule.orignal.Src().IPv6().IsEmpty() {
					hasIPv6 = true
				}
			}
			if rule.orignal.Dst() != nil {
				if !rule.orignal.Dst().IPv4().IsEmpty() {
					hasIPv4 = true
				}
				if !rule.orignal.Dst().IPv6().IsEmpty() {
					hasIPv6 = true
				}
			}
		}

		// 检查转换后地址
		if rule.translate != nil {
			if rule.translate.Src() != nil {
				if !rule.translate.Src().IPv4().IsEmpty() {
					hasIPv4 = true
				}
				if !rule.translate.Src().IPv6().IsEmpty() {
					hasIPv6 = true
				}
			}
			if rule.translate.Dst() != nil {
				if !rule.translate.Dst().IPv4().IsEmpty() {
					hasIPv4 = true
				}
				if !rule.translate.Dst().IPv6().IsEmpty() {
					hasIPv6 = true
				}
			}
		}

		// 根据 IPFamily 过滤
		if options.IPFamily == network.IPv4 && !hasIPv4 {
			return false
		}
		if options.IPFamily == network.IPv6 && !hasIPv6 {
			return false
		}
	}

	return true
}

func getNatRules(nats *Nats, natType firewall.NatType) []*NatRule {
	var rules []*NatRule
	switch natType {
	case firewall.DYNAMIC_NAT:
		return nats.ObjectNat
	case firewall.DESTINATION_NAT:
		// ASA 可能没有 DESTINATION_NAT，返回空
		return rules
	case firewall.STATIC_NAT:
		return nats.TwiceNat
	case firewall.TWICE_NAT:
		return nats.TwiceNat
	}
	return rules
}

// 辅助方法
func (node *ASANode) SnatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.DYNAMIC_NAT))
	return node.NatIterator(opts...)
}

func (node *ASANode) DnatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.DESTINATION_NAT))
	return node.NatIterator(opts...)
}

func (node *ASANode) StaticNatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.STATIC_NAT))
	return node.NatIterator(opts...)
}

// AclIterator 实现
type AclIterator struct {
	*firewall.BaseIterator
}

func (node *ASANode) AclIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)

	// ASA 的 ACL 就是 policySet 中的 ACL 名称
	acls := make([]firewall.Namer, 0)
	for aclName := range node.policySet.policySet {
		acls = append(acls, &ASAAcl{name: aclName})
	}

	return &AclIterator{
		BaseIterator: firewall.NewBaseIterator(acls, options, aclFilter),
	}
}

func aclFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	acl := item.(*ASAAcl)

	// 如果指定了 AclType，检查 ACL 类型
	if options.AclType != "" {
		// ASA 的 ACL 类型可以通过名称前缀或后缀来判断
		// 例如：标准 ACL 可能以 "standard_" 开头，扩展 ACL 可能以 "extended_" 开头
		// 或者通过其他命名约定来判断
		// 这里提供一个基本的实现，可以根据实际需求调整
		aclName := strings.ToLower(acl.name)
		aclType := strings.ToLower(options.AclType)

		// 检查 ACL 名称是否包含指定的类型前缀或后缀
		if !strings.Contains(aclName, aclType) {
			return false
		}
	}

	return true
}

// ASAAcl 是一个简单的 ACL 名称包装器
type ASAAcl struct {
	name string
}

func (a *ASAAcl) Name() string {
	return a.name
}

package forti

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
)

var _ firewall.IteratorFirewall = &FortigateNode{}

// PolicyIterator 实现
type PolicyIterator struct {
	*firewall.BaseIterator
	policySet *PolicySet
	node      *FortigateNode
}

func (node *FortigateNode) PolicyIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	policies := make([]firewall.Namer, 0)

	// 遍历所有的策略
	for _, policy := range node.policySet.policySet {
		policies = append(policies, policy)
	}

	// 创建 filter 函数
	filter := func(item firewall.Namer, opts *firewall.IteratorOptions) bool {
		return policyFilter(item, opts, node)
	}

	return &PolicyIterator{
		BaseIterator: firewall.NewBaseIterator(policies, options, filter),
		policySet:    node.policySet,
		node:         node,
	}
}

func policyFilter(item firewall.Namer, options *firewall.IteratorOptions, node *FortigateNode) bool {
	policy := item.(*Policy)

	// 如果指定了 FromZone，检查策略的源接口/区域
	if options.FromZone != "" {
		matched := false
		for _, zone := range policy.srcZone {
			if zone == options.FromZone {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// 如果指定了 ToZone，检查策略的目标接口/区域
	if options.ToZone != "" {
		matched := false
		for _, zone := range policy.dstZone {
			if zone == options.ToZone {
				matched = true
				break
			}
		}
		if !matched {
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
	objectSet *FortiObjectSet
}

func (node *FortigateNode) NetworkIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)

	allObjects := make([]firewall.Namer, 0)

	// 添加网络对象
	for _, obj := range node.objectSet.networkMap {
		if namer, ok := obj.(firewall.Namer); ok {
			allObjects = append(allObjects, namer)
		}
	}

	// 创建 filter 函数
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
		if options.IPFamily == network.IPv4 && ng.IPv4().IsEmpty() {
			return false
		}
		if options.IPFamily == network.IPv6 && ng.IPv6().IsEmpty() {
			return false
		}
	}

	// 如果指定了 NetworkGroup，检查网络对象是否与指定网络组匹配或重叠
	if options.NetworkGroup != nil {
		if !ng.MatchNetworkGroup(options.NetworkGroup) && !options.NetworkGroup.MatchNetworkGroup(ng) {
			return false
		}
	}

	return true
}

// ServiceIterator 实现
type ServiceIterator struct {
	*firewall.BaseIterator
	objectSet *FortiObjectSet
	node      *FortigateNode
}

func (node *FortigateNode) ServiceIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	services := make([]firewall.Namer, 0, len(node.objectSet.serviceMap))
	for _, service := range node.objectSet.serviceMap {
		services = append(services, service)
	}

	// 创建 filter 函数
	filter := func(item firewall.Namer, opts *firewall.IteratorOptions) bool {
		return serviceFilter(item, opts, node)
	}

	return &ServiceIterator{
		BaseIterator: firewall.NewBaseIterator(services, options, filter),
		objectSet:    node.objectSet,
		node:         node,
	}
}

func serviceFilter(item firewall.Namer, options *firewall.IteratorOptions, node *FortigateNode) bool {
	// FortiGate 的服务对象过滤逻辑
	// 可以根据需要添加更多过滤条件
	return true
}

// AclIterator 实现
// FortiGate 没有 ACL 概念，策略本身就是类似 ACL 的规则
// 这里返回一个空的迭代器或者返回策略名称作为 ACL 名称
type AclIterator struct {
	*firewall.BaseIterator
}

func (node *FortigateNode) AclIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)

	// FortiGate 没有独立的 ACL，策略名称可以作为 ACL 名称
	acls := make([]firewall.Namer, 0)
	for policyName := range node.policySet.policySet {
		acls = append(acls, &FortiAcl{name: policyName})
	}

	return &AclIterator{
		BaseIterator: firewall.NewBaseIterator(acls, options, aclFilter),
	}
}

func aclFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	// FortiGate 的 ACL 过滤逻辑
	// 可以根据需要添加更多过滤条件
	return true
}

// FortiAcl 是一个简单的 ACL 名称包装器
type FortiAcl struct {
	name string
}

func (a *FortiAcl) Name() string {
	return a.name
}

// SnatIterator 实现
func (node *FortigateNode) SnatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.DYNAMIC_NAT))
	return node.NatIterator(opts...)
}

// DnatIterator 实现
func (node *FortigateNode) DnatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.DESTINATION_NAT))
	return node.NatIterator(opts...)
}

// StaticNatIterator 实现
func (node *FortigateNode) StaticNatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.STATIC_NAT))
	return node.NatIterator(opts...)
}

// NatIterator 实现
func (node *FortigateNode) NatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	nats := make([]firewall.Namer, 0)

	// 添加 VIP 规则（静态 NAT）
	for _, vip := range node.nats.VipRules {
		nats = append(nats, vip)
	}

	// 添加动态 NAT 规则
	for _, dynamic := range node.nats.DynamicRules {
		nats = append(nats, dynamic)
	}

	// 创建 filter 函数
	filter := func(item firewall.Namer, opts *firewall.IteratorOptions) bool {
		// 根据 NAT 类型过滤
		if opts.NatType != 0 {
			natRule := item.(*NatRule)
			if natRule.natType != opts.NatType {
				return false
			}
		}
		return true
	}

	return firewall.NewBaseIterator(nats, options, filter)
}

// NatPoolIterator 实现
func (node *FortigateNode) NatPoolIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	pools := make([]firewall.Namer, 0)

	// FortiGate 的 NAT pool 是从动态 NAT 规则中提取的
	// 遍历动态 NAT 规则，提取 pool 信息
	// 每个 DynamicRule 的 translate.Src() 就是 pool 的网络组
	for _, dynamic := range node.nats.DynamicRules {
		if dynamic.translate != nil && dynamic.translate.Src() != nil {
			// 创建一个包装器来将 NatRule 作为 NatPool 使用
			pool := &FortiNatPoolWrapper{
				rule: dynamic,
			}
			pools = append(pools, pool)
		}
	}

	// 创建 filter 函数
	filter := func(item firewall.Namer, opts *firewall.IteratorOptions) bool {
		pool := item.(firewall.NatPool)
		// 如果指定了 NetworkGroup，检查 pool 是否匹配
		if opts.NetworkGroup != nil {
			return pool.MatchNetworkGroup(opts.NetworkGroup)
		}
		return true
	}

	return firewall.NewBaseIterator(pools, options, filter)
}

// FortiNatPoolWrapper 将 NatRule 包装为 NatPool
type FortiNatPoolWrapper struct {
	rule *NatRule
}

func (p *FortiNatPoolWrapper) Name() string {
	return p.rule.name
}

func (p *FortiNatPoolWrapper) ID() string {
	return p.rule.name
}

func (p *FortiNatPoolWrapper) Cli() string {
	return p.rule.cli
}

func (p *FortiNatPoolWrapper) MatchNetworkGroup(ng *network.NetworkGroup) bool {
	if p.rule.translate == nil || p.rule.translate.Src() == nil {
		return false
	}
	poolNg := p.rule.translate.Src()
	return poolNg.MatchNetworkGroup(ng) || ng.MatchNetworkGroup(poolNg)
}

func (p *FortiNatPoolWrapper) Network(_ firewall.FirewallNode) *network.NetworkGroup {
	if p.rule.translate == nil || p.rule.translate.Src() == nil {
		return nil
	}
	return p.rule.translate.Src()
}

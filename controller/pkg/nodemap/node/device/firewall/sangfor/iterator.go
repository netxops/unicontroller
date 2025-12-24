package sangfor

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/service"
)

var _ firewall.IteratorFirewall = &SangforNode{}

// PolicyIterator 实现
type PolicyIterator struct {
	*firewall.BaseIterator
	policySet *PolicySet
	node      *SangforNode
}

func (node *SangforNode) PolicyIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
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

func policyFilter(item firewall.Namer, options *firewall.IteratorOptions, node *SangforNode) bool {
	policy := item.(*Policy)

	// 如果指定了 FromZone，检查策略的源区域
	if options.FromZone != "" {
		matched := false
		for _, zone := range policy.srcZones {
			if zone == options.FromZone {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// 如果指定了 ToZone，检查策略的目标区域
	if options.ToZone != "" {
		matched := false
		for _, zone := range policy.dstZones {
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
	objectSet *SangforObjectSet
}

func (node *SangforNode) NetworkIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)

	allObjects := make([]firewall.Namer, 0)

	// 添加网络对象
	for _, obj := range node.objectSet.networkMap {
		allObjects = append(allObjects, obj)
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
	objectSet *SangforObjectSet
	node      *SangforNode
}

func (node *SangforNode) ServiceIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
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

func serviceFilter(item firewall.Namer, options *firewall.IteratorOptions, node *SangforNode) bool {
	serviceObj := item.(firewall.FirewallServiceObject)

	// 如果指定了 Protocol，检查服务对象是否包含指定协议
	if options.Protocol != 0 {
		svc := serviceObj.Service(node)
		if svc != nil {
			hasProtocol := false
			svc.EachDetailed(func(entry service.ServiceEntry) bool {
				// 检查服务条目是否包含指定协议
				// 这里简化处理，实际可能需要更详细的协议检查
				if l4, ok := entry.(*service.L4Service); ok {
					if int(l4.Protocol()) == options.Protocol {
						hasProtocol = true
						return false // 找到匹配的协议，停止遍历
					}
				}
				return true
			})
			if !hasProtocol {
				return false
			}
		}
	}

	return true
}

// AclIterator 实现
// Sangfor 没有独立的 ACL 概念，策略名称可以作为 ACL 名称
type AclIterator struct {
	*firewall.BaseIterator
}

func (node *SangforNode) AclIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)

	// Sangfor 没有独立的 ACL，策略名称可以作为 ACL 名称
	acls := make([]firewall.Namer, 0)
	for _, policy := range node.policySet.policySet {
		acls = append(acls, &SangforAcl{name: policy.Name()})
	}

	return &AclIterator{
		BaseIterator: firewall.NewBaseIterator(acls, options, aclFilter),
	}
}

func aclFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	// Sangfor 的 ACL 过滤逻辑
	// 可以根据需要添加更多过滤条件
	return true
}

// SangforAcl 是一个简单的 ACL 名称包装器
type SangforAcl struct {
	name string
}

func (a *SangforAcl) Name() string {
	return a.name
}

// SnatIterator 实现
func (node *SangforNode) SnatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.DYNAMIC_NAT))
	return node.NatIterator(opts...)
}

// DnatIterator 实现
func (node *SangforNode) DnatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.DESTINATION_NAT))
	return node.NatIterator(opts...)
}

// StaticNatIterator 实现
func (node *SangforNode) StaticNatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.STATIC_NAT))
	return node.NatIterator(opts...)
}

// NatIterator 实现
func (node *SangforNode) NatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	nats := make([]firewall.Namer, 0)

	// 添加 DNAT 规则（静态 NAT）
	for _, dnat := range node.nats.destinationNatRules {
		nats = append(nats, dnat)
	}

	// 添加 SNAT 规则（动态 NAT）
	for _, snat := range node.nats.sourceNatRules {
		nats = append(nats, snat)
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

		// 如果指定了 FromZone，检查 NAT 规则的源区域
		if opts.FromZone != "" {
			natRule := item.(*NatRule)
			if natRule.from != opts.FromZone {
				return false
			}
		}

		// 如果指定了 ToZone，检查 NAT 规则的目标区域（仅 SNAT）
		if opts.ToZone != "" {
			natRule := item.(*NatRule)
			if natRule.natType == firewall.DYNAMIC_NAT && natRule.to != opts.ToZone {
				return false
			}
		}

		return true
	}

	return firewall.NewBaseIterator(nats, options, filter)
}

// NatPoolIterator 实现
func (node *SangforNode) NatPoolIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	pools := make([]firewall.Namer, 0)

	// Sangfor 的 NAT pool 可以从两个来源获取：
	// 1. 从 SNAT 规则中提取（translate.Src()）
	// 2. 从 networkMap 中的 OBJECT_POOL 对象中提取

	// 首先从 SNAT 规则中提取 pool
	for _, snat := range node.nats.sourceNatRules {
		if snat.translate != nil && snat.translate.Src() != nil {
			// 创建一个包装器来将 NatRule 作为 NatPool 使用
			pool := &SangforNatPoolWrapper{
				rule: snat,
			}
			pools = append(pools, pool)
		}
	}

	// 然后从 networkMap 中的 OBJECT_POOL 对象中提取
	if node.objectSet != nil && node.objectSet.networkMap != nil {
		for _, obj := range node.objectSet.networkMap {
			if obj.objType == firewall.OBJECT_POOL {
				// 创建一个包装器来将 SangforNetworkObject 作为 NatPool 使用
				pool := &SangforNetworkObjectPoolWrapper{
					obj:  obj,
					node: node,
				}
				pools = append(pools, pool)
			}
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

// SangforNetworkObjectPoolWrapper 将 SangforNetworkObject (OBJECT_POOL) 包装为 NatPool
type SangforNetworkObjectPoolWrapper struct {
	obj  *SangforNetworkObject
	node *SangforNode
}

func (p *SangforNetworkObjectPoolWrapper) Name() string {
	return p.obj.name
}

func (p *SangforNetworkObjectPoolWrapper) ID() string {
	return p.obj.name
}

func (p *SangforNetworkObjectPoolWrapper) Cli() string {
	return p.obj.Cli()
}

func (p *SangforNetworkObjectPoolWrapper) MatchNetworkGroup(ng *network.NetworkGroup) bool {
	poolNg := p.obj.Network(p.node)
	if poolNg == nil {
		return false
	}
	return poolNg.MatchNetworkGroup(ng) || ng.MatchNetworkGroup(poolNg)
}

func (p *SangforNetworkObjectPoolWrapper) Network(_ firewall.FirewallNode) *network.NetworkGroup {
	return p.obj.Network(p.node)
}

// SangforNatPoolWrapper 将 NatRule 包装为 NatPool
type SangforNatPoolWrapper struct {
	rule *NatRule
}

func (p *SangforNatPoolWrapper) Name() string {
	return p.rule.name
}

func (p *SangforNatPoolWrapper) ID() string {
	return p.rule.name
}

func (p *SangforNatPoolWrapper) Cli() string {
	return p.rule.Cli()
}

func (p *SangforNatPoolWrapper) MatchNetworkGroup(ng *network.NetworkGroup) bool {
	if p.rule.translate == nil || p.rule.translate.Src() == nil {
		return false
	}
	poolNg := p.rule.translate.Src()
	return poolNg.MatchNetworkGroup(ng) || ng.MatchNetworkGroup(poolNg)
}

func (p *SangforNatPoolWrapper) Network(_ firewall.FirewallNode) *network.NetworkGroup {
	if p.rule.translate == nil || p.rule.translate.Src() == nil {
		return nil
	}
	return p.rule.translate.Src()
}

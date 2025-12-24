package secpath

import (
	"reflect"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
)

// PolicyIterator 现在嵌入 BaseIterator
type PolicyIterator struct {
	*firewall.BaseIterator
	policySet *PolicySet
}

func (node *SecPathNode) PolicyIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	policies := node.PolicySet.securityPolicyAcl

	return &PolicyIterator{
		BaseIterator: firewall.NewBaseIterator(toNamerSlice(policies), options, policyFilter),
		policySet:    node.PolicySet,
	}
}

func policyFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	// policy := item.(*Policy)
	// 实现过滤逻辑
	return true // 根据实际情况返回
}

// 辅助函数，将 []*Policy 转换为 []firewall.Namer
// 通用的 toNamerSlice 函数
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
			// 如果项目不是 Namer，返回 nil 或者处理错误
			return nil
		}
	}

	return namers
}

// 实现 NetworkIterator
type NetworkIterator struct {
	*firewall.BaseIterator
	objectSet *SecPathObjectSet
	zones     []ZoneName
	zoneIndex int
}

func (node *SecPathNode) NetworkIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	zones := getZones(node.ObjectSet, options.Zone)

	allObjects := make([]firewall.Namer, 0)
	for _, zone := range zones {
		for _, obj := range node.ObjectSet.ZoneNetworkMap[zone] {
			if namer, ok := obj.(firewall.Namer); ok {
				allObjects = append(allObjects, namer)
			}
		}
	}

	return &NetworkIterator{
		BaseIterator: firewall.NewBaseIterator(allObjects, options, networkFilter),
		objectSet:    node.ObjectSet,
		zones:        zones,
	}
}

func networkFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	// 实现网络对象的过滤逻辑
	return true
}

func getZones(objectSet *SecPathObjectSet, zoneOption string) []ZoneName {
	if zoneOption != "" {
		return []ZoneName{ZoneName(zoneOption)}
	}
	zones := make([]ZoneName, 0, len(objectSet.ZoneNetworkMap))
	for zone := range objectSet.ZoneNetworkMap {
		zones = append(zones, zone)
	}
	return zones
}

// 实现 ServiceIterator
type ServiceIterator struct {
	*firewall.BaseIterator
	objectSet *SecPathObjectSet
}

func (node *SecPathNode) ServiceIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	services := make([]firewall.Namer, 0, len(node.ObjectSet.ServiceMap))
	for _, service := range node.ObjectSet.ServiceMap {
		services = append(services, service)
	}

	return &ServiceIterator{
		BaseIterator: firewall.NewBaseIterator(services, options, serviceFilter),
		objectSet:    node.ObjectSet,
	}
}

func serviceFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	service := item.(firewall.FirewallServiceObject)
	if options.Protocol != 0 && int(service.Service(nil).Protocol()) != options.Protocol {
		return false
	}
	return true
}

// 实现 NatPoolIterator
type NatIterator struct {
	*firewall.BaseIterator
	nats *Nats
}

func (node *SecPathNode) NatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	rules := getNatRules(node.Nats, options.NatType)

	return &NatIterator{
		BaseIterator: firewall.NewBaseIterator(toNamerSlice(rules), options, natFilter),
		nats:         node.Nats,
	}
}

func natFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	rule := item.(*NatRule)
	if options.FromZone != "" && rule.from != options.FromZone {
		return false
	}
	if options.ToZone != "" && rule.to != options.ToZone {
		return false
	}
	return true
}

func getNatRules(nats *Nats, natType firewall.NatType) []*NatRule {
	// 实现获取NAT规则的逻辑，类似于原来的实现
	// ...
	return nil
}

// 辅助方法
func (node *SecPathNode) SnatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.DYNAMIC_NAT))
	return node.NatIterator(opts...)
}

func (node *SecPathNode) DnatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.DESTINATION_NAT))
	return node.NatIterator(opts...)
}

func (node *SecPathNode) StaticNatIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	opts = append(opts, firewall.WithNatType(firewall.STATIC_NAT))
	return node.NatIterator(opts...)
}

type AclIterator struct {
	*firewall.BaseIterator
}

func (node *SecPathNode) AclIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	acls := make([]firewall.Namer, len(node.AclSet.Sets))
	for i, acl := range node.AclSet.Sets {
		acls[i] = acl
	}

	return &AclIterator{
		BaseIterator: firewall.NewBaseIterator(acls, options, aclFilter),
	}
}

func aclFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	// acl := item.(*ACL)
	// 实现ACL过滤逻辑
	// if options.Zone != "" && acl.Zone != options.Zone {
	//     return false
	// }
	// if options.IPFamily != 0 && acl.IPFamily != options.IPFamily {
	//     return false
	// }
	// if options.AclType != "" && acl.Type != options.AclType {
	//     return false
	// }
	return true
}

type NatPoolIterator struct {
	*firewall.BaseIterator
}

func (node *SecPathNode) NatPoolIterator(opts ...firewall.IteratorOption) firewall.NamerIterator {
	options := firewall.ApplyOptions(opts...)
	pools := make([]firewall.Namer, 0, len(node.Nats.addrGroups))
	for _, pool := range node.Nats.addrGroups {
		pools = append(pools, pool)
	}

	return &NatPoolIterator{
		BaseIterator: firewall.NewBaseIterator(pools, options, natPoolFilter),
	}
}

func natPoolFilter(item firewall.Namer, options *firewall.IteratorOptions) bool {
	pool := item.(firewall.NatPool)
	if options.NetworkGroup != nil && !pool.MatchNetworkGroup(options.NetworkGroup) {
		return false
	}
	return true
}

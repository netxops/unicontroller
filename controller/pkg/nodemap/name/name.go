package name

import (
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
)

type Naming interface {
	Name(data interface{}) string
}

type NamingRuleType int

const (
	_ NamingRuleType = iota
	NEW
	// NEW_OBJECT_ONLY
	// NEW_GROUP_ONLY
	REUSE_OBJECT_ONLY
	REUSE_GROUP_ONLY
	REUSE_ONLY
	REUSE_OBJECT_OR_NEW
	REUSE_GROUP_OR_NEW
	REUSE_OR_NEW
	REUSE_POOL_OR_NEW
)

func (nt NamingRuleType) String() string {
	return []string{
		"NEW", "REUSE_OBJECT_ONLY", "REUSE_GROUP_ONLY", "REUSE_ONLY",
		"REUSE_OBJECT_OR_NEW", "REUSE_GROUP_OR_NEW", "REUSE_OR_NEW",
		"REUSE_POOL_OR_NEW",
	}[nt-1]
}

// func (nrt NamingRuleType) IsSimpleOnly() bool {
// if nrt == REUSE_OBJECT_OR_NEW || nrt == NEW_OBJECT_ONLY || nrt == REUSE_OBJECT_ONLY {
// return true
// }
//
// return false
// }
//
// func (nrt NamingRuleType) IsComplexOnly() bool {
// if nrt == REUSE_GROUP_OR_NEW || nrt == NEW_GROUP_ONLY || nrt == REUSE_GROUP_ONLY {
// return true
// }
//
// return false
// }
//
// func (nrt NamingRuleType) MeetFormatSelector(selector FormatSelector) bool {
// if selector == SIMPLE_NETWORK || selector == SIMPLE_SERVICE {
// if nrt.IsComplexOnly() {
// return false
// }
// }
//
// if selector == COMPLEX_NETWORK || selector == COMPLEX_SERVICE {
// if nrt.IsSimpleOnly() {
// return false
// }
// }
//
// return true
// }
type NamingInput interface {
	Intent() *policy.Intent
	Addition() string
}

type namingInput struct {
	intent   *policy.Intent
	rule     NamingRuleType
	addition string
	// formatter *Formatter
}

func (ni *namingInput) WithRule(rule NamingRuleType) {
	ni.rule = rule
}

func (ni *namingInput) WithAddition(addition string) {
	ni.addition = addition
}

func (ni *namingInput) Intent() *policy.Intent {
	return ni.intent
}

func (ni *namingInput) Addition() string {
	return ni.addition
}

func (ni *namingInput) Rule() NamingRuleType {
	return ni.rule
}

type NetworkNamingInput struct {
	namingInput
	Group *network.NetworkGroup
}
type ServiceNamingInput struct {
	namingInput
	Service *service.Service
}

type PoolNamingInput struct {
	namingInput
	Group   *network.NetworkGroup
	Service *service.Service
}

type VipNamingInput struct {
	namingInput
	Group    *network.NetworkGroup
	Service  *service.Service
	Port     string
	Protocol string
}

type PolicyNamingInput struct {
	namingInput
	Group *network.NetworkGroup
	From  string
	To    string
	Src   string
	Dst   string
}

func NewVipNamingInput(intent *policy.Intent, port string) *VipNamingInput {
	return &VipNamingInput{
		namingInput: namingInput{
			intent: intent,
		},
		Group:    intent.Dst(),
		Service:  intent.Service(),
		Port:     port,
		Protocol: intent.Service().Protocol().String(),
	}
}

func (nni *VipNamingInput) IsSimple() bool {
	if nni.Group.AddressType() == network.HOST || nni.Group.AddressType() == network.SUBNET || nni.Group.AddressType() == network.RANGE {
		return true
	} else {
		return false
	}
}

func (nni *VipNamingInput) Selector() FormatSelector {
	if nni.IsSimple() {
		return SIMPLE_VIP
	} else {
		return COMPLEX_VIP
	}

}

func NewPolicyNamingInput(intent *policy.Intent, from, to string) *PolicyNamingInput {
	return &PolicyNamingInput{
		namingInput: namingInput{
			intent: intent,
		},
		Group: intent.Dst(),
		From:  from,
		To:    to,
		Src:   intent.Src().String(),
		Dst:   intent.Dst().String(),
	}
}

func (nni *PolicyNamingInput) IsSimple() bool {
	if nni.intent != nil && (nni.From != "" || nni.To != "") {
		return true
	} else {
		return false
	}
}

func (nni *PolicyNamingInput) Selector() FormatSelector {
	if nni.IsSimple() {
		return SIMPLE_POLICY
	} else {
		return COMPLEX_POLICY
	}
}

func NewPoolNamingInput(intent *policy.Intent, group *network.NetworkGroup, serviceGroup *service.Service) *PoolNamingInput {
	return &PoolNamingInput{
		namingInput: namingInput{
			intent: intent,
		},
		Group:   group,
		Service: serviceGroup,
	}
}

func (nni *PoolNamingInput) IsSimple() bool {
	if nni.Group.AddressType() == network.HOST || nni.Group.AddressType() == network.SUBNET || nni.Group.AddressType() == network.RANGE {
		return true
	} else {
		return false
	}
}

func (nni *PoolNamingInput) Selector() FormatSelector {
	if nni.IsSimple() {
		return SIMPLE_POOL
	} else {
		return COMPLEX_POOL
	}

}

func NewNetworkNamingInput(intent *policy.Intent, group *network.NetworkGroup) *NetworkNamingInput {
	return &NetworkNamingInput{
		namingInput: namingInput{
			intent: intent,
		},
		Group: group,
	}
}

func (nni *NetworkNamingInput) IsSimple() bool {
	if nni.Group.AddressType() == network.HOST || nni.Group.AddressType() == network.SUBNET || nni.Group.AddressType() == network.RANGE {
		return true
	} else {
		return false
	}
}

func (nni *NetworkNamingInput) Selector() FormatSelector {
	if nni.IsSimple() {
		return SIMPLE_NETWORK
	} else {
		return COMPLEX_NETWORK
	}
}

func NewServiceNamingInput(intent *policy.Intent, s *service.Service) *ServiceNamingInput {
	return &ServiceNamingInput{
		namingInput: namingInput{
			intent: intent,
		},
		Service: s,
	}
}

func (sni *ServiceNamingInput) Selector() FormatSelector {
	if sni.IsSimple() {
		return SIMPLE_SERVICE
	} else {
		return COMPLEX_SERVICE
	}
}

func (sni *ServiceNamingInput) IsSimple() bool {
	one := sni.Service.MustOneServiceEntry()
	switch one.(type) {
	case *service.L3Protocol:
		return true
	case *service.ICMPProto:
		return true
	case *service.L4Service:
		l4, _ := service.NewL4Port(service.RANGE, 0, 65535, 0)
		if !(one.(*service.L4Service).SrcPort().Same(l4) || one.(*service.L4Service).DstPort().Same(l4)) {
			return false
		}
		if one.(*service.L4Service).SrcPort().Same(l4) {
			if len(one.(*service.L4Service).DstPort().DataRange.L) > 1 {
				return false
			}
		} else {
			if len(one.(*service.L4Service).SrcPort().DataRange.L) > 1 {
				return false
			}
		}
		return true

	}
	return false
}

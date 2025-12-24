package secpath

import (
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/service"
)

type FilterType int

const (
	FilterTypeInputContainPolicy FilterType = iota
	FilterTypeInputSameWithPolicy
	FilterTypePolicyContainInput
	FilterTypePolicySameWithInput
)

type PolicyQuery struct {
	policySet  *PolicySet
	fromZone   string
	toZone     string
	srcAddr    *network.NetworkGroup
	dstAddr    *network.NetworkGroup
	svc        *service.Service
	filterType FilterType
	exclude    bool
}

func NewPolicyQuery(policySet *PolicySet) *PolicyQuery {
	return &PolicyQuery{
		policySet:  policySet,
		filterType: FilterTypePolicyContainInput,
	}
}

func (pq *PolicyQuery) FromZone(zone string) *PolicyQuery {
	pq.fromZone = zone
	return pq
}

func (pq *PolicyQuery) ToZone(zone string) *PolicyQuery {
	pq.toZone = zone
	return pq
}

func (pq *PolicyQuery) SrcAddress(addr *network.NetworkGroup) *PolicyQuery {
	pq.srcAddr = addr
	return pq
}

func (pq *PolicyQuery) DstAddress(addr *network.NetworkGroup) *PolicyQuery {
	pq.dstAddr = addr
	return pq
}

func (pq *PolicyQuery) Service(svc *service.Service) *PolicyQuery {
	pq.svc = svc
	return pq
}

func (pq *PolicyQuery) UseInputContainPolicy() *PolicyQuery {
	pq.filterType = FilterTypeInputContainPolicy
	return pq
}

func (pq *PolicyQuery) UseInputSameWithPolicy() *PolicyQuery {
	pq.filterType = FilterTypeInputSameWithPolicy
	return pq
}

func (pq *PolicyQuery) UsePolicyContainInput() *PolicyQuery {
	pq.filterType = FilterTypePolicyContainInput
	return pq
}

func (pq *PolicyQuery) UsePolicySameWithInput() *PolicyQuery {
	pq.filterType = FilterTypePolicySameWithInput
	return pq
}

func (pq *PolicyQuery) Exclude() *PolicyQuery {
	pq.exclude = true
	return pq
}

func (pq *PolicyQuery) filter(policy *Policy) bool {
	if !pq.matchZone(pq.fromZone, policy.srcZone) {
		return pq.exclude
	}
	if !pq.matchZone(pq.toZone, policy.dstZone) {
		return pq.exclude
	}

	match := true

	if pq.srcAddr != nil {
		match = match && pq.compareNetworks(pq.srcAddr, policy.policyEntry.Src())
	}

	if pq.dstAddr != nil {
		match = match && pq.compareNetworks(pq.dstAddr, policy.policyEntry.Dst())
	}

	if pq.svc != nil {
		match = match && pq.compareServices(pq.svc, policy.policyEntry.Service())
	}

	return match != pq.exclude
}

func (pq *PolicyQuery) matchZone(queryZone string, policyZones []string) bool {
	if queryZone == "" {
		return true
	}
	for _, zone := range policyZones {
		if zone == "any" || zone == queryZone {
			return true
		}
	}
	return false
}

func (pq *PolicyQuery) compareNetworks(input, policy *network.NetworkGroup) bool {
	switch pq.filterType {
	case FilterTypeInputContainPolicy:
		return input.MatchNetworkGroup(policy)
	case FilterTypeInputSameWithPolicy:
		return input.Same(policy)
	case FilterTypePolicyContainInput:
		return policy.MatchNetworkGroup(input)
	case FilterTypePolicySameWithInput:
		return policy.Same(input)
	}
	return false
}

func (pq *PolicyQuery) compareServices(input, policy *service.Service) bool {
	switch pq.filterType {
	case FilterTypeInputContainPolicy:
		return input.Match(policy)
	case FilterTypeInputSameWithPolicy:
		return input.Same(policy)
	case FilterTypePolicyContainInput:
		return policy.Match(input)
	case FilterTypePolicySameWithInput:
		return policy.Same(input)
	}
	return false
}

func (pq *PolicyQuery) First() *Policy {
	for _, policy := range pq.policySet.securityPolicyAcl {
		if pq.filter(policy) {
			return policy
		}
	}
	return nil
}

func (pq *PolicyQuery) Last() *Policy {
	var lastMatchedPolicy *Policy
	for _, policy := range pq.policySet.securityPolicyAcl {
		if pq.filter(policy) {
			lastMatchedPolicy = policy
		}
	}
	return lastMatchedPolicy
}

func (pq *PolicyQuery) All() []*Policy {
	var matchedPolicies []*Policy
	for _, policy := range pq.policySet.securityPolicyAcl {
		if pq.filter(policy) {
			matchedPolicies = append(matchedPolicies, policy)
		}
	}
	return matchedPolicies
}

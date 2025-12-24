package asa

import (
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/text"
)

type SameLevelTraffic int

const (
	NO_SAME_LEVEL_TRAFFIC SameLevelTraffic = iota
	SAME_INTERFACE
	DIFFERENT_INTERFACE
)

type Matrix struct {
	// objects     *ASAObjectSet
	policySet   *PolicySet
	node        *ASANode
	globalAcl   string
	sameLevel   SameLevelTraffic
	natControl  bool
	accessGroup map[string]map[string]string
}

func (matrix *Matrix) WithNatControl() {
	matrix.natControl = true
}

func (matrix *Matrix) parseAccessGroup(config string) {
	accessgroupRegexMap := map[string]string{
		"regex": `access-group (?P<acl_name>\S+) (?P<direction>in|out) interface (?P<nameif>\S+)`,
		"name":  "accessgroup",
		"flags": "m",
	}

	accessgroupResult, err := text.SplitterProcessOneTime(accessgroupRegexMap, config)
	if err != nil {
		panic(err)
	}

	for it := accessgroupResult.Iterator(); it.HasNext(); {
		_, _, agMap := it.Next()
		port := matrix.node.GetPortByNameOrAlias(agMap["nameif"])
		matrix.accessGroup[port.Name()] = map[string]string{}

		if agMap["direction"] == "in" {
			matrix.accessGroup[port.Name()]["in"] = agMap["acl_name"]
			port.(*ASAPort).WithInAcl(agMap["acl_name"])
		} else {
			matrix.accessGroup[port.Name()]["out"] = agMap["acl_name"]
			port.(*ASAPort).WithOutAcl(agMap["acl_name"])
		}
	}

	globalRegexMap := map[string]string{
		"regex": `access-group (?P<acl_name>\S+) global`,
		"name":  "global",
		"flags": "m",
	}

	globalResult, err := text.SplitterProcessOneTime(globalRegexMap, config)
	if err != nil {
		if err == text.ErrNoMatched {
			return
		} else {
			panic(err)
		}
	}

	globalMap, ok := globalResult.One()
	if ok {
		matrix.globalAcl = globalMap["acl_name"]
	}
}

func (matrix *Matrix) parseLevel(config string) {
	if strings.Index(config, "same-security-traffic permit inter-interface") > -1 {
		matrix.sameLevel = SAME_INTERFACE
	} else if strings.Index(config, "same-security-traffic permit intra-interface") > -1 {
		matrix.sameLevel = DIFFERENT_INTERFACE
	} else {
		matrix.sameLevel = NO_SAME_LEVEL_TRAFFIC
	}
}

func (matrix *Matrix) parseConfig(config string) {
	matrix.parseAccessGroup(config)
	matrix.parseLevel(config)
	// matrix.parseNatControl(config)
}

func (matrix *Matrix) InPacket(from, to api.Port, entry policy.PolicyEntryInf) (firewall.Action, firewall.FirewallPolicy) {
	// fromPort := matrix.node.GetPort(from)
	fromLevel := from.(*ASAPort).Level()
	inAcl := from.(*ASAPort).InAcl()

	// toPort := matrix.node.GetPort(to)
	toLevel := to.(*ASAPort).Level()

	if fromLevel == toLevel {
		if matrix.sameLevel != SAME_INTERFACE && matrix.sameLevel != DIFFERENT_INTERFACE {
			return firewall.POLICY_IMPLICIT_DENY, nil
		}
	}

	if inAcl == "" {
		if matrix.globalAcl != "" {
			ok, policy := matrix.policySet.Match(matrix.globalAcl, entry)
			if ok {
				return policy.(*Policy).action, policy
			}
		}

		if fromLevel > toLevel {
			if !matrix.natControl {
				return firewall.POLICY_IMPLICIT_PERMIT, nil
			}
		} else if fromLevel == toLevel {
			// 因为已经进行过一轮same level的流量判断，进入到这里，inter_interface和intra_interface必占其一
			if matrix.sameLevel == SAME_INTERFACE {
				if from.HitByName(to.Name()) {
					return firewall.POLICY_IMPLICIT_PERMIT, nil
				}
			} else if matrix.sameLevel == DIFFERENT_INTERFACE {
				if !from.HitByName(to.Name()) {
					return firewall.POLICY_IMPLICIT_PERMIT, nil
				}
			} else {
				panic("unknown error!")
			}
		} else {
			return firewall.POLICY_IMPLICIT_DENY, nil
		}
	} else {
		ok, policy := matrix.policySet.Match(inAcl, entry)
		if ok {
			return policy.(*Policy).action, policy
		}

		if matrix.globalAcl != "" {
			ok, policy := matrix.policySet.Match(matrix.globalAcl, entry)

			if ok {
				return policy.(*Policy).action, policy
			}
		}
	}

	return firewall.POLICY_IMPLICIT_DENY, nil
}

func (matrix *Matrix) OutPacket(from, to api.Port, entry policy.PolicyEntryInf) (firewall.Action, firewall.FirewallPolicy) {
	// toPort := matrix.node.GetPort(to)
	outAcl := to.(*ASAPort).OutAcl()

	if outAcl != "" {
		ok, policy := matrix.policySet.Match(outAcl, entry)
		if ok {
			return policy.(*Policy).action, policy
		}
		return firewall.POLICY_IMPLICIT_DENY, nil
	}

	return firewall.POLICY_IMPLICIT_PERMIT, nil
}

package srx

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/registry"
	"github.com/netxops/utils/service"
	"github.com/netxops/utils/text"
)

type SrxNatMatchState int

const (
	// NONE表示未进行实质匹配，比如NatRule的内容为空
	SRX_NAT_MATCH_NONE SrxNatMatchState = iota
	SRX_NAT_MATCH_OK
	// NOT_OK表示未命中策略
	SRX_NAT_MATCH_NOT_OK
)

type SrxNatStatus int

const (
	SRX_NAT_INACTIVE SrxNatStatus = iota
	SRX_NAT_ACTIVE
)

type NatRuleSet struct {
	from, to *SRXPort
	natType  firewall.NatType
	name     string
	rules    []*NatRule
}

func (ns *NatRuleSet) Name() string {
	return ns.name
}

func (ns *NatRuleSet) NatRule(name string) (*NatRule, bool) {
	for _, rule := range ns.rules {
		if rule.Name() == name {
			return rule, true
		}
	}

	return nil, false
}

func (ns *NatRuleSet) matchDnatTarget(from, to string, entry policy.PolicyEntryInf) (*NatRule, bool) {
	if !(ns.natType == firewall.STATIC_NAT || ns.natType == firewall.DESTINATION_NAT) {
		return nil, false
	}

	for _, rule := range ns.rules {
		if rule.matchDnatTarget(entry) {
			return rule, true
		}
	}
	return nil, false
}

func (ns *NatRuleSet) reverseMatch(from, to string, entry *policy.Intent) (*NatRule, bool) {
	if ns.natType != firewall.STATIC_NAT {
		return nil, false
	}

	for _, rule := range ns.rules {
		if rule.reverseMatch(from, to, entry) == SRX_NAT_MATCH_OK {
			return rule, true
		}
	}
	return nil, false
}

func (ns *NatRuleSet) match(from, to string, entry *policy.Intent) (*NatRule, bool) {
	if ns.natType == firewall.STATIC_NAT || ns.natType == firewall.DESTINATION_NAT {
		if from != ns.from.Zone() {
			return nil, false
		}
	} else {
		if from != ns.from.Zone() || to != ns.to.Zone() {
			return nil, false
		}
	}

	for _, rule := range ns.rules {
		if rule.match(from, to, entry) == SRX_NAT_MATCH_OK {
			return rule, true
		}
	}

	return nil, false
}

type NatRule struct {
	objects     *SRXObjectSet
	name        string
	ruleSetName string
	node        *SRXNode
	from        *SRXPort
	to          *SRXPort
	natType     firewall.NatType
	// afterAuto bool
	cli       string
	status    SrxNatStatus
	orignal   policy.PolicyEntryInf
	translate policy.PolicyEntryInf
}

// TypeName 实现 TypeInterface 接口
func (nr *NatRule) TypeName() string {
	return "SRXNatRule"
}

// natRuleJSON 用于序列化和反序列化
type natRuleJSON struct {
	Name        string                `json:"name"`
	RuleSetName string                `json:"rule_set_name"`
	From        *SRXPort              `json:"from"`
	To          *SRXPort              `json:"to"`
	NatType     firewall.NatType      `json:"nat_type"`
	CLI         string                `json:"cli"`
	Status      SrxNatStatus          `json:"status"`
	Original    policy.PolicyEntryInf `json:"original"`
	Translate   policy.PolicyEntryInf `json:"translate"`
}

// MarshalJSON 实现 JSON 序列化
func (nr *NatRule) MarshalJSON() ([]byte, error) {
	return json.Marshal(natRuleJSON{
		Name:        nr.name,
		RuleSetName: nr.ruleSetName,
		From:        nr.from,
		To:          nr.to,
		NatType:     nr.natType,
		CLI:         nr.cli,
		Status:      nr.status,
		Original:    nr.orignal,
		Translate:   nr.translate,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (nr *NatRule) UnmarshalJSON(data []byte) error {
	var nrj natRuleJSON
	if err := json.Unmarshal(data, &nrj); err != nil {
		return err
	}

	nr.name = nrj.Name
	nr.ruleSetName = nrj.RuleSetName
	nr.from = nrj.From
	nr.to = nrj.To
	nr.natType = nrj.NatType
	nr.cli = nrj.CLI
	nr.status = nrj.Status
	nr.orignal = nrj.Original
	nr.translate = nrj.Translate

	return nil
}

func (rule *NatRule) Name() string {
	return rule.name
}

func (rule *NatRule) Cli() string {
	return rule.cli
}

func (rule *NatRule) Original() policy.PolicyEntryInf {
	return rule.orignal
}

func (rule *NatRule) Translate() policy.PolicyEntryInf {
	return rule.translate
}

func (rule *NatRule) Extended() map[string]interface{} {
	return map[string]interface{}{
		"nat_type": rule.natType,
		// "after_auto": rule.afterAuto,
	}
}

type Nats struct {
	objects    *SRXObjectSet
	node       *SRXNode
	ruleSetMap map[firewall.NatType]map[string]*NatRuleSet
	// 都是以ruleSet的名称为key
	staticNatRules      map[string]*NatRuleSet
	sourceNatRules      map[string]*NatRuleSet
	destinationNatRules map[string]*NatRuleSet
}

// TypeName 实现 TypeInterface 接口
func (n *Nats) TypeName() string {
	return "SRXNats"
}

// natsJSON 用于序列化和反序列化
type natsJSON struct {
	RuleSetMap          map[firewall.NatType]map[string]*NatRuleSet `json:"rule_set_map"`
	StaticNatRules      map[string]*NatRuleSet                      `json:"static_nat_rules"`
	SourceNatRules      map[string]*NatRuleSet                      `json:"source_nat_rules"`
	DestinationNatRules map[string]*NatRuleSet                      `json:"destination_nat_rules"`
}

// MarshalJSON 实现 JSON 序列化
func (n *Nats) MarshalJSON() ([]byte, error) {
	return json.Marshal(natsJSON{
		RuleSetMap:          n.ruleSetMap,
		StaticNatRules:      n.staticNatRules,
		SourceNatRules:      n.sourceNatRules,
		DestinationNatRules: n.destinationNatRules,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (n *Nats) UnmarshalJSON(data []byte) error {
	var nj natsJSON
	if err := json.Unmarshal(data, &nj); err != nil {
		return err
	}

	n.ruleSetMap = nj.RuleSetMap
	n.staticNatRules = nj.StaticNatRules
	n.sourceNatRules = nj.SourceNatRules
	n.destinationNatRules = nj.DestinationNatRules

	return nil
}

func (nat *Nats) hasRuleName(name string) bool {
	for _, ruleSetMap := range []map[string]*NatRuleSet{nat.staticNatRules, nat.sourceNatRules, nat.destinationNatRules} {
		for _, ruleSet := range ruleSetMap {
			for _, rule := range ruleSet.rules {
				if rule.Name() == name {
					return true
				}
			}
		}
	}

	return false
}

func (nat *Nats) GetNatRuleSet(natType firewall.NatType, name string) (*NatRuleSet, bool) {
	var ruleSetMap map[string]*NatRuleSet

	switch natType {
	case firewall.STATIC_NAT:
		ruleSetMap = nat.staticNatRules
	case firewall.DESTINATION_NAT:
		ruleSetMap = nat.destinationNatRules
	case firewall.DYNAMIC_NAT:
		ruleSetMap = nat.sourceNatRules
	default:
		return nil, false
	}

	if ruleSet, ok := ruleSetMap[name]; !ok {
		return nil, false
	} else {
		return ruleSet, true
	}
}

func (nat *Nats) NatRule(natType firewall.NatType, ruleSetName, name string) (*NatRule, bool) {
	ruleSet, ok := nat.GetNatRuleSet(natType, ruleSetName)
	if !ok {
		return nil, false
	}

	return ruleSet.NatRule(name)
}

func (nat *Nats) flyConfig(config string) {
	infoRegexMap := map[string]string{
		"regex": `set security nat (?P<natType>\S+) rule-set (?P<ruleSet>\S+)`,
		"name":  "info",
		"flags": "m",
		"pcre":  "true",
	}

	ruleSetSection := nat.parseRuleSet(config)
	for _, ruleSetCli := range ruleSetSection {
		sections := nat.parseSection(ruleSetCli)
		for _, section := range sections {
			rule := &NatRule{
				objects: nat.objects,
				node:    nat.node,
			}

			infoResult, err := text.SplitterProcessOneTime(infoRegexMap, section)
			if err != nil {
				// 如果解析出错（例如没有匹配），跳过这个section
				continue
			}

			// 如果没有匹配，跳过这个section
			if infoResult == nil || infoResult.Len() == 0 {
				continue
			}

			info, ok := infoResult.One()
			if !ok {
				panic("get nat info error")
			}

			var natType firewall.NatType
			var ruleSet *NatRuleSet
			var ruleSetMap map[string]*NatRuleSet
			if info["natType"] == "static" {
				natType = firewall.STATIC_NAT
				ruleSetMap = nat.staticNatRules
			} else if info["natType"] == "source" {
				natType = firewall.DYNAMIC_NAT
				ruleSetMap = nat.sourceNatRules
			} else {
				natType = firewall.DESTINATION_NAT
				ruleSetMap = nat.destinationNatRules
			}

			ruleSet = ruleSetMap[info["ruleSet"]]
			if ruleSet == nil {
				// 如果ruleSet不存在，尝试从section中解析from/to zone信息来创建它
				// 首先尝试从完整的ruleSetCli中解析
				natTypeFromCli, from, to, ruleSetName := nat.parseNatInfo(ruleSetCli)
				if natTypeFromCli == natType && ruleSetName == info["ruleSet"] {
					ruleSetMap[ruleSetName] = &NatRuleSet{
						natType: natType,
						from:    from,
						to:      to,
						name:    ruleSetName,
					}
					ruleSet = ruleSetMap[ruleSetName]
				} else {
					// 如果无法解析，跳过这个section
					continue
				}
			}

			rule.parseNat(section, natType, ruleSet.from, ruleSet.to)
			ruleSet.rules = append(ruleSet.rules, rule)

		}
	}
}

func (nat *Nats) parseConfig(config string) {
	ruleSetSection := nat.parseRuleSet(config)
	for _, ruleSetCli := range ruleSetSection {
		natType, from, to, ruleSetName := nat.parseNatInfo(ruleSetCli)

		var ruleSetMap map[string]*NatRuleSet

		switch natType {
		case firewall.STATIC_NAT:
			ruleSetMap = nat.staticNatRules
		case firewall.DESTINATION_NAT:
			ruleSetMap = nat.destinationNatRules
		case firewall.DYNAMIC_NAT:
			ruleSetMap = nat.sourceNatRules
		}
		if _, ok := ruleSetMap[ruleSetName]; !ok {
			ruleSetMap[ruleSetName] = &NatRuleSet{
				natType: natType,
				from:    from,
				to:      to,
				name:    ruleSetName,
			}
		}

		ruleSet := ruleSetMap[ruleSetName]

		sections := nat.parseSection(ruleSetCli)
		for _, section := range sections {
			rule := &NatRule{
				objects: nat.objects,
				node:    nat.node,
			}
			rule.parseNat(section, natType, from, to)
			ruleSet.rules = append(ruleSet.rules, rule)
		}
	}
	nat.parseDeactive(config)
}

func (nat *Nats) parseDeactive(config string) {
	deactiveRegexMap := map[string]string{
		"regex": `(?P<all>deactivate security nat (?P<natType>\S+) rule-set (?P<name>\S+) rule (?P<rule>\S+))`,
		"name":  "deactive",
		"flags": "m",
		"pcre":  "true",
	}

	deactiveResult, err := text.SplitterProcessOneTime(deactiveRegexMap, config)
	if err != nil {
		panic(err)
	}

	for it := deactiveResult.Iterator(); it.HasNext(); {
		_, _, deactiveMap := it.Next()
		natType := StringToNatType(deactiveMap["natType"])
		rule, ok := nat.NatRule(natType, deactiveMap["name"], deactiveMap["rule"])
		if !ok {
			panic(fmt.Sprint("get nat ruel faild, deactiveMap: ", deactiveMap))
		}
		rule.status = SRX_NAT_INACTIVE
		rule.cli += "\n" + deactiveMap["all"]
	}
}

func (nat *Nats) parseRuleSet(config string) []string {
	sectionRegexMap := map[string]string{
		"regex": `(?P<all>set security nat (?P<type>\S+) rule-set (?P<ruleSet>\S+) [^\n]+)`,
		"name":  "section",
		"flags": "m",
		"pcre":  "true",
	}

	sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, config)
	if err != nil {
		// 如果解析出错（例如没有匹配），返回空切片
		return []string{}
	}

	// 如果没有匹配，返回空切片
	if sectionResult == nil || sectionResult.Len() == 0 {
		return []string{}
	}

	sections, err := sectionResult.CombinKey([]string{"type", "ruleSet"})
	if err != nil {
		// 如果组合键出错，返回空切片
		return []string{}
	}

	return sections
}

func (nat *Nats) parseNatInfo(config string) (natType firewall.NatType, from, to *SRXPort, name string) {
	infoRegexMap := map[string]string{
		"regex": `set security nat (?P<natType>\S+) rule-set (?P<ruleSet>\S+) (from zone (?P<from>\S+))|(to zone (?P<to>\S+))`,
		"name":  "info",
		"flags": "m",
		"pcre":  "true",
	}

	infoResult, err := text.SplitterProcessOneTime(infoRegexMap, config)
	if err != nil {
		panic(err)
	}

	infoMap, err := infoResult.Projection([]string{}, ",", nil)
	if err != nil {
		panic(err)
	}

	if infoMap["natType"] == "static" {
		natType = firewall.STATIC_NAT
	} else if infoMap["natType"] == "source" {
		natType = firewall.DYNAMIC_NAT
	} else {
		natType = firewall.DESTINATION_NAT
	}

	// 尝试获取端口，如果不存在则使用zone名称创建临时端口
	if infoMap["from"] != "" {
		var port api.Port
		// 使用defer recover来避免PortList panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					// 如果PortList panic，直接创建临时端口
					port = nil
				}
			}()
			port = nat.node.GetPortByNameOrAlias(infoMap["from"])
		}()
		if port != nil {
			from = port.(*SRXPort)
		} else {
			// 如果端口不存在，使用zone名称创建临时端口
			from = NewSRXPort(infoMap["from"], "", nil, nil).WithZone(infoMap["from"])
		}
	}
	if infoMap["to"] != "" {
		var port api.Port
		// 使用defer recover来避免PortList panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					// 如果PortList panic，直接创建临时端口
					port = nil
				}
			}()
			port = nat.node.GetPortByNameOrAlias(infoMap["to"])
		}()
		if port != nil {
			to = port.(*SRXPort)
		} else {
			// 如果端口不存在，使用zone名称创建临时端口
			to = NewSRXPort(infoMap["to"], "", nil, nil).WithZone(infoMap["to"])
		}
	}

	name = infoMap["ruleSet"]

	return
}

func (nat *Nats) parseSection(config string) []string {

	sectionRegexMap := map[string]string{
		"regex": `(?P<all>set security nat (?P<type>\S+) rule-set (?P<ruleSet>\S+) rule (?P<name>\S+) [^\n]+)`,
		"name":  "section",
		"flags": "m",
		"pcre":  "true",
	}

	sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, config)
	if err != nil {
		// 如果解析出错（例如没有匹配），返回空切片
		return []string{}
	}

	// 如果没有匹配，返回空切片
	if sectionResult == nil || sectionResult.Len() == 0 {
		return []string{}
	}

	sections, err := sectionResult.CombinKey([]string{"type", "ruleSet", "name"})
	if err != nil {
		// 如果组合键出错，返回空切片
		return []string{}
	}
	return sections
}

func (rule *NatRule) parseNat(config string, natType firewall.NatType, from, to *SRXPort) {
	rule.natType = natType
	rule.cli = config

	natRegexMap := map[string]string{
		"regex": `
			set\ssecurity\snat\s(?P<direct>\S+)\srule-set\s(?P<rule_set_name>\S+)\srule\s(?P<name>\S+)\s
			(
				(
					(match\s
						(
							(
								source-address\s(?P<src_addr>\S+)
							) |
							(
								source-address-name\s(?P<src_addr_name>\S+)
							) |
							(
								protocol\s(?P<protocol>\S+)
							) |
							(
								destination-address\s(?P<dst_addr>\S+)
							) |
							(
								destination-address-name\s(?P<dst_addr_name>\S+)
							) |
							(
								destination-port\s(to\s(?P<dport2>\S+))
							) |
							(
								destination-port\s(?P<dport>\S+)(\sto\s(?P<_dport2>\S+))?
							) |
							(
								destination-port\s(to\s(?P<sport2>\S+))
							) |
							(
								source-port\s(?P<sport>\S+)(\sto\s(?P<_sport2>\S+))?
							)
						)
					) |
					(then\s
						(
							(source-nat\s
								(
									(?P<snat_off>off) |
									(?P<interface>interface) |
									(pool\s(?P<snat_pool>\S+))
								)
							) |
							(destination-nat\s
								(
									(?P<dnat_off>off) |
									(pool\s(?P<dnat_pool>\S+))
								)
							) |
							(static-nat\s
								(
									(prefix\s
										(
											(?P<static_nat_prefix>[\d\.\/]+) |
											(mapped-port\s
												(
													(to\s(?P<mapped_port2>\d+)) |
													(?P<mapped_port>\d+)
												)
											)
										)
									) |
									(prefix-name\s(?P<static_nat_prefix_name>\S+))
								)
							)
						)
					)
				)
			)
		`,
		"name":  "nat",
		"flags": "mx",
		"pcre":  "true",
	}

	// for _, section := range sections {
	natResult, err := text.SplitterProcessOneTime(natRegexMap, config)
	if err != nil {
		panic(err)
	}

	natMap, err := natResult.Projection(
		[]string{"src_addr", "src_addr_name", "protocol", "dst_addr", "dst_addr_name", "dport", "sport"},
		",",
		[][]string{
			[]string{
				"dport", "_dport2",
			},
			[]string{
				"sport", "_sport2",
			},
		})
	if err != nil {
		panic(err)
	}

	// 针对protocol和端口都设置的情况，需要进行进一步测试

	realService := &service.Service{}
	if natMap["protocol"] != "" {
		ps := strings.Split(natMap["protocol"], ",")
		for _, p := range ps {
			protocol, err := SRXParseProtocol(p)
			if err != nil {
				panic(err)
			}
			l3, err := service.NewL3Protocol(service.IPProto(protocol))
			if err != nil {
				panic(err)
			}
			realService.Add(l3)
		}
	}

	var realSrcL4Port, realDstL4Port *service.L4Port
	if natMap["sport"] != "" {
		if natMap["sport2"] != "" {

			realSrcL4Port, err = service.NewL4PortFromString(natMap["sport"]+"-"+natMap["sport2"], 0)
		} else {
			realSrcL4Port, err = service.NewL4PortFromString(natMap["sport"], 0)
		}
		if err != nil {
			panic(err)
		}
	}

	if natMap["dport"] != "" {
		if natMap["dport2"] != "" {
			realDstL4Port, err = service.NewL4PortFromString(natMap["dport"]+"-"+natMap["dport2"], 0)
		} else {
			realDstL4Port, err = service.NewL4PortFromString(natMap["dport"], 0)
		}

		if err != nil {
			panic(err)
		}
	}

	realSrc := network.NewNetworkGroup()
	realDst := network.NewNetworkGroup()

	// if natMap["realSrc_addr"] != "" {
	if natMap["src_addr"] != "" {
		// ng, err := network.NewNetworkGroupFromString(natMap["realSrc_addr"])
		ng, err := network.NewNetworkGroupFromString(natMap["src_addr"])
		if err != nil {
			panic(err)
		}
		realSrc.AddGroup(ng)
	}

	// if natMap["realSrc_addr_name"] != "" {
	if natMap["src_addr_name"] != "" {
		// names := strings.Split(natMap["realSrc_addr_name"], ",")
		names := strings.Split(natMap["src_addr_name"], ",")
		for _, name := range names {
			ng, ok := rule.objects.Network(from.Zone(), name)
			if !ok {
				panic(fmt.Sprint(natMap))
			}

			realSrc.AddGroup(ng)
		}
	}

	// if natMap["realDst_addr"] != "" {
	if natMap["dst_addr"] != "" {
		// ng, err := network.NewNetworkGroupFromString(natMap["realDst_addr"])
		ng, err := network.NewNetworkGroupFromString(natMap["dst_addr"])
		if err != nil {
			panic(err)
		}
		realDst.AddGroup(ng)
	}

	// if natMap["realDst_addr_name"] != "" {
	if natMap["dst_addr_name"] != "" {
		// names := strings.Split(natMap["realDst_addr_name"], ",")
		names := strings.Split(natMap["dst_addr_name"], ",")
		for _, name := range names {
			ng, ok := rule.objects.Network(from.Zone(), name)
			if !ok {
				panic(fmt.Sprint(natMap))
			}

			realDst.AddGroup(ng)
		}
	}

	if realSrcL4Port != nil || realDstL4Port != nil {
		stcp, err := service.NewL4Service(service.IPProto(6), realSrcL4Port, realDstL4Port)
		if err != nil {
			panic(err)
		}

		realService.Add(stcp)

		sudp, err := service.NewL4Service(service.IPProto(17), realSrcL4Port, realDstL4Port)
		if err != nil {
			panic(err)
		}

		realService.Add(sudp)
	}

	mappedSrc := network.NewNetworkGroup()
	mappedDst := network.NewNetworkGroup()
	mappedService := &service.Service{}

	if natMap["interface"] != "" {
		ipv4 := to.Ipv4List()
		ipv6 := to.Ipv6List()
		if realSrc.IsIPv4() {
			if len(ipv4) > 0 {
				net, err := network.NewNetworkGroupFromString(strings.Join(ipv4, ","))
				if err != nil {
					panic(err)
				}
				// net, _ = network.ParseIPNet(net.IP.String())
				mappedSrc.AddGroup(net)
			}
		}
		if realSrc.IsIPv6() {
			if len(ipv6) > 0 {
				net, err := network.NewNetworkGroupFromString(strings.Join(ipv6, ","))
				if err != nil {
					panic(err)
				}
				// net, _ = network.ParseIPNet(net.IP.String())
				mappedSrc.AddGroup(net)
			}
		}
	}

	if natMap["snat_pool"] != "" {
		obj, ok := rule.objects.Pool(natMap["snat_pool"], rule.natType)
		pool, ok := obj.(*NatPool)
		if !ok {
			panic(fmt.Sprint("get nat pool failed: ", natMap["snat_pool"]))
		}
		ng := pool.Network(nil)
		mappedSrc.AddGroup(ng)
		if pool.L4Port() != nil {
			s1, err := service.NewL4Service(service.IPProto(6), pool.L4Port(), nil)
			if err != nil {
				panic(err)
			}
			mappedService.Add(s1)
			s2, err := service.NewL4Service(service.IPProto(17), pool.L4Port(), nil)
			if err != nil {
				panic(err)
			}
			mappedService.Add(s2)
		}
	}

	if natMap["dnat_pool"] != "" {
		obj, ok := rule.objects.Pool(natMap["dnat_pool"], rule.natType)
		pool, ok := obj.(*NatPool)
		if !ok {
			panic(fmt.Sprint("get nat pool failed: ", natMap["dnat_pool"], rule.natType))
		}
		ng := pool.Network(nil)
		mappedDst.AddGroup(ng)
		if pool.L4Port() != nil {
			s1, err := service.NewL4Service(service.IPProto(6), nil, pool.L4Port())
			if err != nil {
				panic(err)
			}
			mappedService.Add(s1)
			s2, err := service.NewL4Service(service.IPProto(17), nil, pool.L4Port())
			if err != nil {
				panic(err)
			}
			mappedService.Add(s2)
		}
	}

	if natMap["static_nat_prefix"] != "" {
		ng, err := network.NewNetworkGroupFromString(natMap["static_nat_prefix"])
		if err != nil {
			panic(err)
		}
		mappedDst.AddGroup(ng)

		if natMap["mapped_port"] != "" {
			var l4port *service.L4Port
			if natMap["mapped_port2"] != "" {
				l4port, err = service.NewL4PortFromString(natMap["mapped_port"]+"-"+natMap["mapped_port2"], 0)
			} else {
				l4port, err = service.NewL4PortFromString(natMap["mapped_port"], 0)
			}

			if err != nil {
				panic(err)
			}
			s1, err := service.NewL4Service(service.TCP, nil, l4port)
			if err != nil {
				panic(err)
			}

			mappedService.Add(s1)
			s2, err := service.NewL4Service(service.UDP, nil, l4port)
			if err != nil {
				panic(err)
			}

			mappedService.Add(s2)
		}
	}

	if natMap["static_nat_prefix_name"] != "" {
		ng, ok := rule.objects.Network(to.Zone(), natMap["static_nat_prefix_name"])
		if !ok {
			panic(fmt.Sprint("get static nat prefix name failed: ", natMap["static_nat_prefix_name"]))
		}
		mappedDst.AddGroup(ng)
	}

	rule.from = from
	rule.to = to
	rule.name = natMap["name"]
	rule.ruleSetName = natMap["rule_set_name"]
	rule.orignal = policy.NewPolicyEntry()
	rule.orignal.AddSrc(realSrc)
	rule.orignal.AddDst(realDst)
	rule.orignal.AddService(realService)

	rule.translate = policy.NewPolicyEntry()
	rule.translate.AddSrc(mappedSrc)
	rule.translate.AddDst(mappedDst)
	rule.translate.AddService(mappedService)

	rule.status = SRX_NAT_ACTIVE

}

func StringToNatType(natType string) firewall.NatType {
	if natType == "source" {
		return firewall.DYNAMIC_NAT
	} else if natType == "static" {
		return firewall.STATIC_NAT
	} else if natType == "destination" {
		return firewall.DESTINATION_NAT
	} else {
		panic(fmt.Sprint("unsupport nat type: ", natType))
	}

}

func (rule *NatRule) natTranslate(from, to string, entry *policy.Intent) (bool, policy.PolicyEntryInf) {
	// state := rule.match(from, to, entry)
	// if state == SRX_NAT_MATCH_NONE || state == SRX_NAT_MATCH_NOT_OK {
	// return false, nil
	// }
	if rule.natType == firewall.STATIC_NAT {
		if from == rule.from.Zone() {
			ok, tranlateTo, msg := entry.Translate(rule.translate)
			if !ok {
				panic(msg)
			}

			return true, entry.NewIntentWithTicket(tranlateTo)

		} else {
			reverse := rule.orignal.Reverse()
			ok, tranlateTo, msg := entry.Translate(reverse)
			if !ok {
				panic(msg)
			}
			return true, entry.NewIntentWithTicket(tranlateTo)
		}
	} else {
		ok, tranlateTo, msg := entry.Translate(rule.translate)
		if !ok {
			panic(msg)
		}

		return true, entry.NewIntentWithTicket(tranlateTo)
	}
}

func (rule *NatRule) matchDnatTarget(entry policy.PolicyEntryInf) bool {
	if rule.natType == firewall.DYNAMIC_NAT {
		return false
	}

	// reverse := entry.Reverse()
	if rule.translate.Match(entry) {
		return true
	}

	return false
}

func (rule *NatRule) match(from, to string, entry policy.PolicyEntryInf) SrxNatMatchState {
	if rule.status == SRX_NAT_INACTIVE {
		return SRX_NAT_MATCH_NONE
	}

	if rule.orignal.Dst().Count().Cmp(big.NewInt(0)) == 0 {
		return SRX_NAT_MATCH_NONE
	}

	if rule.orignal.Match(entry) {
		return SRX_NAT_MATCH_OK
	} else {
		return SRX_NAT_MATCH_NOT_OK
	}
}

func (rule *NatRule) reverseMatch(from, to string, entry policy.PolicyEntryInf) SrxNatMatchState {
	if rule.status == SRX_NAT_INACTIVE {
		return SRX_NAT_MATCH_NONE
	}

	if rule.orignal.Dst().Count().Cmp(big.NewInt(0)) == 0 {
		return SRX_NAT_MATCH_NONE
	}

	if rule.translate.Reverse().Match(entry) {
		return SRX_NAT_MATCH_OK
	} else {
		return SRX_NAT_MATCH_NOT_OK
	}

}

func (nat *Nats) inputNat(intent *policy.Intent, inPort api.Port) (bool, *policy.Intent, *NatRule) {

	// func (ns *NatRuleSet) match(natType firewall.NatType, from, to string, entry *policy.Intent) (*NatRule, bool) {
	for _, m := range []map[string]*NatRuleSet{nat.staticNatRules, nat.destinationNatRules} {
		for _, ruleSet := range m {
			rule, ok := ruleSet.match(inPort.(*SRXPort).Zone(), "", intent)
			if ok {
				ok, translateTo := rule.natTranslate(inPort.(*SRXPort).Zone(), "", intent)
				return ok, translateTo.(*policy.Intent), rule
			}
		}
	}

	return false, nil, nil
}

func (nat *Nats) outputNat(intent *policy.Intent, inPort, outPort api.Port) (bool, *policy.Intent, *NatRule) {
	for _, ruleSet := range nat.staticNatRules {
		rule, ok := ruleSet.reverseMatch(inPort.(*SRXPort).Zone(), outPort.(*SRXPort).Zone(), intent)
		if ok {
			ok, translateTo := rule.natTranslate(inPort.(*SRXPort).Zone(), outPort.(*SRXPort).Zone(), intent)
			return ok, translateTo.(*policy.Intent), rule
		}

	}

	for _, ruleSet := range nat.sourceNatRules {
		rule, ok := ruleSet.match(inPort.(*SRXPort).Zone(), outPort.(*SRXPort).Zone(), intent)
		if ok {
			ok, translateTo := rule.natTranslate(inPort.(*SRXPort).Zone(), outPort.(*SRXPort).Zone(), intent)
			return ok, translateTo.(*policy.Intent), rule
		}
	}

	return false, nil, nil
}

func (nat *Nats) inputNatTargetCheck(intent *policy.Intent, inPort, outPort api.Port) (bool, *NatRule) {
	target := intent.GenerateIntentPolicyEntry()
	for _, ruleSetMap := range []map[string]*NatRuleSet{nat.staticNatRules, nat.destinationNatRules} {
		for _, ruleSet := range ruleSetMap {
			rule, ok := ruleSet.matchDnatTarget(inPort.(*SRXPort).Zone(), outPort.(*SRXPort).Zone(), target)
			return ok, rule
		}
	}
	return false, nil
}

func (nats *Nats) FindRuleSet(inPort, outPort api.Port, natType firewall.NatType) *NatRuleSet {
	switch natType {
	case firewall.DYNAMIC_NAT:
		for _, ruleSet := range nats.sourceNatRules {
			if ruleSet.from.Zone() == inPort.(*SRXPort).Zone() && ruleSet.to.Zone() == outPort.(*SRXPort).Zone() {
				return ruleSet
			}
		}
	case firewall.STATIC_NAT, firewall.DESTINATION_NAT:
		for _, ruleSet := range nats.staticNatRules {
			if ruleSet.from.Zone() == inPort.(*SRXPort).Zone() {
				return ruleSet
			}
		}
	}
	return nil
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallNatRule)(nil)).Elem(), "SrxNatRule", reflect.TypeOf(NatRule{}))
}

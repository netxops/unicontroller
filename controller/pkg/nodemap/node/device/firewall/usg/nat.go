package usg

import (
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
	"github.com/netxops/utils/text"
	"github.com/netxops/utils/tools"
)

type UsgNatMatchState int

const (
	// NONE表示未进行实质匹配，比如NatRule的内容为空
	Usg_NAT_MATCH_NONE UsgNatMatchState = iota
	Usg_NAT_MATCH_OK
	// NOT_OK表示未命中策略
	Usg_NAT_MATCH_NOT_OK
)

type UsgNatStatus int

const (
	Usg_NAT_INACTIVE UsgNatStatus = iota
	Usg_NAT_ACTIVE
)

// NatServer represents a NAT server configuration
type NatServer struct {
	objects     *UsgObjectSet
	node        *UsgNode
	id          string
	name        string
	protocol    string
	globalIP    string
	globalPort  string
	insideIP    string
	insidePort  string
	vpnInstance string
	out         string
	cli         string
	status      UsgNatStatus
	orignal     policy.PolicyEntryInf
	translate   policy.PolicyEntryInf
}

func (ns *NatServer) Name() string {
	if ns.name != "" {
		return ns.name
	}
	return ns.id
}

func (ns *NatServer) Cli() string {
	return ns.cli
}

func (ns *NatServer) Original() policy.PolicyEntryInf {
	return ns.orignal
}

func (ns *NatServer) Translate() policy.PolicyEntryInf {
	return ns.translate
}

type NatRuleSet struct {
	from, to *UsgPort
	natType  firewall.NatType
	name     string
	rules    []*NatRule
	configs  []string
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

// func (ns *NatRuleSet) matchDnatTarget(from, to string, entry policy.PolicyEntryInf) (*NatRule, bool) {
// 	if !(ns.natType == firewall.STATIC_NAT || ns.natType == firewall.DESTINATION_NAT) {
// 		return nil, false
// 	}

// 	for _, rule := range ns.rules {
// 		if rule.matchDnatTarget(entry) {
// 			return rule, true
// 		}
// 	}
// 	return nil, false
// }

// func (ns *NatRuleSet) reverseMatch(from, to string, entry *policy.Intent) (*NatRule, bool) {
// 	if ns.natType != firewall.STATIC_NAT {
// 		return nil, false
// 	}

// 	for _, rule := range ns.rules {
// 		if rule.reverseMatch(from, to, entry) == Usg_NAT_MATCH_OK {
// 			return rule, true
// 		}
// 	}
// 	return nil, false
// }

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
		if rule.match(from, to, entry) == Usg_NAT_MATCH_OK {
			return rule, true
		}
	}

	return nil, false
}

type NatRule struct {
	objects     *UsgObjectSet
	name        string
	ruleSetName string
	node        *UsgNode
	from        []string
	fromPorts   []string
	to          []string
	toPorts     []string
	natType     firewall.NatType
	cli         string
	status      UsgNatStatus
	orignal     policy.PolicyEntryInf
	translate   policy.PolicyEntryInf
	noReverse   bool
}

// TypeName 实现 TypeInterface 接口
func (nr *NatRule) TypeName() string {
	return "UsgNatRule"
}

// natRuleJSON 用于序列化和反序列化
type natRuleJSON struct {
	Name        string                `json:"name"`
	RuleSetName string                `json:"rule_set_name"`
	From        []string              `json:"from"`
	FromPorts   []string              `json:"from_ports"`
	To          []string              `json:"to"`
	ToPorts     []string              `json:"to_ports"`
	NatType     firewall.NatType      `json:"nat_type"`
	Cli         string                `json:"cli"`
	Status      UsgNatStatus          `json:"status"`
	Orignal     policy.PolicyEntryInf `json:"orignal"`
	Translate   policy.PolicyEntryInf `json:"translate"`
	NoReverse   bool                  `json:"no_reverse"`
}

// MarshalJSON 实现 JSON 序列化
func (nr *NatRule) MarshalJSON() ([]byte, error) {
	return json.Marshal(natRuleJSON{
		Name:        nr.name,
		RuleSetName: nr.ruleSetName,
		From:        nr.from,
		FromPorts:   nr.fromPorts,
		To:          nr.to,
		ToPorts:     nr.toPorts,
		NatType:     nr.natType,
		Cli:         nr.cli,
		Status:      nr.status,
		Orignal:     nr.orignal,
		Translate:   nr.translate,
		NoReverse:   nr.noReverse,
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
	nr.fromPorts = nrj.FromPorts
	nr.to = nrj.To
	nr.toPorts = nrj.ToPorts
	nr.natType = nrj.NatType
	nr.cli = nrj.Cli
	nr.status = nrj.Status
	nr.orignal = nrj.Orignal
	nr.translate = nrj.Translate
	nr.noReverse = nrj.NoReverse

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

// type Nats struct {
// 	objects    *UsgObjectSet
// 	node       *UsgNode
// 	ruleSetMap map[firewall.NatType]map[string]*NatRuleSet
// 	// 都是以ruleSet的名称为key
// 	staticNatRules      map[string]*NatRuleSet
// 	sourceNatRules      map[string]*NatRuleSet
// 	destinationNatRules map[string]*NatRuleSet
// }

// Add NAT servers to the Nats struct
// type Nats struct {
// 	objects             *UsgObjectSet
// 	node                *UsgNode
// 	ruleSetMap          map[firewall.NatType]map[string]*NatRuleSet
// 	staticNatRules      map[string]*NatRuleSet
// 	sourceNatRules      map[string]*NatRuleSet
// 	destinationNatRules map[string]*NatRuleSet
// 	natServers          map[string]*NatServer // Add this field
// }

type Nats struct {
	objects *UsgObjectSet
	node    *UsgNode
	// ruleSetMap          map[firewall.NatType]map[string]*NatRuleSet
	staticNatRules      []*NatRule
	sourceNatRules      []*NatRule
	destinationNatRules []*NatRule
	// natServers          []*NatServer                 // NAT server configurations
	natServers        []*NatRule
	natStaticMappings map[string]*NatStaticMapping // Static NAT mappings
	natPolicyRules    []*NatRule                   // NAT policy rules
	addressGroups     map[string]*AddressGroup     // Address groups for NAT
	// natPools            map[string]*NatPool          // NAT address pools
	insidePools map[string]*NatPool // NAT inside address pools
	globalPools map[string]*NatPool // NAT global address pools
}

// TypeName 实现 TypeInterface 接口
func (n *Nats) TypeName() string {
	return "UsgNats"
}

// natsJSON 用于序列化和反序列化
type natsJSON struct {
	StaticNatRules      []*NatRule                   `json:"static_nat_rules"`
	SourceNatRules      []*NatRule                   `json:"source_nat_rules"`
	DestinationNatRules []*NatRule                   `json:"destination_nat_rules"`
	NatServers          []*NatRule                   `json:"nat_servers"`
	NatStaticMappings   map[string]*NatStaticMapping `json:"nat_static_mappings"`
	NatPolicyRules      []*NatRule                   `json:"nat_policy_rules"`
	AddressGroups       map[string]*AddressGroup     `json:"address_groups"`
	InsidePools         map[string]*NatPool          `json:"inside_pools"`
	GlobalPools         map[string]*NatPool          `json:"global_pools"`
}

// MarshalJSON 实现 JSON 序列化
func (n *Nats) MarshalJSON() ([]byte, error) {
	return json.Marshal(natsJSON{
		StaticNatRules:      n.staticNatRules,
		SourceNatRules:      n.sourceNatRules,
		DestinationNatRules: n.destinationNatRules,
		NatServers:          n.natServers,
		NatStaticMappings:   n.natStaticMappings,
		NatPolicyRules:      n.natPolicyRules,
		AddressGroups:       n.addressGroups,
		InsidePools:         n.insidePools,
		GlobalPools:         n.globalPools,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (n *Nats) UnmarshalJSON(data []byte) error {
	var nj natsJSON
	if err := json.Unmarshal(data, &nj); err != nil {
		return err
	}

	n.staticNatRules = nj.StaticNatRules
	n.sourceNatRules = nj.SourceNatRules
	n.destinationNatRules = nj.DestinationNatRules
	n.natServers = nj.NatServers
	n.natStaticMappings = nj.NatStaticMappings
	n.natPolicyRules = nj.NatPolicyRules
	n.addressGroups = nj.AddressGroups
	n.insidePools = nj.InsidePools
	n.globalPools = nj.GlobalPools

	return nil
}

func (nat *Nats) hasRuleName(name string) bool {
	for _, rules := range [][]*NatRule{nat.staticNatRules, nat.sourceNatRules, nat.destinationNatRules} {
		for _, rule := range rules {
			if rule.Name() == name {
				return true
			}
		}
	}

	return false
}

func (nat *Nats) GetNatRuleSet(natType firewall.NatType, name string) (*NatRule, bool) {
	var rules []*NatRule

	switch natType {
	case firewall.STATIC_NAT:
		rules = nat.staticNatRules
	case firewall.DESTINATION_NAT:
		rules = nat.destinationNatRules
	case firewall.DYNAMIC_NAT:
		rules = nat.sourceNatRules
	default:
		return nil, false
	}

	for _, rule := range rules {
		if rule.Name() == name {
			return rule, true
		}
	}
	return nil, false

}

func (nat *Nats) NatRule(natType firewall.NatType, name string) (*NatRule, bool) {
	rule, ok := nat.GetNatRuleSet(natType, name)
	if !ok {
		return nil, false
	}

	return rule, true
}

// func (nat *Nats) flyConfig(config string) {
// 	infoRegexMap := map[string]string{
// 		"regex": `set security nat (?P<natType>\S+) rule-set (?P<ruleSet>\S+)`,
// 		"name":  "info",
// 		"flags": "m",
// 		"pcre":  "true",
// 	}

// 	ruleSetSection := nat.parseRuleSet(config)
// 	for _, ruleSetCli := range ruleSetSection {
// 		sections := nat.parseSection(ruleSetCli)
// 		for _, section := range sections {
// 			rule := &NatRule{
// 				objects: nat.objects,
// 				node:    nat.node,
// 			}

// 			infoResult, err := text.SplitterProcessOneTime(infoRegexMap, section)
// 			if err != nil {
// 				panic(err)
// 			}

// 			info, ok := infoResult.One()
// 			if !ok {
// 				panic("get nat info error")
// 			}

// 			var natType firewall.NatType
// 			var ruleSet *NatRuleSet
// 			if info["natType"] == "static" {
// 				natType = firewall.STATIC_NAT
// 				ruleSet = nat.staticNatRules[info["ruleSet"]]
// 			} else if info["natType"] == "source" {
// 				natType = firewall.DYNAMIC_NAT
// 				ruleSet = nat.sourceNatRules[info["ruleSet"]]
// 			} else {
// 				natType = firewall.DESTINATION_NAT
// 				ruleSet = nat.destinationNatRules[info["ruleSet"]]
// 			}

// 			if ruleSet == nil {
// 				panic(fmt.Sprintf("get rule set failed, natType: %s, name: %s", natType, info["ruleSet"]))
// 			}

// 			rule.parseNat(section, natType, ruleSet.from, ruleSet.to)
// 			ruleSet.rules = append(ruleSet.rules, rule)

// 		}
// 	}
// }

// func (nat *Nats) flyConfig(config string) error {
// 	ruleSets, err := nat.parseRuleSet(config)
// 	if err != nil {
// 		return err
// 	}

// 	for _, ruleSet := range ruleSets {
// 		var err error
// 		switch ruleSet.natType {
// 		case firewall.STATIC_NAT:
// 			err = nat.parseStaticNat(ruleSet)
// 		case firewall.DYNAMIC_NAT:
// 			err = nat.parseSourceNat(ruleSet)
// 		case firewall.DESTINATION_NAT:
// 			err = nat.parseDestinationNat(ruleSet)
// 		default:
// 			return fmt.Errorf("unknown NAT type: %s", ruleSet.natType)
// 		}

// 		if err != nil {
// 			return err
// 		}
// 	}

// 	return nil
// }

func (nat *Nats) parseConfig(config string) error {
	// Parse address groups first
	if err := nat.parseAddressGroups(config); err != nil {
		fmt.Printf("[DEBUG] failed to parse address groups: %v\n", err)
		fmt.Printf("[DEBUG] config preview (first 500 chars): %s\n", getConfigPreview(config, 500))
	}

	// Parse static mappings
	if err := nat.parseNatStaticMapping(config); err != nil {
		fmt.Printf("[DEBUG] failed to parse static mappings: %v\n", err)
		fmt.Printf("[DEBUG] config contains 'inside-ipv4-pool': %v\n", strings.Contains(config, "inside-ipv4-pool"))
		fmt.Printf("[DEBUG] config contains 'global-ipv4-pool': %v\n", strings.Contains(config, "global-ipv4-pool"))
		fmt.Printf("[DEBUG] config contains 'static-mapping': %v\n", strings.Contains(config, "static-mapping"))
		fmt.Printf("[DEBUG] config preview (first 500 chars): %s\n", getConfigPreview(config, 500))
	}

	_, err := nat.parseRuleSet(config)
	if err != nil {
		return err
	}

	return nil
}

func (nat *Nats) parseRuleSet(config string) ([]*NatRuleSet, error) {
	// 分别处理传统NAT规则和NAT policy
	var ruleSets []*NatRuleSet

	// // 1. 解析传统NAT规则 (nat static/source-nat/destination-nat)
	// traditionalRuleSets, err := nat.parseTraditionalNatRules(config)
	// if err != nil {
	// 	return nil, err
	// }
	// ruleSets = append(ruleSets, traditionalRuleSets...)

	// 2. 解析NAT server (only if config contains nat server format)
	if strings.Contains(config, "nat server") {
		if err := nat.parseNatServer(config); err != nil {
			// 静默处理，如果配置中有 nat server 但解析失败，记录调试信息
			fmt.Printf("[DEBUG] failed to parse NAT server: %v\n", err)
			fmt.Printf("[DEBUG] config preview (first 500 chars): %s\n", getConfigPreview(config, 500))
		}
	}

	// 3. 解析NAT policy
	natPolicyRuleSets, err := nat.parseNatPolicy(config)
	if err != nil {
		return nil, err
	}
	ruleSets = append(ruleSets, natPolicyRuleSets...)

	return ruleSets, nil
}

// parseNatServer parses NAT server configurations
func (nat *Nats) parseNatServer(config string) error {
	// if nat.natServers == nil {
	// 	nat.natServers = make(map[string]*NatServer)
	// }

	// if nat.staticNatRules == nil {
	// 	nat.staticNatRules = make(map[string]*NatRuleSet)
	// }

	natServerRegexMap := map[string]string{
		"regex": `
            nat\s+server\s+(?P<id>\S+)\s+
            (zone\s+(?P<zone>\S+)\s+)?
            (protocol\s+(?P<protocol>\S+)\s+)?
            global\s+(?P<global_ip>\S+)(\s+(?P<global_port>\S+))?\s*
            inside\s+(?P<inside_ip>\S+)
                (\s(?P<inside_port>\S+))?\s*
                (vpn-instance\s+(?P<vpn_instance>\S+))?
        `,
		"name":  "natserver",
		"flags": "mx",
		"pcre":  "true",
	}

	result, err := text.SplitterProcessOneTime(natServerRegexMap, config)
	if err != nil {
		return fmt.Errorf("failed to process NAT server regex: %v", err)
	}

	for it := result.Iterator(); it.HasNext(); {
		_, _, natServerMap := it.Next()

		natServer := &NatServer{
			objects:     nat.objects,
			node:        nat.node,
			id:          natServerMap["id"],
			protocol:    natServerMap["protocol"],
			globalIP:    natServerMap["global_ip"],
			globalPort:  natServerMap["global_port"],
			insideIP:    natServerMap["inside_ip"],
			insidePort:  natServerMap["inside_port"],
			out:         natServerMap["zone"],
			vpnInstance: natServerMap["vpn_instance"],
			cli:         natServerMap["__match__"],
			status:      Usg_NAT_ACTIVE,
			orignal:     policy.NewPolicyEntry(),
			translate:   policy.NewPolicyEntry(),
		}

		// Set name if it's not a numeric ID
		if !isNumeric(natServer.id) {
			natServer.name = natServer.id
		}

		// Parse and set up the policy entries
		if rule, err := nat.setupNatServerPolicy(natServer); err != nil {
			return fmt.Errorf("failed to setup NAT server policy for %s: %v", natServer.Name(), err)
		} else {
			nat.natServers = append(nat.natServers, rule)
		}

		// nat.natServers = append(nat.natServers, natServer)

		// // Convert NAT server to static NAT rule
		// natRule := &NatRule{
		// 	objects:     nat.objects,
		// 	node:        nat.node,
		// 	name:        natServer.Name(),
		// 	ruleSetName: "nat-server",
		// 	natType:     firewall.STATIC_NAT,
		// 	status:      Usg_NAT_ACTIVE,
		// 	orignal:     natServer.orignal,
		// 	translate:   natServer.translate,
		// 	cli:         natServer.cli,
		// 	from:        []string{natServer.from},
		// }

		// // Add the NAT rule to staticNatRules
		// if _, exists := nat.staticNatRules["nat-server"]; !exists {
		// 	nat.staticNatRules["nat-server"] = &NatRuleSet{
		// 		name:    "nat-server",
		// 		natType: firewall.STATIC_NAT,
		// 		rules:   []*NatRule{},
		// 	}
		// }
		// nat.staticNatRules["nat-server"].rules = append(nat.staticNatRules["nat-server"].rules, natRule)
	}

	return nil
}

// setupNatServerPolicy sets up the original and translate policy entries for NAT server
// func (nat *Nats) setupNatServerPolicy(natServer *NatServer) error {
// 	// Setup original policy entry (inside -> global)
// 	insideNG, err := network.NewNetworkGroupFromString(natServer.insideIP)
// 	if err != nil {
// 		return fmt.Errorf("invalid inside IP: %s", natServer.insideIP)
// 	}
// 	natServer.orignal.AddSrc(insideNG)

// 	globalNG, err := network.NewNetworkGroupFromString(natServer.globalIP)
// 	if err != nil {
// 		return fmt.Errorf("invalid global IP: %s", natServer.globalIP)
// 	}
// 	natServer.orignal.AddDst(globalNG)

// 	// Setup translate policy entry (global -> inside)
// 	natServer.translate.AddSrc(globalNG)
// 	natServer.translate.AddDst(insideNG)

// 	// Setup service if protocol and ports are specified
// 	if natServer.protocol != "" {
// 		var svc *service.Service
// 		if natServer.globalPort != "" && natServer.insidePort != "" {
// 			// Both ports specified
// 			svc, err = service.NewServiceWithL4(natServer.protocol, natServer.globalPort, natServer.insidePort)
// 		} else if natServer.globalPort != "" {
// 			// Only global port specified
// 			svc, err = service.NewServiceWithL4(natServer.protocol, "", natServer.globalPort)
// 		} else {
// 			// Only protocol specified
// 			svc, err = service.NewServiceWithProto(natServer.protocol)
// 		}

// 		if err != nil {
// 			return fmt.Errorf("failed to create service: %v", err)
// 		}

// 		natServer.orignal.AddService(svc)
// 		natServer.translate.AddService(svc)
// 	} else {
// 		// Default to IP service
// 		svc, err := service.NewServiceWithProto("ip")
// 		if err != nil {
// 			return err
// 		}
// 		natServer.orignal.AddService(svc)
// 		natServer.translate.AddService(svc)
// 	}

// 	return nil
// }

// parseNatPolicy parses NAT policy configurations and returns rule sets
func (nat *Nats) parseNatPolicy(config string) ([]*NatRuleSet, error) {
	var ruleSets []*NatRuleSet

	// Extract nat-policy sections using regex
	natPolicyRegex := `nat-policy.*?#`
	natPolicyRegexMap := map[string]string{
		"regex": natPolicyRegex,
		"name":  "natpolicy",
		"flags": "s",
		"pcre":  "true",
	}

	result, err := text.SplitterProcessOneTime(natPolicyRegexMap, config)
	if err != nil {
		return nil, fmt.Errorf("failed to process NAT policy regex: %v", err)
	}

	for it := result.Iterator(); it.HasNext(); {
		_, _, rsMap := it.Next()
		natPolicyConfig := rsMap["__match__"]

		// Parse rules within this nat-policy section
		policyRuleSets, err := nat.parseNatPolicyRules(natPolicyConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to parse NAT policy rules: %v", err)
		}
		ruleSets = append(ruleSets, policyRuleSets...)
	}

	return ruleSets, nil
}

// parseNatPolicyRules parses individual rules within a nat-policy section
func (nat *Nats) parseNatPolicyRules(config string) ([]*NatRuleSet, error) {
	var ruleSets []*NatRuleSet

	// Group rules by rule name
	ruleGroups := nat.groupNatPolicyRules(config)

	for ruleName, ruleConfig := range ruleGroups {
		rule, err := nat.parseNatPolicyRule(ruleName, ruleConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to parse NAT policy rule %s: %v", ruleName, err)
		}

		// Create a rule set for this rule
		ruleSet := &NatRuleSet{
			natType: rule.natType,
			name:    "nat-policy-" + ruleName,
			rules:   []*NatRule{rule},
		}
		ruleSets = append(ruleSets, ruleSet)
	}

	return ruleSets, nil
}

func (nat *Nats) groupNatPolicyRules(config string) map[string][]string {
	ruleGroups := make(map[string][]string)

	// Regex to match rule lines
	ruleRegex := regexp.MustCompile(`rule\s+name\s+(\S+)`)

	lines := strings.Split(config, "\n")
	var currentRule string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Check if this is a new rule
		if matches := ruleRegex.FindStringSubmatch(line); len(matches) > 1 {
			currentRule = matches[1]
			ruleGroups[currentRule] = []string{line}
		} else if currentRule != "" {
			// Add line to current rule
			ruleGroups[currentRule] = append(ruleGroups[currentRule], line)
		}
	}

	return ruleGroups
}

// parseNatPolicyRule parses a single NAT policy rule
func (nat *Nats) parseNatPolicyRule(ruleName string, ruleConfig []string) (*NatRule, error) {
	rule := &NatRule{
		objects:     nat.objects,
		node:        nat.node,
		name:        ruleName,
		ruleSetName: "nat-policy",
		status:      Usg_NAT_ACTIVE,
		orignal:     policy.NewPolicyEntry(),
		translate:   policy.NewPolicyEntry(),
		cli:         strings.Join(ruleConfig, "\n"),
	}

	// Parse rule configuration
	configStr := strings.Join(ruleConfig, "\n")

	// Determine NAT type and parse accordingly
	var err error
	if strings.Contains(configStr, "action source-nat") {
		rule.natType = firewall.DYNAMIC_NAT
		err = nat.parseNatPolicySourceNat(rule, configStr)
	} else if strings.Contains(configStr, "action destination-nat") {
		rule.natType = firewall.DESTINATION_NAT
		err = nat.parseNatPolicyDestinationNat(rule, configStr)
	} else {
		return nil, fmt.Errorf("unknown NAT action type in rule: %s", ruleName)
	}

	if err != nil {
		return nil, err
	}
	nat.natPolicyRules = append(nat.natPolicyRules, rule)

	return rule, nil
}

// parseNatPolicySourceNat parses source NAT configuration in nat-policy
func (nat *Nats) parseNatPolicySourceNat(rule *NatRule, config string) error {
	// Parse source zone
	if matches := regexp.MustCompile(`source-zone\s+(\S+)`).FindStringSubmatch(config); len(matches) > 1 {
		rule.from = []string{matches[1]}
	}

	// Parse destination zone
	if matches := regexp.MustCompile(`destination-zone\s+(\S+)`).FindStringSubmatch(config); len(matches) > 1 {
		rule.to = []string{matches[1]}
	}

	// Parse source IP
	if err := nat.parseNatPolicySourceIP(rule, config); err != nil {
		return err
	}

	// Parse destination IP
	if err := nat.parseNatPolicyDestinationIP(rule, config); err != nil {
		return err
	}

	// Parse service
	if err := nat.parseNatPolicyService(rule, config); err != nil {
		return err
	}

	// Parse SNAT action
	if err := nat.parseNatPolicySnatAction(rule, config); err != nil {
		return err
	}

	if rule.translate.Dst() == nil {
		rule.translate.SetDst(network.NewAny4Group())
	}

	if rule.translate.Service() == nil {
		rule.translate.SetService(service.NewServiceMust("ip"))
	}

	return nil
}

// parseNatPolicySnatAction parses SNAT action configuration in nat-policy
func (nat *Nats) parseNatPolicySnatAction(rule *NatRule, config string) error {
	regexMap := map[string]string{
		"regex": `
            action\s+source-nat\s+
            (
                (address-group\s+(?P<address_group>\S+)) |
                (?P<easy_ip>easy-ip) |
                (static-mapping(\s(?P<mapping_id>\S+))?)
            )
        `,
		"name":  "action_snat",
		"flags": "mx",
		"pcre":  "true",
	}

	result, err := text.SplitterProcessOneTime(regexMap, config)
	if err != nil {
		return fmt.Errorf("failed to process SNAT action regex: %v", err)
	}

	snatMap, ok := result.One()
	if !ok {
		return fmt.Errorf("no SNAT action found in config")
	}

	if snatMap["address_group"] != "" {
		groupName := snatMap["address_group"]
		addGrp, ok := nat.addressGroups[groupName]
		if !ok {
			return fmt.Errorf("address group not found: %s", groupName)
		}

		// Add the address group to the translate source of the rule
		rule.translate.AddSrc(addGrp.Network(nil))
	} else if snatMap["easy_ip"] != "" {
		// For easy-ip, we use the output interface's IP address
		// easy-ip uses the IP of the destination zone's interface (output interface)
		if len(rule.to) > 0 {
			// rule.to contains destination zone names
			// Find the port that belongs to this zone
			zoneName := rule.to[0]
			var outPort api.Port
			portList := nat.node.PortList()
			for _, port := range portList {
				if port == nil {
					continue
				}
				// Check if port is UsgPort and has matching zone
				if usgPort, ok := port.(*UsgPort); ok {
					if usgPort.Zone() == zoneName {
						outPort = port
						break
					}
				}
			}
			if outPort == nil {
				return fmt.Errorf("interface not found for easy-ip in destination zone: %s", zoneName)
			}
			rule.translate.AddSrc(outPort.V4NetworkGroup())
		} else {
			return fmt.Errorf("no destination zone specified for easy-ip")
		}
	} else if snatMap["mapping_id"] != "" {
		mappingID := snatMap["mapping_id"]
		mapping, ok := nat.natStaticMappings[mappingID]
		if !ok {
			return fmt.Errorf("static mapping not found: %s", mappingID)
		}

		// Add the static mapping to the translate source of the rule
		// rule.translate.AddSrc(mapping.Network(nil))
		rule.translate = mapping.translate.Copy().(policy.PolicyEntryInf)
	} else {
		return fmt.Errorf("unknown SNAT action in config: %s", config)
	}

	return nil
}

// parseNatPolicyDnatAction parses DNAT action configuration in nat-policy
func (nat *Nats) parseNatPolicyDnatAction(rule *NatRule, config string) error {
	regexMap := map[string]string{
		"regex": `
            action\s+destination-nat\s+
            (static\s+
                (
                    (?P<type>address-to-address|address-to-port|port-to-address|port-to-port)
                )
                \s+
            )?
            (
                (address-group\s+(?P<address_group>\S+)(\s+(?P<group_port>\S+))?) |
                (address\s+(?P<address>\S+)(\s+(?P<addr_port>\S+))?) 
            )
        `,
		"name":  "action_dnat",
		"flags": "mx",
		"pcre":  "true",
	}

	result, err := text.SplitterProcessOneTime(regexMap, config)
	if err != nil {
		return fmt.Errorf("failed to process DNAT action regex: %v", err)
	}

	dnatMap, ok := result.One()
	if !ok {
		return fmt.Errorf("no DNAT action found in config")
	}

	var ng *network.NetworkGroup
	var svc *service.Service

	// Parse address-group
	if dnatMap["address_group"] != "" {
		groupName := dnatMap["address_group"]
		if isNumeric(groupName) {
			// 数字类型的 groupNumber，从 addressGroups 查找
			addrGrp := nat.addressGroups[groupName]
			if addrGrp != nil && addrGrp.N != nil {
				ng = addrGrp.N
			}
		} else {
			// 非数字类型的 groupName，从 addressGroups 查找（MIP对象）
			addrGrp, exists := nat.addressGroups[groupName]
			if !exists || addrGrp == nil {
				return fmt.Errorf("address group not found: %s", groupName)
			}
			// 使用 AddressGroup 的 Network() 方法获取网络组
			ng = addrGrp.Network(nil)
		}

		// Parse port for address-group
		if dnatMap["group_port"] != "" {
			port := dnatMap["group_port"]
			l4port, err := service.NewL4PortFromString(port, 0)
			if err != nil {
				return fmt.Errorf("invalid port for address group: %s", port)
			}
			svc, err = service.NewService(service.TCP, nil, l4port, 0, 0)
			if err != nil {
				return err
			}
		}
	}

	// Parse direct address
	if dnatMap["address"] != "" {
		address := dnatMap["address"]
		ng, err = network.NewNetworkGroupFromString(address)
		if err != nil {
			return fmt.Errorf("invalid DNAT address: %s", address)
		}

		// Parse port for direct address
		if dnatMap["addr_port"] != "" {
			port := dnatMap["addr_port"]
			l4port, err := service.NewL4PortFromString(port, 0)
			if err != nil {
				return fmt.Errorf("invalid port for address: %s", port)
			}
			svc, err = service.NewService(service.TCP, nil, l4port, 0, 0)
			if err != nil {
				return err
			}
		}
	}

	// Add parsed network group to translate destination
	if ng != nil {
		rule.translate.AddSrc(network.NewAny4Group())
		rule.translate.AddDst(ng)
	} else {
		return fmt.Errorf("no valid destination address found in DNAT action")
	}

	// Add parsed service to translate if specified
	if svc != nil {
		rule.translate.AddService(svc)
	}

	return nil
}

// parseNatPolicyDestinationNat parses destination NAT configuration in nat-policy
func (nat *Nats) parseNatPolicyDestinationNat(rule *NatRule, config string) error {
	// Parse source zone
	if matches := regexp.MustCompile(`source-zone\s+(\S+)`).FindStringSubmatch(config); len(matches) > 1 {
		rule.from = []string{matches[1]}
	}

	// Parse destination zone
	if matches := regexp.MustCompile(`destination-zone\s+(\S+)`).FindStringSubmatch(config); len(matches) > 1 {
		rule.to = []string{matches[1]}
	}

	// Parse source IP
	if err := nat.parseNatPolicySourceIP(rule, config); err != nil {
		return err
	}

	// Parse destination IP
	if err := nat.parseNatPolicyDestinationIP(rule, config); err != nil {
		return err
	}

	// Parse service
	if err := nat.parseNatPolicyService(rule, config); err != nil {
		return err
	}

	// Parse DNAT action
	if err := nat.parseNatPolicyDnatAction(rule, config); err != nil {
		return err
	}

	return nil
}

// AddressGroup represents an address group (placeholder struct)
// type AddressGroup struct {
// 	id      int
// 	members []string
// }

// Network returns the network group for this address group
// func (ag *AddressGroup) Network(zone interface{}) *network.NetworkGroup {
// 	ng := network.NewNetworkGroup()
// 	for _, member := range ag.members {
// 		if net, err := network.NewNetworkGroupFromString(member); err == nil {
// 			ng.AddGroup(net)
// 		}
// 	}
// 	return ng
// }

// parseNatPolicySourceIP parses source IP configuration
func (nat *Nats) parseNatPolicySourceIP(rule *NatRule, config string) error {
	lines := strings.Split(config, "\n")
	ng := network.NewNetworkGroup()
	for _, line := range lines {
		if strings.Contains(line, "source-address") {
			parts := strings.Fields(line)
			g, err := parseAddress(parts, nat.objects)
			if err != nil {
				return err
			}
			ng.AddGroup(g)
		}
	}
	rule.Original().SetSrc(ng)

	return nil
}

// parseNatPolicyDestinationIP parses destination IP configuration
func (nat *Nats) parseNatPolicyDestinationIP(rule *NatRule, config string) error {
	lines := strings.Split(config, "\n")
	ng := network.NewNetworkGroup()
	for _, line := range lines {
		if strings.Contains(line, "destination-address") {
			parts := strings.Fields(line)
			g, err := parseAddress(parts, nat.objects)
			if err != nil {
				return err
			}
			ng.AddGroup(g)
		}
	}

	rule.Original().SetDst(ng)
	return nil
}

// parseNatPolicyService parses service configuration
func (nat *Nats) parseNatPolicyService(rule *NatRule, config string) error {
	lines := strings.Split(config, "\n")
	for _, line := range lines {
		if strings.Contains(line, "service") {
			srv, err := parsePolicyServiceLine(line, nat.objects)
			if err != nil {
				return err
			}
			rule.Original().AddService(srv)
		}
	}

	return nil
}

// func getNatType(typeStr string) firewall.NatType {
// 	switch typeStr {
// 	case "source-nat":
// 		return firewall.DYNAMIC_NAT
// 	case "destination-nat":
// 		return firewall.DESTINATION_NAT
// 	case "static":
// 		return firewall.STATIC_NAT
// 	default:
// 		panic(fmt.Sprintf("unknown NAT type: %s", typeStr))
// 	}
// }

// func (nat *Nats) parseStaticNat(ruleSet *NatRuleSet) error {
// 	rule := &NatRule{
// 		objects:     nat.objects,
// 		node:        nat.node,
// 		name:        ruleSet.name,
// 		ruleSetName: ruleSet.name,
// 		natType:     firewall.STATIC_NAT,
// 		status:      Usg_NAT_ACTIVE,
// 		orignal:     policy.NewPolicyEntry(),
// 		translate:   policy.NewPolicyEntry(),
// 	}

// 	// 定义正则表达式
// 	regexPattern := `nat\s+static\s+(\S+)\s+interface\s+([\S\s]+?)\s+global-address\s+(\S+)\s+local-address\s+(\S+)`
// 	regex := regexp.MustCompile(regexPattern)

// 	for _, line := range ruleSet.configs {
// 		matches := regex.FindStringSubmatch(line)
// 		if len(matches) != 5 {
// 			continue
// 		}

// 		// 解析接口
// 		interfaces := strings.Fields(matches[2])
// 		if len(interfaces) == 0 {
// 			return fmt.Errorf("no interfaces specified for static NAT rule: %s", ruleSet.name)
// 		}

// 		rule.from = interfaces

// 		// 解析全局地址
// 		globalAddress := matches[3]
// 		ng, err := network.NewNetworkGroupFromString(globalAddress)
// 		if err != nil {
// 			return fmt.Errorf("invalid global address: %s", globalAddress)
// 		}
// 		rule.translate.AddSrc(ng)

// 		// 解析本地地址
// 		localAddress := matches[4]
// 		ng, err = network.NewNetworkGroupFromString(localAddress)
// 		if err != nil {
// 			return fmt.Errorf("invalid local address: %s", localAddress)
// 		}
// 		rule.orignal.AddDst(ng)

// 		// 我们已经处理了主要的配置行，所以可以跳出循环
// 		break
// 	}

// 	nat.staticNatRules = append(nat.staticNatRules, rule)

// 	return nil
// }

// Helper function to find index of a string in a slice
// func indexOf(slice []string, item string) int {
// 	for i, s := range slice {
// 		if s == item {
// 			return i
// 		}
// 	}
// 	return -1
// }

// func (nat *Nats) parseSourceNat(ruleSet *NatRuleSet) error {
// 	rule := &NatRule{
// 		objects:     nat.objects,
// 		node:        nat.node,
// 		name:        ruleSet.name,
// 		ruleSetName: ruleSet.name,
// 		natType:     firewall.DYNAMIC_NAT,
// 		status:      Usg_NAT_ACTIVE,
// 		orignal:     policy.NewPolicyEntry(),
// 		translate:   policy.NewPolicyEntry(),
// 	}

// 	// 定义正则表达式
// 	regexPatterns := map[string]*regexp.Regexp{
// 		"interface":   regexp.MustCompile(`nat\s+source-nat\s+\S+\s+interface\s+(\S+)`),
// 		"src-address": regexp.MustCompile(`nat\s+source-nat\s+\S+\s+src-address\s+(any|address-object\s+\S+|address-group\s+\S+)`),
// 		"dst-address": regexp.MustCompile(`nat\s+source-nat\s+\S+\s+dst-address\s+(any|address-object\s+\S+|address-group\s+\S+)`),
// 		"service":     regexp.MustCompile(`nat\s+source-nat\s+\S+\s+service\s+(\S+)`),
// 		"action":      regexp.MustCompile(`nat\s+source-nat\s+\S+\s+action\s+(use-interface|address-pool\s+\S+)`),
// 		"port":        regexp.MustCompile(`nat\s+source-nat\s+\S+\s+port\s+(\d+)(\s+to\s+(\d+))?`),
// 	}

// 	for _, line := range ruleSet.configs {
// 		for key, regex := range regexPatterns {
// 			matches := regex.FindStringSubmatch(line)
// 			if len(matches) > 1 {
// 				switch key {
// 				case "interface":
// 					rule.from = append(rule.from, matches[1])
// 				case "src-address":
// 					ng, err := nat.parseAddress(matches[1])
// 					if err != nil {
// 						return err
// 					}
// 					rule.orignal.AddSrc(ng)
// 				case "dst-address":
// 					ng, err := nat.parseAddress(matches[1])
// 					if err != nil {
// 						return err
// 					}
// 					rule.orignal.AddDst(ng)
// 				case "service":
// 					svc, err := nat.parseService(matches[1])
// 					if err != nil {
// 						return err
// 					}
// 					rule.orignal.AddService(svc)
// 				case "action":
// 					if strings.HasPrefix(matches[1], "address-pool") {
// 						poolName := strings.TrimPrefix(matches[1], "address-pool ")
// 						pool, ok := nat.objects.Pool(poolName, rule.natType)
// 						if !ok {
// 							return fmt.Errorf("pool not found: %s", poolName)
// 						}
// 						rule.translate.AddSrc(pool.Network(nil))
// 					}
// 				case "port":
// 					startPort := matches[1]
// 					endPort := matches[3]
// 					if endPort == "" {
// 						endPort = startPort
// 					}
// 					portRange := fmt.Sprintf("%s-%s", startPort, endPort)
// 					l4port, err := service.NewL4PortFromString(portRange, 0)
// 					if err != nil {
// 						return err
// 					}
// 					svc, err := service.NewService(service.TCP, nil, l4port, 0, 0)
// 					if err != nil {
// 						return err
// 					}
// 					rule.translate.AddService(svc)
// 				}
// 				break
// 			}
// 		}
// 	}

// 	nat.sourceNatRules = append(nat.sourceNatRules, rule)
// 	return nil
// }

// func (nat *Nats) parseAddress(addrStr string) (*network.NetworkGroup, error) {
// 	ng := network.NewNetworkGroup()

// 	if addrStr == "any" {
// 		ng.AddGroup(network.NewAny4Group())
// 	} else if strings.HasPrefix(addrStr, "address-object ") {
// 		objName := strings.TrimPrefix(addrStr, "address-object ")
// 		_, obj, ok := nat.objects.Network("", objName)
// 		if !ok {
// 			return nil, fmt.Errorf("address object not found: %s", objName)
// 		}
// 		ng.AddGroup(obj)
// 	} else if strings.HasPrefix(addrStr, "address-group ") {
// 		groupName := strings.TrimPrefix(addrStr, "address-group ")
// 		_, group, ok := nat.objects.Network("", groupName)
// 		if !ok {
// 			return nil, fmt.Errorf("address group not found: %s", groupName)
// 		}
// 		ng.AddGroup(group)
// 	} else {
// 		return nil, fmt.Errorf("invalid address format: %s", addrStr)
// 	}

// 	return ng, nil
// }

// func (nat *Nats) parseService(svcStr string) (*service.Service, error) {
// 	if svcStr == "any" {
// 		return service.NewServiceFromString("ip")
// 	}

// 	_, svc, ok := nat.objects.Service(svcStr)
// 	if !ok {
// 		return nil, fmt.Errorf("service not found: %s", svcStr)
// 	}

// 	return svc, nil
// }

// // nat destination-nat DCN_SSLVPN_TEST05 interface bond12 global-address 1.1.1.1 service ftp http tcp 8888 tcp 1000 to 1003 local-address 132.252.138.226 to 132.252.138.226 local-port 5555
// func (nat *Nats) parseDestinationNat(ruleSet *NatRuleSet) error {
// 	rule := &NatRule{
// 		objects:     nat.objects,
// 		node:        nat.node,
// 		name:        ruleSet.name,
// 		ruleSetName: ruleSet.name,
// 		natType:     firewall.DESTINATION_NAT,
// 		status:      Usg_NAT_ACTIVE,
// 		orignal:     policy.NewPolicyEntry(),
// 		translate:   policy.NewPolicyEntry(),
// 	}

// 	regexMap := map[string]string{
// 		"regex": `
//             nat\s+destination-nat\s+(?P<name>\S+)\s+
//             interface\s+(?P<ports>[\S\s]+?)\s+
//             global-address\s+ ((?P<global_address>\S+) | (address-pool\s+(?P<pool>\S+))) \s+
//             (service\s+(?P<services>[\S\s]+?)\s+)?
//             local-address\s+(?P<local_start>\S+)(\s+to\s+(?P<local_end>\S+))?\s+
//             local-port\s+(?P<local_port>\S+)
//         `,
// 		"name":  "dnat",
// 		"flags": "mx",
// 		"pcre":  "true",
// 	}

// 	for _, line := range ruleSet.configs {
// 		result, err := text.SplitterProcessOneTime(regexMap, line)
// 		if err != nil {
// 			return fmt.Errorf("failed to process regex: %v", err)
// 		}

// 		dnatMap, ok := result.One()
// 		if !ok {
// 			return fmt.Errorf("failed to match regex")
// 		}

// 		// Parse interfaces
// 		rule.from = strings.Fields(dnatMap["ports"])

// 		// Parse global address
// 		// Parse global address or address pool
// 		var globalNG *network.NetworkGroup
// 		// var err error

// 		if dnatMap["global_address"] != "" {
// 			globalNG, err = network.NewNetworkGroupFromString(dnatMap["global_address"])
// 			if err != nil {
// 				return fmt.Errorf("invalid global address: %s", dnatMap["global_address"])
// 			}
// 		} else if dnatMap["address_pool"] != "" {
// 			poolName := dnatMap["address_pool"]
// 			pool, ok := nat.objects.Pool(poolName, rule.natType)
// 			if !ok {
// 				return fmt.Errorf("address pool not found: %s", poolName)
// 			}
// 			globalNG = pool.Network(nil)
// 		} else {
// 			return fmt.Errorf("neither global address nor address pool specified")
// 		}
// 		rule.orignal.AddDst(globalNG)

// 		// ftp https http telnet smtp icmp
// 		// ftp http tcp 8888 tcp 1000 to 1003
// 		// protocol 123 udp 53
// 		// Parse services
// 		if dnatMap["services"] != "" {
// 			svc, err := nat.parseDnatService(dnatMap["services"])
// 			if err != nil {
// 				return err
// 			}
// 			rule.orignal.AddService(svc)
// 		}

// 		// Parse local address
// 		localStart := dnatMap["local_start"]
// 		localEnd := dnatMap["local_end"]
// 		var localAddress string
// 		if localEnd != "" {
// 			localAddress = localStart + "-" + localEnd
// 		} else {
// 			localAddress = localStart
// 		}
// 		localNG, err := network.NewNetworkGroupFromString(localAddress)
// 		if err != nil {
// 			return fmt.Errorf("invalid local address: %s", localAddress)
// 		}
// 		rule.translate.AddDst(localNG)

// 		// Parse local port
// 		localPort := dnatMap["local_port"]
// 		l4port, err := service.NewL4PortFromString(localPort, 0)
// 		if err != nil {
// 			return fmt.Errorf("invalid local port: %s", localPort)
// 		}
// 		svc, err := service.NewService(service.TCP, nil, l4port, 0, 0)
// 		if err != nil {
// 			return err
// 		}
// 		rule.translate.AddService(svc)

// 		// Add the rule to the ruleSet
// 		nat.destinationNatRules = append(nat.destinationNatRules, rule)

// 		// We've successfully parsed a DNAT rule, so we can break the loop
// 		break
// 	}

// 	return nil
// }

// func (nat *Nats) parseDeactive(config string) {
// 	deactiveRegexMap := map[string]string{
// 		"regex": `(?P<all>deactivate security nat (?P<natType>\S+) rule-set (?P<name>\S+) rule (?P<rule>\S+))`,
// 		"name":  "deactive",
// 		"flags": "m",
// 		"pcre":  "true",
// 	}

// 	deactiveResult, err := text.SplitterProcessOneTime(deactiveRegexMap, config)
// 	if err != nil {
// 		panic(err)
// 	}

// 	for it := deactiveResult.Iterator(); it.HasNext(); {
// 		_, _, deactiveMap := it.Next()
// 		natType := StringToNatType(deactiveMap["natType"])
// 		rule, ok := nat.NatRule(natType, deactiveMap["name"], deactiveMap["rule"])
// 		if !ok {
// 			panic(fmt.Sprint("get nat ruel faild, deactiveMap: ", deactiveMap))
// 		}
// 		rule.status = Usg_NAT_INACTIVE
// 		rule.cli += "\n" + deactiveMap["all"]
// 	}
// }

// func (nat *Nats) parseRuleSet(config string) []string {
// 	sectionRegexMap := map[string]string{
// 		"regex": `(?P<all>set security nat (?P<type>\S+) rule-set (?P<ruleSet>\S+) [^\n]+)`,
// 		"name":  "section",
// 		"flags": "m",
// 		"pcre":  "true",
// 	}

// 	sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, config)
// 	if err != nil {
// 		panic(err)
// 	}

// 	sections, err := sectionResult.CombinKey([]string{"type", "ruleSet"})
// 	if err != nil {
// 		panic(err)
// 	}

// 	return sections
// }

// func (nat *Nats) parseDnatService(serviceStr string) (*service.Service, error) {
// 	s := &service.Service{}
// 	services := strings.Fields(serviceStr)

// 	// 处理预定义服务
// 	predefinedServices := map[string]bool{
// 		"ftp": true, "http": true, "https": true, "smtp": true, "telnet": true,
// 	}

// 	var customServices []string

// 	for i := 0; i < len(services); i++ {
// 		if predefinedServices[services[i]] {
// 			svc, ok := UsgBuiltinService(services[i])
// 			if !ok {
// 				return nil, fmt.Errorf("predefined service not found: %s", services[i])
// 			}
// 			s.Add(svc)
// 		} else {
// 			customServices = append(customServices, services[i])
// 		}
// 	}

// 	// 处理自定义服务
// 	if len(customServices) > 0 {
// 		customServiceStr := strings.Join(customServices, " ")
// 		customServiceStr = strings.ReplaceAll(customServiceStr, " to ", "-")
// 		parts := strings.Split(customServiceStr, " ")

// 		var result []string
// 		for i := 0; i < len(parts); i++ {
// 			if i+1 < len(parts) && (parts[i] == "tcp" || parts[i] == "udp") {
// 				result = append(result, fmt.Sprintf("%s:%s", parts[i], parts[i+1]))
// 				i++
// 			} else {
// 				result = append(result, parts[i])
// 			}
// 		}

// 		customServiceStr = strings.Join(result, ";")
// 		customSvc, err := service.NewServiceFromString(customServiceStr)
// 		if err != nil {
// 			return nil, err
// 		}
// 		s.Add(customSvc)
// 	}

// 	return s, nil
// }

// func (nat *Nats) parseNatInfo(config string) (natType firewall.NatType, from, to *UsgPort, name string) {
// 	infoRegexMap := map[string]string{
// 		"regex": `set security nat (?P<natType>\S+) rule-set (?P<ruleSet>\S+) (from zone (?P<from>\S+))|(to zone (?P<to>\S+))`,
// 		"name":  "info",
// 		"flags": "m",
// 		"pcre":  "true",
// 	}

// 	infoResult, err := text.SplitterProcessOneTime(infoRegexMap, config)
// 	if err != nil {
// 		panic(err)
// 	}

// 	infoMap, err := infoResult.Projection([]string{}, ",", nil)
// 	if err != nil {
// 		panic(err)
// 	}

// 	if infoMap["natType"] == "static" {
// 		natType = firewall.STATIC_NAT
// 	} else if infoMap["natType"] == "source" {
// 		natType = firewall.DYNAMIC_NAT
// 	} else {
// 		natType = firewall.DESTINATION_NAT
// 	}

// 	from = nat.node.GetPort(infoMap["from"]).(*UsgPort)
// 	if infoMap["to"] != "" {
// 		to = nat.node.GetPort(infoMap["to"]).(*UsgPort)
// 	}

// 	name = infoMap["ruleSet"]

// 	return
// }

// func (nat *Nats) parseSection(config string) []string {

// 	sectionRegexMap := map[string]string{
// 		"regex": `(?P<all>set security nat (?P<type>\S+) rule-set (?P<ruleSet>\S+) rule (?P<name>\S+) [^\n]+)`,
// 		"name":  "section",
// 		"flags": "m",
// 		"pcre":  "true",
// 	}

// 	sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, config)
// 	if err != nil {
// 		panic(err)
// 	}

// 	sections, err := sectionResult.CombinKey([]string{"type", "ruleSet", "name"})
// 	if err != nil {
// 		panic(err)
// 	}
// 	return sections
// }

// func (rule *NatRule) parseNat(config string, natType firewall.NatType, from, to *UsgPort) {
// 	rule.natType = natType
// 	rule.cli = config

// 	natRegexMap := map[string]string{
// 		"regex": `
// 			set\ssecurity\snat\s(?P<direct>\S+)\srule-set\s(?P<rule_set_name>\S+)\srule\s(?P<name>\S+)\s
// 			(
// 				(
// 					(match\s
// 						(
// 							(
// 								source-address\s(?P<src_addr>\S+)
// 							) |
// 							(
// 								source-address-name\s(?P<src_addr_name>\S+)
// 							) |
// 							(
// 								protocol\s(?P<protocol>\S+)
// 							) |
// 							(
// 								destination-address\s(?P<dst_addr>\S+)
// 							) |
// 							(
// 								destination-address-name\s(?P<dst_addr_name>\S+)
// 							) |
// 							(
// 								destination-port\s(to\s(?P<dport2>\S+))
// 							) |
// 							(
// 								destination-port\s(?P<dport>\S+)(\sto\s(?P<_dport2>\S+))?
// 							) |
// 							(
// 								destination-port\s(to\s(?P<sport2>\S+))
// 							) |
// 							(
// 								source-port\s(?P<sport>\S+)(\sto\s(?P<_sport2>\S+))?
// 							)
// 						)
// 					) |
// 					(then\s
// 						(
// 							(source-nat\s
// 								(
// 									(?P<snat_off>off) |
// 									(?P<interface>interface) |
// 									(pool\s(?P<snat_pool>\S+))
// 								)
// 							) |
// 							(destination-nat\s
// 								(
// 									(?P<dnat_off>off) |
// 									(pool\s(?P<dnat_pool>\S+))
// 								)
// 							) |
// 							(static-nat\s
// 								(
// 									(prefix\s
// 										(
// 											(?P<static_nat_prefix>[\d\.\/]+) |
// 											(mapped-port\s
// 												(
// 													(to\s(?P<mapped_port2>\d+)) |
// 													(?P<mapped_port>\d+)
// 												)
// 											)
// 										)
// 									) |
// 									(prefix-name\s(?P<static_nat_prefix_name>\S+))
// 								)
// 							)
// 						)
// 					)
// 				)
// 			)
// 		`,
// 		"name":  "nat",
// 		"flags": "mx",
// 		"pcre":  "true",
// 	}

// 	// for _, section := range sections {
// 	natResult, err := text.SplitterProcessOneTime(natRegexMap, config)
// 	if err != nil {
// 		panic(err)
// 	}

// 	natMap, err := natResult.Projection(
// 		[]string{"src_addr", "src_addr_name", "protocol", "dst_addr", "dst_addr_name", "dport", "sport"},
// 		",",
// 		[][]string{
// 			[]string{
// 				"dport", "_dport2",
// 			},
// 			[]string{
// 				"sport", "_sport2",
// 			},
// 		})
// 	if err != nil {
// 		panic(err)
// 	}

// 	// 针对protocol和端口都设置的情况，需要进行进一步测试

// 	realService := &service.Service{}
// 	if natMap["protocol"] != "" {
// 		ps := strings.Split(natMap["protocol"], ",")
// 		for _, p := range ps {
// 			protocol, err := UsgParseProtocol(p)
// 			if err != nil {
// 				panic(err)
// 			}
// 			l3, err := service.NewL3Protocol(service.IPProto(protocol))
// 			if err != nil {
// 				panic(err)
// 			}
// 			realService.Add(l3)
// 		}
// 	}

// 	var realSrcL4Port, realDstL4Port *service.L4Port
// 	if natMap["sport"] != "" {
// 		if natMap["sport2"] != "" {

// 			realSrcL4Port, err = service.NewL4PortFromString(natMap["sport"]+"-"+natMap["sport2"], 0)
// 		} else {
// 			realSrcL4Port, err = service.NewL4PortFromString(natMap["sport"], 0)
// 		}
// 		if err != nil {
// 			panic(err)
// 		}
// 	}

// 	if natMap["dport"] != "" {
// 		if natMap["dport2"] != "" {
// 			realDstL4Port, err = service.NewL4PortFromString(natMap["dport"]+"-"+natMap["dport2"], 0)
// 		} else {
// 			realDstL4Port, err = service.NewL4PortFromString(natMap["dport"], 0)
// 		}

// 		if err != nil {
// 			panic(err)
// 		}
// 	}

// 	realSrc := network.NewNetworkGroup()
// 	realDst := network.NewNetworkGroup()

// 	// if natMap["realSrc_addr"] != "" {
// 	if natMap["src_addr"] != "" {
// 		// ng, err := network.NewNetworkGroupFromString(natMap["realSrc_addr"])
// 		ng, err := network.NewNetworkGroupFromString(natMap["src_addr"])
// 		if err != nil {
// 			panic(err)
// 		}
// 		realSrc.AddGroup(ng)
// 	}

// 	// if natMap["realSrc_addr_name"] != "" {
// 	if natMap["src_addr_name"] != "" {
// 		// names := strings.Split(natMap["realSrc_addr_name"], ",")
// 		names := strings.Split(natMap["src_addr_name"], ",")
// 		for _, name := range names {
// 			ng, ok := rule.objects.Network(from.Zone(), name)
// 			if !ok {
// 				panic(fmt.Sprint(natMap))
// 			}

// 			realSrc.AddGroup(ng)
// 		}
// 	}

// 	// if natMap["realDst_addr"] != "" {
// 	if natMap["dst_addr"] != "" {
// 		// ng, err := network.NewNetworkGroupFromString(natMap["realDst_addr"])
// 		ng, err := network.NewNetworkGroupFromString(natMap["dst_addr"])
// 		if err != nil {
// 			panic(err)
// 		}
// 		realDst.AddGroup(ng)
// 	}

// 	// if natMap["realDst_addr_name"] != "" {
// 	if natMap["dst_addr_name"] != "" {
// 		// names := strings.Split(natMap["realDst_addr_name"], ",")
// 		names := strings.Split(natMap["dst_addr_name"], ",")
// 		for _, name := range names {
// 			ng, ok := rule.objects.Network(from.Zone(), name)
// 			if !ok {
// 				panic(fmt.Sprint(natMap))
// 			}

// 			realDst.AddGroup(ng)
// 		}
// 	}

// 	if realSrcL4Port != nil || realDstL4Port != nil {
// 		stcp, err := service.NewL4Service(service.IPProto(6), realSrcL4Port, realDstL4Port)
// 		if err != nil {
// 			panic(err)
// 		}

// 		realService.Add(stcp)

// 		sudp, err := service.NewL4Service(service.IPProto(17), realSrcL4Port, realDstL4Port)
// 		if err != nil {
// 			panic(err)
// 		}

// 		realService.Add(sudp)
// 	}

// 	mappedSrc := network.NewNetworkGroup()
// 	mappedDst := network.NewNetworkGroup()
// 	mappedService := &service.Service{}

// 	if natMap["interface"] != "" {
// 		ipv4 := to.Ipv4List()
// 		ipv6 := to.Ipv6List()
// 		if realSrc.IsIPv4() {
// 			if len(ipv4) > 0 {
// 				net, err := network.NewNetworkGroupFromString(strings.Join(ipv4, ","))
// 				if err != nil {
// 					panic(err)
// 				}
// 				// net, _ = network.ParseIPNet(net.IP.String())
// 				mappedSrc.AddGroup(net)
// 			}
// 		}
// 		if realSrc.IsIPv6() {
// 			if len(ipv6) > 0 {
// 				net, err := network.NewNetworkGroupFromString(strings.Join(ipv6, ","))
// 				if err != nil {
// 					panic(err)
// 				}
// 				// net, _ = network.ParseIPNet(net.IP.String())
// 				mappedSrc.AddGroup(net)
// 			}
// 		}
// 	}

// 	if natMap["snat_pool"] != "" {
// 		obj, ok := rule.objects.Pool(natMap["snat_pool"], rule.natType)
// 		pool, ok := obj.(*NatPool)
// 		if !ok {
// 			panic(fmt.Sprint("get nat pool failed: ", natMap["snat_pool"]))
// 		}
// 		ng := pool.Network(nil)
// 		mappedSrc.AddGroup(ng)
// 		if pool.L4Port() != nil {
// 			s1, err := service.NewL4Service(service.IPProto(6), pool.L4Port(), nil)
// 			if err != nil {
// 				panic(err)
// 			}
// 			mappedService.Add(s1)
// 			s2, err := service.NewL4Service(service.IPProto(17), pool.L4Port(), nil)
// 			if err != nil {
// 				panic(err)
// 			}
// 			mappedService.Add(s2)
// 		}
// 	}

// 	if natMap["dnat_pool"] != "" {
// 		obj, ok := rule.objects.Pool(natMap["dnat_pool"], rule.natType)
// 		pool, ok := obj.(*NatPool)
// 		if !ok {
// 			panic(fmt.Sprint("get nat pool failed: ", natMap["dnat_pool"], rule.natType))
// 		}
// 		ng := pool.Network(nil)
// 		mappedSrc.AddGroup(ng)
// 		if pool.L4Port() != nil {
// 			s1, err := service.NewL4Service(service.IPProto(6), nil, pool.L4Port())
// 			if err != nil {
// 				panic(err)
// 			}
// 			mappedService.Add(s1)
// 			s2, err := service.NewL4Service(service.IPProto(17), nil, pool.L4Port())
// 			if err != nil {
// 				panic(err)
// 			}
// 			mappedService.Add(s2)
// 		}
// 	}

// 	if natMap["static_nat_prefix"] != "" {
// 		ng, err := network.NewNetworkGroupFromString(natMap["static_nat_prefix"])
// 		if err != nil {
// 			panic(err)
// 		}
// 		mappedDst.AddGroup(ng)

// 		if natMap["mapped_port"] != "" {
// 			var l4port *service.L4Port
// 			if natMap["mapped_port2"] != "" {
// 				l4port, err = service.NewL4PortFromString(natMap["mapped_port"]+"-"+natMap["mapped_port2"], 0)
// 			} else {
// 				l4port, err = service.NewL4PortFromString(natMap["mapped_port"], 0)
// 			}

// 			if err != nil {
// 				panic(err)
// 			}
// 			s1, err := service.NewL4Service(service.TCP, nil, l4port)
// 			if err != nil {
// 				panic(err)
// 			}

// 			mappedService.Add(s1)
// 			s2, err := service.NewL4Service(service.UDP, nil, l4port)
// 			if err != nil {
// 				panic(err)
// 			}

// 			mappedService.Add(s2)
// 		}
// 	}

// 	if natMap["static_nat_prefix_name"] != "" {
// 		ng, ok := rule.objects.Network(to.Zone(), natMap["static_nat_prefix_name"])
// 		if !ok {
// 			panic(fmt.Sprint("get static nat prefix name failed: ", natMap["static_nat_prefix_name"]))
// 		}
// 		mappedDst.AddGroup(ng)
// 	}

// 	// rule.from = from
// 	// rule.to = to
// 	rule.name = natMap["name"]
// 	rule.ruleSetName = natMap["rule_set_name"]
// 	rule.orignal = policy.NewPolicyEntry()
// 	rule.orignal.AddSrc(realSrc)
// 	rule.orignal.AddDst(realDst)
// 	rule.orignal.AddService(realService)

// 	rule.translate = policy.NewPolicyEntry()
// 	rule.translate.AddSrc(mappedSrc)
// 	rule.translate.AddDst(mappedDst)
// 	rule.translate.AddService(mappedService)

// 	rule.status = Usg_NAT_ACTIVE

// }

func StringToNatType(natType string) firewall.NatType {
	switch natType {
	case "source":
		return firewall.DYNAMIC_NAT
	case "static":
		return firewall.STATIC_NAT

	case "destination":
		return firewall.DESTINATION_NAT
	default:
		panic(fmt.Sprint("unsupport nat type: ", natType))
	}

}

func (rule *NatRule) natTranslate(from, to string, fromPort, toPort string, entry *policy.Intent, isInputNat bool) (bool, policy.PolicyEntryInf) {
	switch rule.natType {
	case firewall.STATIC_NAT:
		if isInputNat {
			// 入向匹配
			if tools.Contains(rule.toPorts, fromPort) || tools.Contains(rule.to, from) {
				reverse := rule.orignal.Reverse()
				ok, translateTo, msg := entry.Translate(reverse)
				if !ok {
					panic(msg)
				}
				return true, entry.NewIntentWithTicket(translateTo)
			}
		} else {
			// 出向匹配
			if tools.Contains(rule.toPorts, toPort) || tools.Contains(rule.to, to) {
				ok, translateTo, msg := entry.Translate(rule.translate)
				if !ok {
					panic(msg)
				}
				return true, entry.NewIntentWithTicket(translateTo)
			}
		}
		return false, nil

	case firewall.DESTINATION_NAT:
		if isInputNat {
			// DNAT 通常用于入向流量
			if tools.Contains(rule.fromPorts, fromPort) || tools.Contains(rule.from, from) {
				ok, translateTo, msg := entry.Translate(rule.translate)
				if !ok {
					panic(msg)
				}
				return true, entry.NewIntentWithTicket(translateTo)
			}
		}
		return false, nil

	default: // DYNAMIC_NAT or other types
		if !isInputNat {
			// SNAT 通常用于出向流量
			if tools.Contains(rule.toPorts, toPort) || tools.Contains(rule.to, to) {
				ok, translateTo, msg := entry.Translate(rule.translate)
				if !ok {
					panic(msg)
				}
				return true, entry.NewIntentWithTicket(translateTo)
			}
		}
		return false, nil
	}
}

// func (rule *NatRule) natTranslate(from, to string, fromPort, toPort string, entry *policy.Intent) (bool, policy.PolicyEntryInf) {
// 	switch rule.natType {
// 	case firewall.STATIC_NAT:
// 		if tools.Contains(rule.fromPorts, fromPort) || tools.Contains(rule.from, from) {
// 			ok, translateTo, msg := entry.Translate(rule.translate)
// 			if !ok {
// 				panic(msg)
// 			}
// 			return true, entry.NewIntentWithTicket(translateTo)
// 		} else {
// 			reverse := rule.orignal.Reverse()
// 			ok, translateTo, msg := entry.Translate(reverse)
// 			if !ok {
// 				panic(msg)
// 			}
// 			return true, entry.NewIntentWithTicket(translateTo)
// 		}

// 	default: // DYNAMIC_NAT or other types
// 		ok, translateTo, msg := entry.Translate(rule.translate)
// 		if !ok {
// 			panic(msg)
// 		}
// 		return true, entry.NewIntentWithTicket(translateTo)
// 	}

// }

// func (rule *NatRule) natTranslate(from, to string, entry *policy.Intent) (bool, policy.PolicyEntryInf) {
// 	// state := rule.match(from, to, entry)
// 	// if state == Usg_NAT_MATCH_NONE || state == Usg_NAT_MATCH_NOT_OK {
// 	// return false, nil
// 	// }
// 	if rule.natType == firewall.STATIC_NAT {
// 		if tools.Contains(rule.from, from) {
// 			ok, tranlateTo, msg := entry.Translate(rule.translate)
// 			if !ok {
// 				panic(msg)
// 			}

// 			return true, entry.NewIntentWithTicket(tranlateTo)

// 		} else {
// 			reverse := rule.orignal.Reverse()
// 			ok, tranlateTo, msg := entry.Translate(reverse)
// 			if !ok {
// 				panic(msg)
// 			}
// 			return true, entry.NewIntentWithTicket(tranlateTo)
// 		}
// 	} else {
// 		ok, tranlateTo, msg := entry.Translate(rule.translate)
// 		if !ok {
// 			panic(msg)
// 		}

// 		return true, entry.NewIntentWithTicket(tranlateTo)
// 	}
// }

// func (rule *NatRule) matchDnatTarget(entry policy.PolicyEntryInf) bool {
// 	if rule.natType == firewall.DYNAMIC_NAT {
// 		return false
// 	}

// 	// reverse := entry.Reverse()
// 	if rule.translate.Match(entry) {
// 		return true
// 	}

// 	return false
// }

func (rule *NatRule) match(from, to string, entry policy.PolicyEntryInf) UsgNatMatchState {
	if rule.status == Usg_NAT_INACTIVE {
		return Usg_NAT_MATCH_NONE
	}

	if rule.orignal.Dst() == nil || rule.orignal.Dst().Count().Cmp(big.NewInt(0)) == 0 {
		return Usg_NAT_MATCH_NONE
	}

	if rule.orignal.Match(entry) {
		return Usg_NAT_MATCH_OK
	} else {
		return Usg_NAT_MATCH_NOT_OK
	}
}

func (rule *NatRule) reverseMatch(from, to string, entry policy.PolicyEntryInf) UsgNatMatchState {
	if rule.status == Usg_NAT_INACTIVE {
		return Usg_NAT_MATCH_NONE
	}

	if rule.translate.Dst() == nil || rule.translate.Dst().Count().Cmp(big.NewInt(0)) == 0 {
		return Usg_NAT_MATCH_NONE
	}

	if rule.translate.Src() == nil || rule.translate.Src().Count().Cmp(big.NewInt(9)) == 0 {
		return Usg_NAT_MATCH_NONE
	}

	fmt.Println("1. translate reverse to: ", rule.translate.Reverse().String())
	fmt.Println("2. input entry", entry.String())

	if rule.translate.Reverse().Match(entry) {
		return Usg_NAT_MATCH_OK
	} else {
		return Usg_NAT_MATCH_NOT_OK
	}

}

// func (nat *Nats) inputNat(intent *policy.Intent, inPort api.Port) (bool, *policy.Intent, *NatRule) {

// 	// func (ns *NatRuleSet) match(natType firewall.NatType, from, to string, entry *policy.Intent) (*NatRule, bool) {
// 	for _, rules := range [][]*NatRule{nat.natServers, nat.staticNatRules, nat.destinationNatRules} {
// 		for _, rule := range rules {
// 			if state := rule.match(inPort.(*UsgPort).Zone(), "", intent); state == Usg_NAT_MATCH_OK {
// 				ok, translateTo := rule.natTranslate(inPort.(*UsgPort).Zone(), "", intent)
// 				return ok, translateTo.(*policy.Intent), rule
// 			}
// 		}
// 	}

// 	return false, nil, nil
// }

func (nat *Nats) inputNat(intent *policy.Intent, inPort api.Port) (bool, *policy.Intent, *NatRule) {
	inZone := inPort.(*UsgPort).Zone()
	inPortName := inPort.Name()

	for _, rules := range [][]*NatRule{nat.natServers, nat.staticNatRules, nat.destinationNatRules} {
		for _, rule := range rules {
			var matchState UsgNatMatchState

			switch rule.natType {
			case firewall.STATIC_NAT, firewall.DESTINATION_NAT:
				// 对于静态NAT和目标NAT，我们使用translate的反向匹配
				matchState = rule.reverseMatch(inZone, "", intent)
				// case firewall.DYNAMIC_NAT:
				// 	// 对于动态NAT，我们使用正常的匹配
				// 	matchState = rule.match(inZone, "", intent)
			}

			if matchState == Usg_NAT_MATCH_OK {
				// 检查端口匹配
				if !matchPortOrZone(inPortName, inZone, rule.toPorts, rule.to) {
					continue
				}

				// var ok bool
				// var translateTo policy.PolicyEntryInf

				if rule.natType == firewall.STATIC_NAT || rule.natType == firewall.DESTINATION_NAT {
					// if ok {
					ok, translateTo := rule.natTranslate(inPort.(*UsgPort).Zone(), inPort.Name(), "", "", intent, true)
					if !ok || translateTo == nil {
						continue
					}
					fmt.Println("translateTo: ", translateTo.String())
					if intentResult, ok := translateTo.(*policy.Intent); ok {
						return true, intentResult, rule
					}
				}
			}
		}
	}

	// 单独处理 natPolicyRules
	for _, rule := range nat.natPolicyRules {
		matchState := rule.match(inZone, "", intent)
		if matchState == Usg_NAT_MATCH_OK {
			if !matchPortOrZone(inPortName, inZone, rule.fromPorts, rule.from) {
				continue
			}
			ok, translateTo := rule.natTranslate(inZone, inPortName, "", "", intent, true)
			if ok {
				return ok, translateTo.(*policy.Intent), rule
			}
		}
	}

	return false, nil, nil
}

// matchPortOrZone checks if the given port name or zone matches any of the rule's ports or zones
func matchPortOrZone(portName, zone string, rulePorts, ruleZones []string) bool {
	// First, check if the port name matches any of the rule's ports
	for _, rulePort := range rulePorts {
		if rulePort == portName {
			return true
		}
	}

	// If port name doesn't match, check if the zone matches any of the rule's zones
	for _, ruleZone := range ruleZones {
		if ruleZone == zone {
			return true
		}
	}

	// If neither port name nor zone matches, check if "any" is specified in the rule
	for _, ruleZone := range ruleZones {
		if ruleZone == "any" {
			return true
		}
	}

	// If no match is found, return false
	return false
}

func (nat *Nats) outputNat(intent *policy.Intent, inPort, outPort api.Port) (bool, *policy.Intent, *NatRule) {
	for _, rule := range nat.natServers {
		state := rule.match(inPort.(*UsgPort).Zone(), outPort.(*UsgPort).Zone(), intent)
		if state == Usg_NAT_MATCH_OK {
			ok, translateTo := rule.natTranslate(inPort.(*UsgPort).Zone(), outPort.(*UsgPort).Zone(), inPort.Name(), outPort.Name(), intent, false)
			return ok, translateTo.(*policy.Intent), rule
		}

	}

	for _, rule := range nat.natPolicyRules {
		state := rule.match(inPort.(*UsgPort).Zone(), outPort.(*UsgPort).Zone(), intent)
		if state == Usg_NAT_MATCH_OK {
			ok, translateTo := rule.natTranslate(inPort.(*UsgPort).Zone(), outPort.(*UsgPort).Zone(), inPort.Name(), outPort.Name(), intent, false)
			return ok, translateTo.(*policy.Intent), rule
		}
	}

	return false, nil, nil
}

// func (nat *Nats) inputNatTargetCheck(intent *policy.Intent, inPort, outPort api.Port) (bool, *NatRule) {
// 	target := intent.GenerateIntentPolicyEntry()
// 	for _, rules := range [][]*NatRule{nat.staticNatRules, nat.destinationNatRules} {
// 		for _, rule := range rules {
// 			ok := rule.matchDnatTarget(target)
// 			return ok, rule
// 		}
// 	}
// 	return false, nil
// }

// func (nats *Nats) FindRuleSet(inPort, outPort api.Port, natType firewall.NatType) *NatRuleSet {
// 	switch natType {
// 	case firewall.DYNAMIC_NAT:
// 		for _, ruleSet := range nats.sourceNatRules {
// 			if ruleSet.from.Zone() == inPort.(*UsgPort).Zone() && ruleSet.to.Zone() == outPort.(*UsgPort).Zone() {
// 				return ruleSet
// 			}
// 		}
// 	case firewall.STATIC_NAT, firewall.DESTINATION_NAT:
// 		for _, ruleSet := range nats.staticNatRules {
// 			if ruleSet.from.Zone() == inPort.(*UsgPort).Zone() {
// 				return ruleSet
// 			}
// 		}
// 	}
// 	return nil
// }

// getConfigPreview 返回配置的前N个字符，用于调试
func getConfigPreview(config string, maxLen int) string {
	if len(config) <= maxLen {
		return config
	}
	return config[:maxLen] + "..."
}

func init() {
	// registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallNatRule)(nil)).Elem(), "UsgNatRule", reflect.TypeOf(NatRule{}))
}

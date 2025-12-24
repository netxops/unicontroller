package forti

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/fw/forti/dto"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/forti/templates"
	"github.com/netxops/utils/registry"
	"github.com/netxops/utils/service"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
)

type FortigateNatStatus int

// const (
// Fortigate_NAT_ACTIVE FortigateNatStatus = iota
// Fortigate_NAT_INACTIVE
// )

type NatRule struct {
	objects *FortiObjectSet
	name    string
	node    *FortigateNode
	from    string
	to      string
	extIntf string
	natType firewall.NatType
	cli     string
	status  firewall.NatStatus
	//afterAuto bool
	objMap dto.ForiRespResult
	// status    FortigateNatStatus
	orignal   policy.PolicyEntryInf
	translate policy.PolicyEntryInf
}

// TypeName 实现 TypeInterface 接口
func (nr *NatRule) TypeName() string {
	return "FortiNatRule"
}

// natRuleJSON 用于序列化和反序列化
type natRuleJSON struct {
	Name      string                `json:"name"`
	From      string                `json:"from"`
	To        string                `json:"to"`
	ExtIntf   string                `json:"ext_intf"`
	NatType   firewall.NatType      `json:"nat_type"`
	Cli       string                `json:"cli"`
	Status    firewall.NatStatus    `json:"status"`
	ObjMap    dto.ForiRespResult    `json:"obj_map"`
	Orignal   policy.PolicyEntryInf `json:"orignal"`
	Translate policy.PolicyEntryInf `json:"translate"`
}

// MarshalJSON 实现 JSON 序列化
func (nr *NatRule) MarshalJSON() ([]byte, error) {
	return json.Marshal(natRuleJSON{
		Name:      nr.name,
		From:      nr.from,
		To:        nr.to,
		ExtIntf:   nr.extIntf,
		NatType:   nr.natType,
		Cli:       nr.cli,
		Status:    nr.status,
		ObjMap:    nr.objMap,
		Orignal:   nr.orignal,
		Translate: nr.translate,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (nr *NatRule) UnmarshalJSON(data []byte) error {
	var nrj natRuleJSON
	if err := json.Unmarshal(data, &nrj); err != nil {
		return err
	}

	nr.name = nrj.Name
	nr.from = nrj.From
	nr.to = nrj.To
	nr.extIntf = nrj.ExtIntf
	nr.natType = nrj.NatType
	nr.cli = nrj.Cli
	nr.status = nrj.Status
	nr.objMap = nrj.ObjMap
	nr.orignal = nrj.Orignal
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

func (rule *NatRule) matchDnatTarget(entry policy.PolicyEntryInf) bool {
	// 为了理解方便，其实就是Intent的RealIp+RealPort，能匹配已有的STATIC_NAT策略
	if rule.natType == firewall.DYNAMIC_NAT {
		return false
	}

	reverse := entry.Reverse()
	if rule.orignal.Match(reverse) {
		return true
	}

	return false
}

func (rule *NatRule) Extended() map[string]interface{} {
	return map[string]interface{}{
		"extIntf": rule.extIntf,
	}
}

func (rule *NatRule) match(from, to string, entry policy.PolicyEntryInf) firewall.NatMatchState {
	if rule.status == firewall.NAT_INACTIVE {
		return firewall.NAT_MATCH_NONE
	}

	if rule.natType == firewall.STATIC_NAT {
		if rule.from != "" && rule.to != "" {
			if from != rule.from && from != rule.to {
				return firewall.NAT_MATCH_NONE
			}
		}

		if to == "" {
			// 对于入向 NAT，如果 rule.from 为空，表示匹配任何源接口
			if rule.from == "" || from == rule.from || rule.to == "any" {
				if rule.orignal.Dst().Count().Cmp(big.NewInt(0)) == 0 {
					return firewall.NAT_MATCH_NONE
				}

				if rule.orignal.Match(entry) {
					return firewall.NAT_MATCH_OK
				} else {
					return firewall.NAT_MATCH_NOT_OK
				}
			} else if from == rule.to || rule.to == "any" {
				reverse := rule.translate.Reverse()
				if reverse.Match(entry) {
					return firewall.NAT_MATCH_OK
				} else {
					return firewall.NAT_MATCH_NOT_OK
				}
			} else {
				return firewall.NAT_MATCH_NONE
			}
		} else {
			if from == rule.from && to == rule.to {
			} else if from == rule.from && rule.to == "any" {
			} else if rule.from == "any" && to == rule.to {
			} else if rule.from == "any" && rule.to == "any" {
			} else {
				return firewall.NAT_MATCH_NONE
			}

			if rule.orignal.Match(entry) {
				return firewall.NAT_MATCH_OK
			} else {
				return firewall.NAT_MATCH_NOT_OK
			}
		}
	} else {
		if (from == rule.from || rule.from == "any") && (to == rule.to || rule.to == "any") {
			if rule.orignal.Match(entry) {
				return firewall.NAT_MATCH_OK
			} else {
				return firewall.NAT_MATCH_NOT_OK
			}
		} else {
			return firewall.NAT_MATCH_NONE
		}
	}
}

func (rule *NatRule) natTranslate(from, to string, entry *policy.Intent) (bool, policy.PolicyEntryInf) {
	state := rule.match(from, to, entry)
	if state == firewall.NAT_MATCH_NONE || state == firewall.NAT_MATCH_NOT_OK {
		return false, nil
	}
	if rule.natType == firewall.STATIC_NAT {
		// 对于入向 NAT (to == ""), 使用 rule.translate 进行转换
		// 对于出向 NAT (to != ""), 根据 from 和 to 的关系决定使用 rule.translate 还是 rule.orignal.Reverse()
		if to == "" {
			// 入向 NAT: 使用 rule.translate 将外部流量转换为内部流量
			ok, tranlateTo, msg := entry.Translate(rule.translate)
			if !ok {
				panic(msg)
			}
			return true, entry.NewIntentWithTicket(tranlateTo)
		} else if from == rule.from {
			// 出向 NAT: 如果 from 匹配，使用 rule.translate
			ok, tranlateTo, msg := entry.Translate(rule.translate)
			if !ok {
				panic(msg)
			}
			return true, entry.NewIntentWithTicket(tranlateTo)
		} else {
			// 出向 NAT: 如果 from 不匹配，使用 rule.orignal.Reverse()
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

type Nats struct {
	VipRules     []*NatRule
	DynamicRules []*NatRule
	//objects   *FortiObjectSet
	node *FortigateNode
}

// TypeName 实现 TypeInterface 接口
func (n *Nats) TypeName() string {
	return "FortiNats"
}

// natsJSON 用于序列化和反序列化
type natsJSON struct {
	VipRules     []*NatRule `json:"vip_rules"`
	DynamicRules []*NatRule `json:"dynamic_rules"`
}

// MarshalJSON 实现 JSON 序列化
func (n *Nats) MarshalJSON() ([]byte, error) {
	return json.Marshal(natsJSON{
		VipRules:     n.VipRules,
		DynamicRules: n.DynamicRules,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (n *Nats) UnmarshalJSON(data []byte) error {
	var nj natsJSON
	if err := json.Unmarshal(data, &nj); err != nil {
		return err
	}

	n.VipRules = nj.VipRules
	n.DynamicRules = nj.DynamicRules

	return nil
}

func NewFortiNats(node *FortigateNode) *Nats {
	return &Nats{node: node}
}

func (nat *Nats) getVipByName(name string) *NatRule {
	for _, r := range nat.VipRules {
		if r.Name() == name {
			return r
		}
	}

	return nil
}

func (nat *Nats) getPoolByName(name string) *NatRule {
	for _, r := range nat.DynamicRules {
		if r.Name() == name {
			return r
		}
	}

	return nil
}

func (nat *Nats) parseRespResultForVip(result []dto.ForiRespResult) {
	var rules []*NatRule
	for _, res := range result {
		if res.ExtIp == "" {
			panic(fmt.Errorf("forti vip src ip is nil"))
		}
		rule := &NatRule{}
		rule.name = res.Name
		rule.extIntf = res.ExtIntf
		rule.objects = nat.node.objectSet
		rule.node = nat.node
		// 如果 Type 为空，使用默认值 "static-nat"
		if res.Type == "" {
			res.Type = "static-nat"
		}
		rule.natType = nat.natType(res.Type)
		// 如果 Status 为空，使用默认值 "enable"
		if res.Status == "" {
			res.Status = "enable"
		}
		rule.status = nat.natStatus(res.Status)
		realSrc := network.NewNetworkGroup()
		realDst := network.NewNetworkGroup()
		mappedSrc := network.NewNetworkGroup()
		mappedDst := network.NewNetworkGroup()
		var realService *service.Service
		var mappedService *service.Service
		var err error

		if res.PortForward == "enable" {
			realService, err = nat.parsePortAndService(res.Protocol, res.PortForward, res.ExtPort, false)
			if err != nil {
				panic(err)
			}
			mappedService, err = nat.parsePortAndService(res.Protocol, res.PortForward, res.MappedPort, false)
			if err != nil {
				panic(err)
			}
		} else {
			realService, err = nat.parsePortAndService(res.Protocol, res.PortForward, res.ExtPort, true)
			if err != nil {
				panic(err)
			}
			mappedService, err = nat.parsePortAndService(res.Protocol, res.PortForward, res.MappedPort, false)
			if err != nil {
				panic(err)
			}
		}

		realDst, _ = network.NewNetworkGroupFromString(res.ExtIp)
		nt, _ := network.ParseIPNet("0.0.0.0/0")
		realSrc.Add(nt)

		var mappedTo []string
		if len(res.MappedIp) == 0 {
			// 如果没有 MappedIp，尝试从 MappedIp 字段直接解析（兼容旧格式）
			// 或者使用默认值
			panic(fmt.Errorf("forti vip mapped ip is empty, MappedIp count: %d", len(res.MappedIp)))
		}
		for _, mappedIp := range res.MappedIp {
			if mappedIp.Range == "" {
				panic(fmt.Errorf("forti vip mapped ip is nil, mappedIp: %+v", mappedIp))
			}
			dnt, _ := network.NewNetworkGroupFromString(mappedIp.Range)
			mappedDst.AddGroup(dnt)
			mappedTo = append(mappedTo, mappedIp.Range)
		}
		net, _ := network.ParseIPNet("0.0.0.0/0")
		mappedSrc.Add(net)
		rule.from = ""
		rule.to = res.ExtIntf
		original := policy.NewPolicyEntry()
		translate := policy.NewPolicyEntry()

		// Original 应该匹配外部流量（进入防火墙的流量）
		// Src=any, Dst=ExtIp (外部IP), Service=ExtPort (外部端口)
		original.AddSrc(realSrc)         // any (0.0.0.0/0)
		original.AddDst(realDst)         // ExtIp (203.0.113.100)
		original.AddService(realService) // ExtPort (80)

		// Translate 应该转换为内部流量（转换后的流量）
		// Src=any, Dst=MappedIp (内部IP), Service=MappedPort (内部端口)
		translate.AddSrc(mappedSrc)         // any (0.0.0.0/0)
		translate.AddDst(mappedDst)         // MappedIp (10.1.1.100)
		translate.AddService(mappedService) // MappedPort (8080)

		rule.orignal = original
		rule.natType = firewall.STATIC_NAT
		rule.translate = translate
		rule.objMap = res
		rules = append(rules, rule)

		pairs := []templates.ParamPair{
			{S: "VipName", V: rule.Name()},
			{S: "ExtIp", V: res.ExtIp},
			{S: "MappedIp", V: mappedTo},
			{S: "ExtIntf", V: rule.extIntf},
		}
		var template *templates.CliTemplate
		if strings.ToLower(res.Protocol) == "ip" {
			template = templates.CliTemplates["ConfigFirewallVipIp"]
		} else {
			pairs = append(pairs, templates.ParamPair{S: "ExtPort", V: res.ExtPort}, templates.ParamPair{S: "MappedPort", V: res.MappedPort})
			template = templates.CliTemplates["ConfigFirewallVipTcpUdp"]
		}

		rule.cli = template.Formatter(pairs)
		fmt.Println(fmt.Sprintf("forti vip rule name:%s Original:%s Translate:%s", rule.name, rule.Original().String(), rule.Translate().String()))
	}
	nat.VipRules = rules
}

func (nat *Nats) parsePortAndService(protocol string, portForward string, port string, isSrc bool) (srv *service.Service, err error) {
	if protocol == "" {
		return nil, fmt.Errorf("nat protocol is nil")
	}
	if portForward != "disable" {
		sport, dport := splitPortRange(port, "-")
		srv, err = service.NewServiceWithL4(protocol, sport, dport)
		if err != nil {
			return nil, err
		}
		return
	} else {
		p, err := service.NewL4PortFromString(port, 0)
		if err != nil {
			return nil, err
		}
		if isSrc {
			srv, err = service.NewService(service.IP, p, nil, service.ICMP_TYPE_NIL, service.ICMP_CODE_NIL)
		} else {
			srv, err = service.NewService(service.IP, nil, p, service.ICMP_TYPE_NIL, service.ICMP_CODE_NIL)
		}
		if err != nil {
			return nil, err
		}
		return srv, err
	}
}

func (nat *Nats) parseRespResultForIpPool(result []dto.ForiRespResult) {
	var rules []*NatRule
	for _, res := range result {
		if res.StartIpPool == "" || res.EndIpPool == "" {
			panic(fmt.Errorf("forti pool src ip is nil"))
		}
		rule := &NatRule{}
		rule.name = res.Name
		rule.objects = nat.node.objectSet
		rule.node = nat.node
		rule.natType = firewall.DYNAMIC_NAT
		rule.status = firewall.NAT_ACTIVE
		rule.from = "any"
		rule.to = "any"
		realSrc := network.NewNetworkGroup()
		realDst := network.NewNetworkGroup()
		//mappedSrc := network.NewNetworkGroup()
		//mappedDst := network.NewNetworkGroup()
		realService := &service.Service{}
		s := service.NewL3ProtocolFromString("ip")
		realService.Add(s)
		mappedService := &service.Service{}
		ms := service.NewL3ProtocolFromString("ip")
		mappedService.Add(ms)

		realIpPool := strings.Join([]string{res.StartIpPool, res.EndIpPool}, "-")
		//mappedIpPool := strings.Join([]string{res.SourceStartIpPool, res.SourceEndIpPool}, "-")
		if realRange, err := network.NewIPRange(realIpPool); err != nil {
			panic(err)
		} else {
			net := network.NewNetworkFromIPRange(realRange)
			realSrc.Add(net)
			nt, _ := network.ParseIPNet("0.0.0.0/0")
			realDst.Add(nt)
		}

		//if mappedRange, err := network.NewIPRange(mappedIpPool); err != nil {
		//	panic(err)
		//} else {
		//	net := network.NewNetworkFromIPRange(mappedRange)
		//	mappedSrc.Add(net)
		//	nt, _ := network.ParseIPNet("0.0.0.0/0")
		//	mappedDst.Add(nt)
		//}

		original := policy.NewPolicyEntry()
		translate := policy.NewPolicyEntry()
		//original.AddSrc(realSrc)
		//original.AddDst(realDst)
		//original.AddService(realService)

		//original.AddSrc(mappedSrc)
		//original.AddDst(mappedDst)
		//original.AddService(mappedService)

		translate.AddSrc(realSrc)
		translate.AddDst(realDst)
		translate.AddService(realService)

		//translate.AddSrc(mappedSrc)
		//translate.AddDst(mappedDst)
		//translate.AddService(mappedService)
		rule.natType = firewall.DYNAMIC_NAT
		rule.orignal = original
		rule.translate = translate
		rule.objMap = res
		rules = append(rules, rule)

		pairs := []templates.ParamPair{
			{S: "PoolName", V: rule.Name()},
			{S: "StartIp", V: res.StartIpPool},
			{S: "EndIp", V: res.EndIpPool},
		}
		template := templates.CliTemplates["ConfigFirewallIpPool"]
		rule.cli = template.Formatter(pairs)
		fmt.Println(fmt.Sprintf("forti dynamic rule name:%s Original:%s Translate:%s", rule.name, rule.Original().String(), rule.Translate().String()))
	}
	nat.DynamicRules = rules

}

func (nat *Nats) inputNat(intent *policy.Intent, inPort api.Port) (bool, *policy.Intent, *NatRule) {
	for _, ruleList := range [][]*NatRule{nat.VipRules} {
		for _, rule := range ruleList {
			ok, tranlateTo := rule.natTranslate(inPort.Name(), "", intent)
			if ok {
				return ok, tranlateTo.(*policy.Intent), rule
			}
		}
	}
	return false, nil, nil
}

func (nat *Nats) outputNat(intent *policy.Intent, inPort, outPort api.Port) (bool, *policy.Intent, *NatRule) {
	if intent.Snat == "" {
		return false, nil, nil
	}
	for _, ruleList := range [][]*NatRule{nat.DynamicRules} {
		for _, rule := range ruleList {
			address, err := network.NewNetworkGroupFromString(intent.Snat)
			if err != nil {
				panic(err)
			}
			if rule.translate.Src().Same(address) {
				ok, translateTo := rule.natTranslate(inPort.Name(), outPort.Name(), intent)
				if ok {
					return ok, translateTo.(*policy.Intent), rule
				}
			}
		}
	}
	return false, nil, nil
}

func (nat *Nats) inputNatTargetCheck(intent *policy.Intent, inPort, outPort api.Port) (bool, *NatRule) {
	// 利用intent的realIp生成新的PolicyEntry，该PolicyEntry的源地址为realIp地址
	target := intent.GenerateIntentPolicyEntry()
	for _, ruleList := range [][]*NatRule{nat.VipRules} {
		for _, rule := range ruleList {
			ok := rule.matchDnatTarget(target)
			if ok {
				return true, rule
			}
		}
	}
	return false, nil
}

func (nat *Nats) natType(tp string) firewall.NatType {
	switch tp {
	case "static-nat":
		return firewall.STATIC_NAT
	case "dynamic-nat":
		return firewall.DYNAMIC_NAT
		// case "destination-nat":
		// return firewall.DYNAMIC_NAT
	}
	return 0
}
func (nat *Nats) natStatus(st string) firewall.NatStatus {
	switch st {
	case "enable":
		return firewall.NAT_ACTIVE
	case "disable":
		return firewall.NAT_INACTIVE
	}
	return 999
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallNatRule)(nil)).Elem(), "FortiNatRule", reflect.TypeOf(NatRule{}))
}

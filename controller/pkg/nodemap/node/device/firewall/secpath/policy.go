package secpath

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/secpath/model"

	//"github.com/netxops/unify/global"
	//M "github.com/netxops/unify/model"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/registry"
	"github.com/netxops/utils/service"
	"github.com/netxops/utils/text"
	"github.com/netxops/utils/tools"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/cast"
)

type Policy struct {
	cli          string
	id           int
	name         string
	ipType       network.IPFamily
	policyEntry  policy.PolicyEntryInf
	node         *SecPathNode
	from         api.Port
	out          api.Port
	srcZone      []string
	dstZone      []string
	srcAddr      []string
	srcObject    []string
	srcObjectCli []string
	dstAddr      []string
	dstObject    []string
	dstObjectCli []string
	srv          []string
	srvObject    []string
	srvObjectCli []string
	action       firewall.Action
	status       firewall.PolicyStatus
	objects      *SecPathObjectSet
	description  string
}

// TypeName 实现 TypeInterface 接口
func (p *Policy) TypeName() string {
	return "SecPathPolicy"
}

// policyJSON 用于序列化和反序列化
type policyJSON struct {
	CLI          string                `json:"cli"`
	ID           int                   `json:"id"`
	Name         string                `json:"name"`
	IPType       network.IPFamily      `json:"ip_type"`
	PolicyEntry  json.RawMessage       `json:"policy_entry"`
	From         json.RawMessage       `json:"from,omitempty"`
	Out          json.RawMessage       `json:"out,omitempty"`
	SrcZone      []string              `json:"src_zone"`
	DstZone      []string              `json:"dst_zone"`
	SrcAddr      []string              `json:"src_addr"`
	SrcObject    []string              `json:"src_object"`
	SrcObjectCli []string              `json:"src_object_cli"`
	DstAddr      []string              `json:"dst_addr"`
	DstObject    []string              `json:"dst_object"`
	DstObjectCli []string              `json:"dst_object_cli"`
	Srv          []string              `json:"srv"`
	SrvObject    []string              `json:"srv_object"`
	SrvObjectCli []string              `json:"srv_object_cli"`
	Description  string                `json:"description"`
	Action       firewall.Action       `json:"action"`
	Status       firewall.PolicyStatus `json:"status"`
}

// MarshalJSON 实现 JSON 序列化
func (p *Policy) MarshalJSON() ([]byte, error) {
	policyEntryRaw, err := registry.InterfaceToRawMessage(p.policyEntry)
	if err != nil {
		return nil, err
	}

	var fromRaw, outRaw json.RawMessage
	if p.from != nil {
		fromRaw, err = registry.InterfaceToRawMessage(p.from)
		if err != nil {
			return nil, err
		}
	}

	if p.out != nil {
		outRaw, err = registry.InterfaceToRawMessage(p.out)
		if err != nil {
			return nil, err
		}
	}

	return json.Marshal(&policyJSON{
		CLI:          p.cli,
		ID:           p.id,
		Name:         p.name,
		IPType:       p.ipType,
		PolicyEntry:  policyEntryRaw,
		From:         fromRaw,
		Out:          outRaw,
		SrcZone:      p.srcZone,
		DstZone:      p.dstZone,
		SrcAddr:      p.srcAddr,
		SrcObject:    p.srcObject,
		SrcObjectCli: p.srcObjectCli,
		DstAddr:      p.dstAddr,
		DstObject:    p.dstObject,
		DstObjectCli: p.dstObjectCli,
		Srv:          p.srv,
		SrvObject:    p.srvObject,
		SrvObjectCli: p.srvObjectCli,
		Description:  p.description,
		Action:       p.action,
		Status:       p.status,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (p *Policy) UnmarshalJSON(data []byte) error {
	var pj policyJSON
	if err := json.Unmarshal(data, &pj); err != nil {
		return err
	}

	p.cli = pj.CLI
	p.id = pj.ID
	p.name = pj.Name
	p.ipType = pj.IPType
	p.srcZone = pj.SrcZone
	p.dstZone = pj.DstZone
	p.srcAddr = pj.SrcAddr
	p.srcObject = pj.SrcObject
	p.srcObjectCli = pj.SrcObjectCli
	p.dstAddr = pj.DstAddr
	p.dstObject = pj.DstObject
	p.dstObjectCli = pj.DstObjectCli
	p.srv = pj.Srv
	p.srvObject = pj.SrvObject
	p.srvObjectCli = pj.SrvObjectCli
	p.description = pj.Description
	p.action = pj.Action
	p.status = pj.Status

	var err error
	p.policyEntry, err = registry.RawMessageToInterface[policy.PolicyEntryInf](pj.PolicyEntry)
	if err != nil {
		return err
	}

	if len(pj.From) > 0 {
		p.from, err = registry.RawMessageToInterface[api.Port](pj.From)
		if err != nil {
			return err
		}
	} else {
		p.from = nil
	}

	if len(pj.Out) > 0 {
		p.out, err = registry.RawMessageToInterface[api.Port](pj.Out)
		if err != nil {
			return err
		}
	} else {
		p.out = nil
	}

	return nil
}
func (plc *Policy) Action() firewall.Action {
	return plc.action
}

func (plc *Policy) Name() string {
	return plc.name
}

func (plc *Policy) ID() string {
	return fmt.Sprintf("%d", plc.id)
}

func (plc *Policy) Cli() string {
	return plc.cli
}

func (plc *Policy) PolicyEntry() policy.PolicyEntryInf {
	return plc.policyEntry
}

func (plc *Policy) Match(pe policy.PolicyEntryInf) bool {
	if plc.status == firewall.POLICY_INACTIVE {
		return false
	}

	for _, objName := range plc.srcObject {
		ng, _, ok := plc.node.ObjectSet.Network("", objName)
		if ok {
			plc.policyEntry.AddSrc(ng)
		}
	}

	for _, objName := range plc.dstObject {
		ng, _, ok := plc.node.ObjectSet.Network("", objName)
		if ok {
			plc.policyEntry.AddDst(ng)
		}
	}

	for _, objName := range plc.srvObject {
		srv, _, ok := plc.node.ObjectSet.Service(objName)
		if ok {
			plc.policyEntry.AddService(srv)
		}
	}

	return plc.policyEntry.Match(pe)
}

func (plc *Policy) FromZones() []string {
	return plc.srcZone
}

func (plc *Policy) ToZones() []string {
	return plc.dstZone
}

func (plc *Policy) FromPorts() []api.Port {
	if plc.from != nil {
		return []api.Port{plc.from}
	}
	return nil
}

func (plc *Policy) ToPorts() []api.Port {
	if plc.out != nil {
		return []api.Port{plc.out}
	}
	return nil
}

func (plc *Policy) Extended() map[string]interface{} {
	return map[string]interface{}{
		"SrcObjectCli": plc.srcObjectCli,
		"DstObjectCli": plc.dstObjectCli,
		"SrvObjectCli": plc.srvObjectCli,
		"SrcZone":      plc.srcZone,
		"DstZone":      plc.dstZone,
		"SrcAddr":      plc.srcAddr,
		"SrcObject":    plc.srcObject,
		"DstAddr":      plc.dstAddr,
		"DstObject":    plc.dstObject,
		"Srv":          plc.srv,
		"SrvObject":    plc.srvObject,
		"IPType":       plc.ipType,
		"ID":           plc.id,
	}
}

func (plc *Policy) Description() string {
	return plc.description
}

// GetSourceAddressObject 获取策略使用的源地址对象
func (plc *Policy) GetSourceAddressObject() (firewall.FirewallNetworkObject, bool) {
	if plc.policyEntry == nil || plc.objects == nil {
		return nil, false
	}

	// 如果策略有源地址对象名称，尝试查找
	if len(plc.srcObject) > 0 {
		objName := plc.srcObject[0]
		// 尝试从各个zone查找
		for _, zone := range plc.srcZone {
			if networkMap, ok := plc.objects.ZoneNetworkMap[ZoneName(zone)]; ok {
				if obj, found := networkMap[objName]; found {
					return obj, true
				}
			}
		}
		// 如果zone中找不到，尝试从默认zone查找
		if networkMap, ok := plc.objects.ZoneNetworkMap[model.SECPATH_NIL_ZONE]; ok {
			if obj, found := networkMap[objName]; found {
				return obj, true
			}
		}
	}

	return nil, false
}

// GetDestinationAddressObject 获取策略使用的目标地址对象
func (plc *Policy) GetDestinationAddressObject() (firewall.FirewallNetworkObject, bool) {
	if plc.policyEntry == nil || plc.objects == nil {
		return nil, false
	}

	// 如果策略有目标地址对象名称，尝试查找
	if len(plc.dstObject) > 0 {
		objName := plc.dstObject[0]
		// 尝试从各个zone查找
		for _, zone := range plc.dstZone {
			if networkMap, ok := plc.objects.ZoneNetworkMap[ZoneName(zone)]; ok {
				if obj, found := networkMap[objName]; found {
					return obj, true
				}
			}
		}
		// 如果zone中找不到，尝试从默认zone查找
		if networkMap, ok := plc.objects.ZoneNetworkMap[model.SECPATH_NIL_ZONE]; ok {
			if obj, found := networkMap[objName]; found {
				return obj, true
			}
		}
	}

	return nil, false
}

// GetServiceObject 获取策略使用的服务对象
func (plc *Policy) GetServiceObject() (firewall.FirewallServiceObject, bool) {
	if plc.policyEntry == nil || plc.objects == nil {
		return nil, false
	}

	// 如果策略有服务对象名称，尝试查找
	if len(plc.srvObject) > 0 {
		objName := plc.srvObject[0]
		if obj, found := plc.objects.ServiceMap[objName]; found {
			return obj, true
		}
	}

	return nil, false
}

type PolicySet struct {
	objects     *SecPathObjectSet
	node        *SecPathNode
	ipv4NameAcl map[string]*PolicyGroup
	ipv6NameAcl map[string]*PolicyGroup
	// securityPolicyAcl map[string]*Policy
	securityPolicyAcl []*Policy
	ruleIds           []int
	currentIndex      int
}

// TypeName 实现 TypeInterface 接口
func (ps *PolicySet) TypeName() string {
	return "SecPathPolicySet"
}

// policySetJSON 用于序列化和反序列化
type policySetJSON struct {
	IPv4NameAcl       map[string]*PolicyGroup `json:"ipv4_name_acl"`
	IPv6NameAcl       map[string]*PolicyGroup `json:"ipv6_name_acl"`
	SecurityPolicyAcl []*Policy               `json:"security_policy_acl"`
	RuleIds           []int                   `json:"rule_ids"`
	CurrentIndex      int                     `json:"current_index"`
}

// MarshalJSON 实现 JSON 序列化
func (ps *PolicySet) MarshalJSON() ([]byte, error) {
	return json.Marshal(policySetJSON{
		IPv4NameAcl:       ps.ipv4NameAcl,
		IPv6NameAcl:       ps.ipv6NameAcl,
		SecurityPolicyAcl: ps.securityPolicyAcl,
		RuleIds:           ps.ruleIds,
		CurrentIndex:      ps.currentIndex,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (ps *PolicySet) UnmarshalJSON(data []byte) error {
	var psj policySetJSON
	if err := json.Unmarshal(data, &psj); err != nil {
		return err
	}

	ps.ipv4NameAcl = psj.IPv4NameAcl
	ps.ipv6NameAcl = psj.IPv6NameAcl
	ps.securityPolicyAcl = psj.SecurityPolicyAcl
	ps.ruleIds = psj.RuleIds
	ps.currentIndex = psj.CurrentIndex

	return nil
}

type PolicyGroup struct {
	name  string
	rules []*Policy
}

type PolicySorucePortParser string

func (s PolicySorucePortParser) Service() *service.Service {
	tokens := strings.Split(string(s), " ")
	if len(tokens) <= 0 {
		panic("unknown error")
	}
	if len(tokens) == 1 {
		srv, err := service.NewServiceWithProto(tokens[0])
		if err != nil {
			panic(err)
		}
		if len(srv.ICMPProto) > 0 {
			srv.L3Protocol = []*service.L3Protocol{service.NewL3ProtocolFromString(tokens[0])}
			srv.ICMPProto = srv.ICMPProto[:0]
		}
		return srv
	}

	protocol := service.NewIPProtoFromString(tokens[0])
	switch tokens[0] {
	case "tcp", "udp":
		var bs bool
		var srcL4, dstL4 *service.L4Port
		for i := 1; i < len(tokens); {
			var l4port *service.L4Port
			var err error
			if tokens[i] == "source" {

				bs = true
			}

			if tokens[i] == "destination" {
				bs = false
			}

			if tokens[i] == "eq" {
				l4port, err = service.NewL4Port(service.EQ, cast.ToInt(tokens[i+1]), -1, 0)
				if err != nil {
					panic(err)
				}
				i += 1
			}

			if tokens[i] == "lt" {
				l4port, err = service.NewL4Port(service.LT, cast.ToInt(tokens[i+1]), -1, 0)
				if err != nil {
					panic(err)
				}
				i += 1
			}

			if tokens[i] == "gt" {
				l4port, err = service.NewL4Port(service.GT, cast.ToInt(tokens[i+1]), -1, 0)
				if err != nil {
					panic(err)
				}
				i += 1
			}

			if tokens[i] == "range" {
				l4port, err = service.NewL4Port(service.RANGE, cast.ToInt(tokens[i+1]), cast.ToInt(tokens[i+2]), 0)
				if err != nil {
					panic(err)
				}
				i += 2
			}

			if bs {
				srcL4 = l4port
			} else {
				dstL4 = l4port
			}
			i++
		}
		srv, err := service.NewService(protocol, srcL4, dstL4, service.ICMP_TYPE_NIL, service.ICMP_CODE_NIL)
		if err != nil {
			panic(err)
		}
		return srv
	case "icmp", "icmpv6":
		if len(tokens) > 2 && tokens[2] != "" {
			srv, err := service.NewService(protocol, nil, nil, cast.ToInt(tokens[1]), cast.ToInt(tokens[2]))
			if err != nil {
				panic(err)
			}
			return srv
		} else if len(tokens) > 1 {
			srv, err := service.NewService(protocol, nil, nil, cast.ToInt(tokens[1]), service.ICMP_CODE_NIL)
			if err != nil {
				panic(err)
			}
			return srv
		} else {
			// ICMP 协议但没有指定类型，创建默认 ICMP 服务
			srv, err := service.NewServiceWithProto(tokens[0])
			if err != nil {
				panic(err)
			}
			return srv
		}
	case "ip":
		// IP 协议（所有协议），直接创建 IP 协议服务
		srv, err := service.NewServiceWithProto("ip")
		if err != nil {
			panic(fmt.Sprintf("failed to create IP service: %v", err))
		}
		return srv
	default:
		// 对于其他 L3 协议，尝试直接创建服务
		srv, err := service.NewServiceWithProto(tokens[0])
		if err != nil {
			panic(fmt.Sprintf("unknown error, tokens:%s, error:%v", tokens, err))
		}
		return srv
	}
}

// type xmlIPv4AclStruct struct {
// GroupIndex string            `mapstructure:"GroupIndex" mapstructrue:"GroupIndex"`
// RuleID     int               `mapstructure:"RuleID" mapstructrue:"RuleId"`
// Action     ApiRuleActionType `mapstructure:"Action" mapstructrue:"Action"`
// SrcAny     bool              `mapstructure:"SrcAny" mapstructrue:"SrcAny"`
// SrcIPv4    struct {
// SrcIPv4Addr     string `mapstructure:"SrcIPv4Addr" mapstructrue:"SrcIPv4Addr"`
// SrcIPv4Wildcard string `mapstructure:"SrcIPv4Wildcard" mapstructrue:"SrcIPv4Wildcard"`
// } `mapstructure:"SrcIPv4" mapstructrue:"SrcIpv4"`
// Fragment bool             `mapstructure:"Fragment" mapstructrue:"Fragment"`
// Counting bool             `mapstructure:"Counting" mapstructrue:"Counting"`
// Logging  bool             `mapstructure:"Logging" mapstructrue:"Logging"`
// Status   ApiACLStatusType `mapstructure:"Status" mapstructrue:"Status"`
// Count    int              `mapstructure:"Count" mapstructrue:"Count"`
// }

// func (xas *xmlIPv4AclStruct) Policy(node *SecPathNode, objects *SecPathObjectSet) *Policy {
// byteS, err := mapstructrue.Marshal(xas)
// if err != nil {
// panic(err)
// }
// plc := Policy{
// node:    node,
// objects: objects,
// cli:     string(byteS),
// }
//
// var src *network.NetworkGroup
// if xas.SrcAny {
// src = network.NewAny4Group()
// } else {
// one, err := network.ParseIP(xas.SrcIPv4.SrcIPv4Wildcard)
// if err != nil {
// panic(err)
// }
// m, _ := network.IPtoMask(one)
// mask := m.Reverse()
//
// src, err = network.NewNetworkGroupFromString(fmt.Sprintf("%s/%s", xas.SrcIPv4.SrcIPv4Addr, network.IP(*mask).String()))
// if err != nil {
// panic(err)
// }
//
// }
//
// pe := policy.NewPolicyEntry()
// pe.AddSrc(src)
// plc.policyEntry = pe
//
// if xas.Status == ACL_STATUS_ACTIVE {
// plc.status = firewall.POLICY_ACTIVE
// } else {
// plc.status = firewall.POLICY_INACTIVE
// }
//
// if xas.Action == SECPATH_RULE_PERMIT {
// plc.action = firewall.POLICY_PERMIT
// } else {
// plc.action = firewall.POLICY_DENY
// }
//
// return &plc
// }
func (ps *PolicySet) parseIpv4Name(objList []interface{}) {
	for _, obj := range objList {

		var xmlObj model.XmlIPv4AdvanceAclStruct
		mapstructure.Decode(obj, &xmlObj)
		xmlObj.IPFamily = network.IPv4
		// fmt.Println(ps.ipv4NameAcl[xmlObj.GroupIndex])
		group := tools.OR(ps.ipv4NameAcl[xmlObj.GroupIndex], &PolicyGroup{name: xmlObj.GroupIndex}).(*PolicyGroup)
		// fmt.Println("group:", group)
		group.rules = append(group.rules, XmlIPv4AdvanceAclStructToPolicy(&xmlObj, ps.node, ps.objects))
		// fmt.Println(group)
		ps.ipv4NameAcl[xmlObj.GroupIndex] = group
		// fmt.Println(xmlObj.Policy(ps.node, ps.objects))
	}

}

func (ps *PolicySet) parseIpv4NameAdvance(objList []interface{}) {
	for _, obj := range objList {

		var xmlObj model.XmlIPv4AdvanceAclStruct
		mapstructure.Decode(obj, &xmlObj)
		xmlObj.IPFamily = network.IPv4

		group := tools.OR(ps.ipv4NameAcl[xmlObj.GroupIndex], &PolicyGroup{name: xmlObj.GroupIndex}).(*PolicyGroup)
		// group.rules = append(group.rules, xmlObj.Policy(ps.node, ps.objects))
		group.rules = append(group.rules, XmlIPv4AdvanceAclStructToPolicy(&xmlObj, ps.node, ps.objects))
		ps.ipv4NameAcl[xmlObj.GroupIndex] = group
		// fmt.Println(xmlObj.Policy(ps.node, ps.objects))
	}

}

func (ps *PolicySet) parseIpv6Name(objList []interface{}) {
	for _, obj := range objList {

		var xmlObj model.XmlIPv4AdvanceAclStruct
		mapstructure.Decode(obj, &xmlObj)

		// fmt.Println(xmlObj.Policy(ps.node, ps.objects))

		group := tools.OR(ps.ipv6NameAcl[xmlObj.GroupIndex], &PolicyGroup{name: xmlObj.GroupIndex}).(*PolicyGroup)
		group.rules = append(group.rules, XmlIPv4AdvanceAclStructToPolicy(&xmlObj, ps.node, ps.objects))
		ps.ipv6NameAcl[xmlObj.GroupIndex] = group
		// fmt.Println(xmlObj.Policy(ps.node, ps.objects))
	}

}

func (ps *PolicySet) parseIpv6NameAdvance(objList []interface{}) {
	for _, obj := range objList {

		var xmlObj model.XmlIPv4AdvanceAclStruct
		mapstructure.Decode(obj, &xmlObj)

		group := tools.OR(ps.ipv6NameAcl[xmlObj.GroupIndex], &PolicyGroup{name: xmlObj.GroupIndex}).(*PolicyGroup)
		// group.rules = append(group.rules, xmlObj.Policy(ps.node, ps.objects))
		group.rules = append(group.rules, XmlIPv4AdvanceAclStructToPolicy(&xmlObj, ps.node, ps.objects))
		ps.ipv6NameAcl[xmlObj.GroupIndex] = group
		// fmt.Println(xmlObj.Policy(ps.node, ps.objects))
	}
}

func (ps *PolicySet) parseSecurityRulesCli(config string) {
	sections := strings.Split(config, "#")

	var policyClis, policyV6Clis string
	for _, section := range sections {
		if strings.Index(section, "security-policy ipv6") >= 0 {
			// 去除第一行nat global-policy
			lines := strings.Split(strings.TrimSpace(section), "\n")
			policyV6Clis = strings.Join(lines[1:], "\n")
		} else if strings.Index(section, "security-policy ip") >= 0 {
			// 去除第一行nat global-policy
			lines := strings.Split(section, "\n")
			policyClis = strings.Join(lines[1:], "\n")
		}
	}

	if policyClis == "" && policyV6Clis == "" {
		return
	}

	ps.parseCli(policyClis, network.IPv4, false)
	ps.parseCli(policyV6Clis, network.IPv6, false)

}

func (ps *PolicySet) flySecurityRuleCli(config string) {
	sections := strings.Split(config, "#")

	var policyClis, policyV6Clis string
	for _, section := range sections {
		if strings.Index(section, "security-policy ipv6") >= 0 {
			// 去除第一行nat global-policy
			lines := strings.Split(strings.TrimSpace(section), "\n")
			policyV6Clis = strings.Join(lines[1:], "\n")
		} else if strings.Index(section, "security-policy ip") >= 0 {
			// 去除第一行nat global-policy
			lines := strings.Split(section, "\n")
			policyClis = strings.Join(lines[1:], "\n")
		}
	}

	if policyClis == "" && policyV6Clis == "" {
		return
	}

	ps.parseCli(policyClis, network.IPv4, true)
	ps.parseCli(policyV6Clis, network.IPv6, true)

}

func (ps *PolicySet) parseOnePolicyCli(clis string, ipFamily network.IPFamily, top bool) *Policy {
	basePolicyEntry := policy.NewPolicyEntry()
	basePolicyEntry.AddSrc(network.NewAny4Group())
	basePolicyEntry.AddDst(network.NewAny4Group())
	s, _ := service.NewServiceWithProto("ip")
	basePolicyEntry.AddService(s)

	ruleRegexMap := map[string]string{
		"regex": `
		    ^[\s]+
			(
				(rule\s((?P<id>\d+)\s)?name\s(?P<rule_name>\S+))|
				(description\s(?P<description>\S+))|
				(source-zone\s(?P<src_zone>\S+))|
				(destination-zone\s(?P<dst_zone>\S+))|
				(service
					(
						(\s(?P<srv>\S+))|
						(-port\s(?P<sp>[ \w]+))
					)
				)|
				(source-ip\s(?P<src_obj>\S+))|
				(source-ip-host\s(?P<src_host>\S+))|
				(source-ip-subnet\s(?P<src_subnet>\S+)\s(?P<src_prefix>\S+))|
				(source-ip-range\s(?P<src_range>\S+)\s(?P<src_end>\S+))|
				(destination-ip\s(?P<dst_obj>\S+))|
				(destination-ip-host\s(?P<dst_host>\S+))|
				(destination-ip-subnet\s(?P<dst_subnet>\S+)\s(?P<dst_prefix>\S+))|
				(destination-ip-range\s(?P<dst_range>\S+)\s(?P<dst_end>\S+))|
				(action\s((?P<permit>pass)|(?P<deny>drop)))|
				(?P<disable>disable)
			)
		`,
		"name":  "rule",
		"flags": "mx",
		"pcre":  "true",
	}

	ruleRgexResult, err := text.SplitterProcessOneTime(ruleRegexMap, clis)
	if err != nil {
		panic(err)
	}
	// for it := ruleRgexResult.Iterator(); it.HasNext(); {
	// _, _, m := it.Next()
	// if m["service_port_cli"] != "" {
	// fmt.Printf("service_port_cli----->%s", m["service_port_cli"])
	// }
	// }

	ruleMap, err := ruleRgexResult.Projection(
		[]string{"sp", "srv", "description",
			"src_zone", "src_obj", "src_host", "src_subnet", "src_range",
			"dst_zone", "dst_obj", "dst_host", "dst_subnet", "dst_range"},
		",",
		[][]string{
			[]string{"src_subnet", "src_prefix"},
			[]string{"src_range", "src_end"},
			[]string{"dst_subnet", "dst_prefix"},
			[]string{"dst_range", "dst_end"},
		})
	if err != nil {
		panic(err)
	}

	// if ruleMap["id"] == "" {
	// 	panic(fmt.Sprintf("parse security policy failed, clis:%s, ruleMap:%+v", clis, ruleMap))
	// }

	var ruleId int
	if ruleMap["id"] != "" {
		ruleId, err = strconv.Atoi(ruleMap["id"])
		if err != nil {
			panic(err)
		}
	}

	var plc *Policy
	var reusePolicy bool
	for index, _ := range ps.securityPolicyAcl {
		if ps.securityPolicyAcl[index].name == ruleMap["rule_name"] {
			plc = ps.securityPolicyAcl[index]
			reusePolicy = true
			break
		}
	}

	if plc == nil {
		plc = &Policy{
			id:      ruleId,
			name:    ruleMap["rule_name"],
			node:    ps.node,
			objects: ps.objects,
			ipType:  ipFamily,
			cli:     clis,
			action:  tools.Conditional(ruleMap["permit"] != "", firewall.POLICY_PERMIT, firewall.POLICY_DENY).(firewall.Action),
			status:  tools.Conditional(ruleMap["disable"] != "", firewall.POLICY_INACTIVE, firewall.POLICY_ACTIVE).(firewall.PolicyStatus),
		}
	}

	if ruleMap["src_zone"] != "" {
		for _, zone := range strings.Split(ruleMap["src_zone"], ",") {
			plc.srcZone = append(plc.srcZone, zone)
		}
	}

	if ruleMap["dst_zone"] != "" {
		for _, zone := range strings.Split(ruleMap["dst_zone"], ",") {
			plc.dstZone = append(plc.dstZone, zone)
		}
	}

	// src := network.NewNetworkGroup()
	var src *network.NetworkGroup

	if ruleMap["src_host"] != "" {
		for _, host := range strings.Split(ruleMap["src_host"], ",") {
			net, err := network.NewNetworkGroupFromString(host)
			if err != nil {
				panic(err)
			}
			plc.srcAddr = append(plc.srcAddr, host)
			if src == nil {
				src = net
			} else {
				src.AddGroup(net)
			}
		}
	}

	if ruleMap["src_subnet"] != "" {
		for _, subnet := range strings.Split(ruleMap["src_subnet"], ",") {
			subnet2 := strings.ReplaceAll(subnet, "-", "/")
			net, err := network.NewNetworkGroupFromString(subnet2)
			if err != nil {
				panic(err)
			}
			plc.srcAddr = append(plc.srcAddr, subnet2)
			if src == nil {
				src = net
			} else {
				src.AddGroup(net)
			}
		}
	}

	if ruleMap["src_range"] != "" {
		for _, subnet := range strings.Split(ruleMap["src_range"], ",") {
			net, err := network.NewNetworkGroupFromString(subnet)
			if err != nil {
				panic(err)
			}
			plc.srcAddr = append(plc.srcAddr, subnet)
			if src == nil {
				src = net
			} else {
				src.AddGroup(net)
			}
		}
	}

	if ruleMap["src_obj"] != "" {
		for _, objName := range strings.Split(ruleMap["src_obj"], ",") {
			net, objCli, ok := ps.objects.Network("", objName)
			if !ok {
				panic(fmt.Sprintf("get network object failed,  objName:%s", objName))
			}

			plc.srcObject = append(plc.srcObject, objName)
			if objCli != "" {
				plc.srcObjectCli = append(plc.srcObjectCli, objCli)
			}

			if src == nil {
				src = net
			} else {
				src.AddGroup(net)
			}

		}
	}

	var dst *network.NetworkGroup
	if ruleMap["dst_host"] != "" {
		for _, host := range strings.Split(ruleMap["dst_host"], ",") {
			net, err := network.NewNetworkGroupFromString(host)
			if err != nil {
				panic(err)
			}
			if dst == nil {
				dst = net
			} else {
				dst.AddGroup(net)
			}
		}
	}

	if ruleMap["dst_subnet"] != "" {
		for _, subnet := range strings.Split(ruleMap["dst_subnet"], ",") {
			subnet2 := strings.ReplaceAll(subnet, "-", "/")
			net, err := network.NewNetworkGroupFromString(subnet2)
			if err != nil {
				panic(err)
			}
			if dst == nil {
				dst = net
			} else {
				dst.AddGroup(net)
			}
		}
	}

	if ruleMap["dst_range"] != "" {
		for _, subnet := range strings.Split(ruleMap["dst_range"], ",") {
			net, err := network.NewNetworkGroupFromString(subnet)
			if err != nil {
				panic(err)
			}
			if dst == nil {
				dst = net
			} else {
				dst.AddGroup(net)
			}

		}
	}

	if ruleMap["dst_obj"] != "" {
		for _, objName := range strings.Split(ruleMap["dst_obj"], ",") {
			net, objCli, ok := ps.objects.Network("", objName)
			if !ok {
				panic(fmt.Sprintf("get network object failed,  objName:%s", objName))
			}

			if objCli != "" {
				plc.dstObjectCli = append(plc.dstObjectCli, objCli)
			}
			plc.dstObject = append(plc.dstObject, objName)

			if dst == nil {
				dst = net
			} else {
				dst.AddGroup(net)
			}
		}
	}

	var srv *service.Service

	if ruleMap["srv"] != "" {
		for _, objName := range strings.Split(ruleMap["srv"], ",") {
			s, objCli, ok := ps.objects.Service(objName)
			if !ok {
				panic(fmt.Sprintf("get service object failed,  objName:%s", objName))
			}
			if objCli != "" {
				plc.srvObjectCli = append(plc.srvObjectCli, objCli)
			}
			plc.srvObject = append(plc.srvObject, objName)
			if srv == nil {
				srv = s
			} else {
				srv.Add(s)
			}
		}
	}

	for _, cli := range strings.Split(ruleMap["sp"], ",") {
		if cli == "" {
			continue
		}
		cli = strings.Trim(cli, " ")
		s := PolicySorucePortParser(cli)
		if srv == nil {
			srv = s.Service()
		} else {
			srv.Add(s.Service())
		}
	}

	if ruleMap["description"] != "" {
		plc.description = ruleMap["description"]
	}

	if reusePolicy {
		plc.policyEntry.AddSrc(src)
		plc.policyEntry.AddDst(dst)
		plc.policyEntry.AddService(srv)
	} else {
		pe := policy.NewPolicyEntry()
		pe.AddSrc(src)
		pe.AddDst(dst)
		pe.AddService(srv)

		pe.AutoFill(basePolicyEntry)
		plc.policyEntry = pe

		ps.addPolicy(plc)
	}

	return plc
}

func (ps *PolicySet) addPolicy(plc *Policy) {
	// 查找是否存在同名策略
	for i, existingPlc := range ps.securityPolicyAcl {
		if existingPlc.name == plc.name {
			// 找到同名策略，进行叠加
			mergePolicy(ps.securityPolicyAcl[i], plc)
			return
		}
	}

	// 如果没有找到同名策略，直接添加新策略
	ps.securityPolicyAcl = append(ps.securityPolicyAcl, plc)
}

func mergePolicy(existing *Policy, new *Policy) {
	// 合并源地址
	if new.policyEntry.Src() != nil && !new.policyEntry.Src().IsAny(true) {
		existing.policyEntry.AddSrc(new.policyEntry.Src())
	}

	// 合并目标地址
	if new.policyEntry.Dst() != nil && !new.policyEntry.Dst().IsAny(true) {
		existing.policyEntry.AddDst(new.policyEntry.Dst())
	}

	// 合并服务
	if new.policyEntry.Service() != nil && !new.policyEntry.Service().IsAny(true) {
		existing.policyEntry.AddService(new.policyEntry.Service())
	}
}

// ((?P<service_port_cli>service-port[\s\w]+))|
func (ps *PolicySet) parseCli(clis string, ipFamily network.IPFamily, top bool) {
	if len(strings.TrimSpace(clis)) == 0 {
		return
	}
	basePolicyEntry := policy.NewPolicyEntry()
	if ipFamily == network.IPv4 {
		basePolicyEntry.AddSrc(network.NewAny4Group())
		basePolicyEntry.AddDst(network.NewAny4Group())
	} else {
		basePolicyEntry.AddSrc(network.NewAny6Group())
		basePolicyEntry.AddDst(network.NewAny6Group())
	}
	s, _ := service.NewServiceWithProto("ip")
	basePolicyEntry.AddService(s)

	policySectionResult := text.IndentSection2(clis)
	for _, clis := range policySectionResult {
		ps.parseOnePolicyCli(clis, ipFamily, top)
	}
}

func (ps *PolicySet) parseSecurityRules(objList []interface{}) {
	for _, obj := range objList {
		var xmlObj model.XmlSecurityPolicyStruct
		mapstructure.Decode(obj, &xmlObj)
		// xmlObj.node = ps.node

		// ps.securityPolicyAcl[xmlObj.Name] = XmlSecurityPolicyStructToPolicy(&xmlObj, ps.node, ps.objects)
		// ps.ruleIds = append(ps.ruleIds, ps.securityPolicyAcl[xmlObj.Name].id])
		ps.securityPolicyAcl = append(ps.securityPolicyAcl, XmlSecurityPolicyStructToPolicy(&xmlObj, ps.node, ps.objects))

		// fmt.Println(xmlObj.Policy(ps.node, ps.objects))
		// fmt.Println(obj)
	}
}

func (ps *PolicySet) getPolicyGroup(name string) *PolicyGroup {
	// fmt.Println(ps)
	for n, v := range ps.ipv4NameAcl {
		if n == name {
			return v
		}
	}

	for n, v := range ps.ipv6NameAcl {
		if n == name {
			return v
		}
	}

	return nil
}

func (ps *PolicySet) Match(from, to string, pe policy.PolicyEntryInf) (bool, firewall.FirewallPolicy) {
	for _, rule := range ps.securityPolicyAcl {
		if rule.status == firewall.POLICY_INACTIVE {
			continue
		}

		if (tools.Contains(rule.srcZone, model.SECPATH_ANY_ZONE) || tools.Contains(rule.srcZone, from)) &&
			(tools.Contains(rule.dstZone, model.SECPATH_ANY_ZONE) || tools.Contains(rule.dstZone, to)) {
			if rule.Match(pe) {
				return true, rule
			}
		}
	}

	return false, nil
}

func (ps *PolicySet) hasPolicyName(name string) bool {
	if ps.getPolicyGroup(name) != nil {
		return true
	}

	for _, rule := range ps.securityPolicyAcl {
		if rule.name == name {
			return true
		}
	}

	return false
}

func (ps *PolicySet) firstRuleId(ip network.IPFamily) int {
	if len(ps.securityPolicyAcl) == 0 {
		return -1
	} else {
		for _, rule := range ps.securityPolicyAcl {
			if rule.ipType == ip {
				return rule.id
			}
		}

		return -1
	}

}

/* Cli              string `gorm:"column:cli"` */
/* Name             string `gorm:"column:name"` */
/* RuleId           int */
/* ipType           network.IPFamily */
/* FromPort         string */
/* OutPort          string */
/* FromZone         string */
/* OutZone          string */
/* Status           string */
/* SrcAddress       *network.NetworkGroup */
/* DstAddress       *network.NetworkGroup */
/* Service          *service.Service */

//func (ps *PolicySet) AclToDb(db *gorm.DB, task_id uint) {
//	for _, acl := range ps.ipv4NameAcl {
//		pg := M.PolicyGroup{
//			Name:          acl.name,
//			ExtractTaskID: task_id,
//		}
//		// plcList := []*M.PolicyObject{}
//		for _, rule := range acl.rules {
//			plc := rule.ToDBStruct(db, task_id)
//			pg.Rules = append(pg.Rules, plc)
//		}
//
//		if len(pg.Rules) > 0 {
//			result := db.Save(&pg)
//			global.GVA_LOG.Info("ACL对象数量大于1, 保存数据入库", zap.Any("TaskId", task_id), zap.Any("Total", len(pg.Rules)), zap.Any("RowsAffected", result.RowsAffected))
//			if result.Error != nil {
//				panic(result.Error)
//			}
//		}
//	}
//}

//func (rule *Policy) ToDBStruct(db *gorm.DB, task_id uint) *M.PolicyObject {
//	plc := M.PolicyObject{
//		Cli:           rule.cli,
//		ExtractTaskID: task_id,
//		Name:          rule.name,
//		RuleId:        rule.id,
//		IpType:        rule.ipType,
//		FromZone:      strings.Join(rule.srcZone, ","),
//		OutZone:       strings.Join(rule.dstZone, ","),
//		Status:        int(rule.status),
//		Action:        int(rule.Action()),
//		SrcAddress:    rule.policyEntry.Src(),
//		DstAddress:    rule.policyEntry.Dst(),
//		Service:       rule.policyEntry.Service(),
//		Src:           strings.Join(rule.srcAddr, ","),
//		// SrcObject:  strings.Join(rule.SrcObject, ","),
//		Dst: strings.Join(rule.dstAddr, ","),
//		// DstObject:  strings.Join(rule.DstObject, ","),
//		Srv:        strings.Join(rule.srv, ","),
//		SrcObject1: rule.policyEntry.Src().String(),
//		DstObject1: rule.policyEntry.Dst().String(),
//		SrvObject1: rule.policyEntry.Service().String(),
//		// SrvObject:  strings.Join(rule.srvObject, ","),
//	}
//	for _, soName := range rule.srcObject {
//		netObj := M.NetworkObject{}
//		global.GVA_DB.Where("name = ?", soName).Where("extract_task_id = ?", task_id).Find(&netObj)
//		plc.SrcObjects = append(plc.SrcObjects, &netObj)
//	}
//	// fmt.Println("====src", plc.SrcObjects)
//	for _, dstName := range rule.dstObject {
//		netObj := M.NetworkObject{}
//		global.GVA_DB.Where("name = ?", dstName).Where("extract_task_id = ?", task_id).Find(&netObj)
//		plc.DstObjects = append(plc.DstObjects, &netObj)
//	}
//	// fmt.Println("++dst", plc.DstObjects)
//	for _, srvName := range rule.srvObject {
//		srvObj := M.ServiceObject{}
//		global.GVA_DB.Where("name = ?", srvName).Where("extract_task_id = ?", task_id).Find(&srvObj)
//		plc.SrvObjects = append(plc.SrvObjects, &srvObj)
//	}
//	// fmt.Println("++==", plc.SrvObjects)
//	return &plc
//}

//func (ps *PolicySet) PolicyToDb(db *gorm.DB, task_id uint) {
//
//	plcList := []*M.PolicyObject{}
//	for _, rule := range ps.securityPolicyAcl {
//		plc := rule.ToDBStruct(db, task_id)
//		plcList = append(plcList, plc)
//	}
//
//	if len(plcList) > 0 {
//		result2 := db.Save(plcList)
//		global.GVA_LOG.Info("PolicyObject对象数量大于1,保存数据入库", zap.Any("TaskId", task_id), zap.Any("Total", len(plcList)), zap.Any("RowsAffected", result2.RowsAffected))
//		if result2.Error != nil {
//			panic(result2.Error)
//		}
//	} else {
//		global.GVA_LOG.Info("PolicyObject对象数量为0,保存数据入库", zap.Any("TaskId", task_id), zap.Any("Total", len(plcList)))
//	}
//}

func XmlSecurityPolicyStructToPolicy(xps *model.XmlSecurityPolicyStruct, node *SecPathNode, objects *SecPathObjectSet) *Policy {
	basePolicyEntry := policy.NewPolicyEntry()
	basePolicyEntry.AddSrc(network.NewAny4Group())
	basePolicyEntry.AddDst(network.NewAny4Group())
	s, _ := service.NewServiceWithProto("ip")
	basePolicyEntry.AddService(s)

	byteS, err := json.Marshal(xps)
	if err != nil {
		panic(err)
	}
	plc := Policy{
		id:      xps.ID,
		name:    xps.Name,
		node:    node,
		objects: objects,
		ipType:  tools.Conditional(xps.Type == model.SECPATH_IP_IPV4, network.IPv4, network.IPv6).(network.IPFamily),
		cli:     string(byteS),
		action:  tools.Conditional(xps.Action == model.SECPATH_RULE_PERMIT, firewall.POLICY_PERMIT, firewall.POLICY_DENY).(firewall.Action),
		status:  tools.Conditional(*xps.Enable, firewall.POLICY_ACTIVE, firewall.POLICY_INACTIVE).(firewall.PolicyStatus),
	}

	if len(xps.SrcZoneList.SrcZoneItem) > 0 {
		plc.srcZone = append(plc.srcZone, xps.SrcZoneList.SrcZoneItem...)
	} else {
		plc.srcZone = append(plc.srcZone, model.SECPATH_ANY_ZONE)
	}

	if len(xps.DestZoneList.DestZoneItem) > 0 {
		plc.dstZone = append(plc.dstZone, xps.DestZoneList.DestZoneItem...)
	} else {
		plc.dstZone = append(plc.dstZone, model.SECPATH_ANY_ZONE)
	}

	var src *network.NetworkGroup
	var dst *network.NetworkGroup
	if len(xps.SrcAddrList.SrcAddrItem) > 0 {
		if src == nil {
			src = network.NewNetworkGroup()
		}
		for _, objName := range xps.SrcAddrList.SrcAddrItem {
			zoneList := []string{}
			zoneList = append(zoneList, xps.SrcZoneList.SrcZoneItem...)
			if len(zoneList) == 0 {
				zoneList = append(zoneList, model.SECPATH_NIL_ZONE)
			}

			for _, zone := range zoneList {
				net, _ := node.Network(zone, objName)
				if net != nil {
					src.AddGroup(net)
				}

				if net == nil {
					panic(fmt.Sprintf("find network object failed, name:%s", objName))
				}
			}

			// 添加srcObject
			plc.srcObject = append(plc.srcObject, objName)
		}
	}

	if len(xps.SrcSimpleAddrList.SrcSimpleAddrItem) > 0 {
		if src == nil {
			src = network.NewNetworkGroup()
		}
		for _, addr := range xps.SrcSimpleAddrList.SrcSimpleAddrItem {
			n, err := network.NewNetworkGroupFromString(addr)
			if err != nil {
				panic(err)
			}
			src.AddGroup(n)

			// 添加srcAddr
			plc.srcAddr = append(plc.srcAddr, addr)
		}

	}

	if len(xps.DestAddrList.DestAddrItem) > 0 {
		if dst == nil {
			dst = network.NewNetworkGroup()
		}
		for _, objName := range xps.DestAddrList.DestAddrItem {
			zoneList := []string{}
			zoneList = append(zoneList, xps.DestZoneList.DestZoneItem...)
			if len(zoneList) == 0 {
				zoneList = append(zoneList, model.SECPATH_NIL_ZONE)
			}

			for _, zone := range zoneList {
				net, _ := node.Network(zone, objName)
				if net != nil {
					dst.AddGroup(net)
				}

				if net == nil {
					panic(fmt.Sprintf("find network object failed, name:%s", objName))
				}
			}

			// 添加dstObject
			plc.dstObject = append(plc.dstObject, objName)
		}
	}

	if len(xps.DestSimpleAddrList.DestSimpleAddrItem) > 0 {
		if dst == nil {
			dst = network.NewNetworkGroup()
		}
		for _, addr := range xps.DestSimpleAddrList.DestSimpleAddrItem {
			n, err := network.NewNetworkGroupFromString(addr)
			if err != nil {
				panic(err)
			}
			dst.AddGroup(n)

			// 添加dstAddr
			plc.dstAddr = append(plc.dstAddr, addr)
		}
	}

	var srv *service.Service
	if len(xps.ServObjList.ServObjItem) > 0 {
		if srv == nil {
			srv = &service.Service{}
		}
		for _, item := range xps.ServObjList.ServObjItem {
			var xmlItemObj model.XmlRuleServiceStruct
			m := map[string]interface{}{}
			err := json.Unmarshal([]byte(item), &m)
			if err != nil {
				panic(err)
			}

			err = mapstructure.WeakDecode(m, &xmlItemObj)
			if err != nil {
				panic(err)
			}

			//此时不会存在NestedGroup的情况
			// fmt.Println(item)
			// fmt.Println(xmlItemObj)
			s, err := xmlItemObj.Service()
			srv.Add(s)

			// 添加 srv
			plc.srv = append(plc.srvObject, item)
		}
	}

	if len(xps.ServGrpList.ServGrpItem) > 0 {
		if srv == nil {
			srv = &service.Service{}
		}
		for _, objName := range xps.ServGrpList.ServGrpItem {
			obj, ok := node.Service(objName)
			if !ok {
				panic(fmt.Sprintf("find service failed, name: %s", objName))
			}
			srv.Add(obj)
			// 添加 srvObject
			plc.srvObject = append(plc.srvObject, objName)
		}
	}

	pe := policy.NewPolicyEntry()
	if src != nil {
		pe.AddSrc(src)
	}
	if dst != nil {
		pe.AddDst(dst)
	}
	if srv != nil {
		pe.AddService(srv)
	}

	pe.AutoFill(basePolicyEntry)
	plc.policyEntry = pe

	return &plc

}

func XmlIPv4AdvanceAclStructToPolicy(xas *model.XmlIPv4AdvanceAclStruct, node *SecPathNode, objects *SecPathObjectSet) *Policy {
	byteS, err := json.Marshal(xas)
	if err != nil {
		panic(err)
	}
	plc := Policy{
		node:    node,
		objects: objects,
		cli:     string(byteS),
	}

	var src *network.NetworkGroup
	var dst *network.NetworkGroup
	if xas.SrcAny {
		src = network.NewAny4Group()
	} else {
		if xas.SrcIPv4 != nil {
			one, err := network.ParseIP(xas.SrcIPv4.SrcIPv4Wildcard)
			if err != nil {
				panic(err)
			}
			m, _ := network.IPtoMask(one)
			mask := m.Reverse()

			src, err = network.NewNetworkGroupFromString(fmt.Sprintf("%s/%s", xas.SrcIPv4.SrcIPv4Addr, network.IP(*mask).String()))
			if err != nil {
				panic(err)
			}

			// 添加srcAddr
			plc.srcAddr = append(plc.srcAddr, fmt.Sprintf("%s/%s", xas.SrcIPv4.SrcIPv4Addr, network.IP(*mask).String()))

		}
		if xas.SrcIPv6 != nil {
			dst, err = network.NewNetworkGroupFromString(fmt.Sprintf("%s/%d", xas.SrcIPv6.SrcIPv6Addr, xas.SrcIPv6.SrcIPv6Prefix))
			if err != nil {
				panic(err)
			}

			// 添加srcAddr
			plc.srcAddr = append(plc.srcAddr, fmt.Sprintf("%s/%d", xas.SrcIPv6.SrcIPv6Addr, xas.SrcIPv6.SrcIPv6Prefix))
		}

	}

	if xas.DstAny {
		dst = network.NewAny4Group()
	} else {
		if xas.DstIPv4 != nil {
			one, err := network.ParseIP(xas.DstIPv4.DstIPv4Wildcard)
			if err != nil {
				panic(err)
			}
			m, _ := network.IPtoMask(one)
			mask := m.Reverse()

			dst, err = network.NewNetworkGroupFromString(fmt.Sprintf("%s/%s", xas.DstIPv4.DstIPv4Addr, network.IP(*mask).String()))
			if err != nil {
				panic(err)
			}

			// 添加dstAddr
			plc.dstAddr = append(plc.dstAddr, fmt.Sprintf("%s/%s", xas.DstIPv4.DstIPv4Addr, network.IP(*mask).String()))
		}
		if xas.DstIPv6 != nil {
			dst, err = network.NewNetworkGroupFromString(fmt.Sprintf("%s/%d", xas.DstIPv6.DstIPv6Addr, xas.DstIPv6.DstIPv6Prefix))
			if err != nil {
				panic(err)
			}

			// 添加dstAddr
			plc.dstAddr = append(plc.dstAddr, fmt.Sprintf("%s/%d", xas.DstIPv6.DstIPv6Addr, xas.DstIPv6.DstIPv6Prefix))
		}

	}

	pe := policy.NewPolicyEntry()
	if xas.ProtocolType == nil {
	} else {
		var protocol service.IPProto
		switch *xas.ProtocolType {
		case 256:
			protocol = service.IP
		case 0:
			protocol = service.IP
			// protocol = service.IPProto(0)
		default:
			protocol = service.IPProto(*xas.ProtocolType)
		}

		var srv *service.Service
		if protocol == service.ICMP || protocol == service.ICMP6 {
			// ICMPType int `mapstructure:"ICMPType"`
			// ICMPCode int `mapstructure:"ICMPCode"`
			if xas.ICMP != nil {
				c := tools.OR(xas.ICMP.ICMPCode, service.ICMP_DEFAULT_CODE)
				icmp, err := service.NewICMPProto(protocol, xas.ICMP.ICMPType, c.(int))
				if err != nil {
					panic(err)
				}
				srv = &service.Service{}
				srv.Add(icmp)

			} else {
				icmp, err := service.NewL3Protocol(protocol)
				if err != nil {
					panic(err)
				}

				srv = &service.Service{}
				srv.Add(icmp)
			}
		} else if protocol == service.TCP || protocol == service.UDP {
			var srcL4Port, dstL4Port *service.L4Port
			if xas.SrcPort == nil {
			} else {
				switch xas.SrcPort.SrcPortOp {
				case model.OP_EQ:
					srcL4Port, err = service.NewL4Port(service.EQ, xas.SrcPort.SrcPortValue1, -1, 0)
				case model.OP_GT:
					srcL4Port, err = service.NewL4Port(service.GT, xas.SrcPort.SrcPortValue1, -1, 0)
				case model.OP_LT:
					srcL4Port, err = service.NewL4Port(service.LT, xas.SrcPort.SrcPortValue1, -1, 0)
				case model.OP_NEQ:
					srcL4Port, err = service.NewL4Port(service.NEQ, xas.SrcPort.SrcPortValue1, -1, 0)
				case model.OP_RANGE:
					srcL4Port, err = service.NewL4Port(service.RANGE, xas.SrcPort.SrcPortValue1, xas.SrcPort.SrcPortValue2, 0)
				}
			}
			if xas.DstPort == nil {
			} else {
				switch xas.DstPort.DstPortOp {
				case model.OP_EQ:
					dstL4Port, err = service.NewL4Port(service.EQ, xas.DstPort.DstPortValue1, -1, 0)
				case model.OP_GT:
					dstL4Port, err = service.NewL4Port(service.GT, xas.DstPort.DstPortValue1, -1, 0)
				case model.OP_LT:
					dstL4Port, err = service.NewL4Port(service.LT, xas.DstPort.DstPortValue1, -1, 0)
				case model.OP_NEQ:
					dstL4Port, err = service.NewL4Port(service.NEQ, xas.DstPort.DstPortValue1, -1, 0)
				case model.OP_RANGE:
					dstL4Port, err = service.NewL4Port(service.RANGE, xas.DstPort.DstPortValue1, xas.DstPort.DstPortValue2, 0)
				}
			}
			if err != nil {
				panic(err)
			}

			srv, err = service.NewService(protocol, srcL4Port, dstL4Port, service.ICMP_TYPE_NIL, service.ICMP_CODE_NIL)
			if err != nil {
				panic(err)
			}
		} else {
			p, err := service.NewL3Protocol(protocol)
			if err != nil {
				panic(err)
			}

			srv = &service.Service{}
			srv.Add(p)
		}

		pe.AddService(srv)

		// 添加srv
		plc.srv = append(plc.srv, srv.String())
	}

	if src != nil {
		pe.AddSrc(src)
	}
	if dst != nil {
		pe.AddDst(dst)
	}
	plc.policyEntry = pe

	if xas.Status == model.ACL_STATUS_ACTIVE {
		plc.status = firewall.POLICY_ACTIVE
	} else {
		plc.status = firewall.POLICY_INACTIVE
	}

	if xas.Action == model.SECPATH_RULE_PERMIT {
		plc.action = firewall.POLICY_PERMIT
	} else {
		plc.action = firewall.POLICY_DENY
	}

	return &plc
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallPolicy)(nil)).Elem(), "SecPathPolicy", reflect.TypeOf(Policy{}))
}

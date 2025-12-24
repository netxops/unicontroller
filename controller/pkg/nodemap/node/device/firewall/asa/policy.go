package asa

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/registry"
	"github.com/netxops/utils/service"
	"github.com/netxops/utils/text"
)

type Policy struct {
	cli         string
	name        string
	policyEntry policy.PolicyEntryInf
	node        *ASANode
	action      firewall.Action
	status      firewall.PolicyStatus
	objects     *ASAObjectSet
	// srcObj      string
	// srcObjCli   string
	// dstObj      string
	// dstObjCli   string
	// srvObj      string
	// srvObjCli   string

	srcAddr      []string
	srcObject    []string
	srcObjectCli []string
	dstAddr      []string
	dstObject    []string
	dstObjectCli []string
	srv          []string
	srvObject    []string
	srvObjectCli []string
	description  string
}

// 实现 TypeInterface 接口
func (p *Policy) TypeName() string {
	return "ASAPolicy"
}

// policyJSON 用于序列化和反序列化
type policyJSON struct {
	CLI          string                `json:"cli"`
	Name         string                `json:"name"`
	PolicyEntry  json.RawMessage       `json:"policy_entry"`
	Action       firewall.Action       `json:"action"`
	Status       firewall.PolicyStatus `json:"status"`
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
}

// MarshalJSON 实现 JSON 序列化
func (p *Policy) MarshalJSON() ([]byte, error) {
	policyEntryRaw, err := json.Marshal(p.policyEntry)
	if err != nil {
		return nil, err
	}

	return json.Marshal(policyJSON{
		CLI:          p.cli,
		Name:         p.name,
		PolicyEntry:  policyEntryRaw,
		Action:       p.action,
		Status:       p.status,
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
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (p *Policy) UnmarshalJSON(data []byte) error {
	var pj policyJSON
	if err := json.Unmarshal(data, &pj); err != nil {
		return err
	}

	p.cli = pj.CLI
	p.name = pj.Name
	p.action = pj.Action
	p.status = pj.Status
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
	// 反序列化 PolicyEntry
	var policyEntry policy.PolicyEntryInf
	if err := json.Unmarshal(pj.PolicyEntry, &policyEntry); err != nil {
		return err
	}
	p.policyEntry = policyEntry

	return nil
}

func (plc *Policy) Action() firewall.Action {
	return plc.action
}

func (plc *Policy) Name() string {
	return plc.name
}

func (plc *Policy) ID() string {
	return ""
}

func (plc *Policy) Cli() string {
	return plc.cli
}

func (plc *Policy) Description() string {
	return plc.description
}

func (plc *Policy) PolicyEntry() policy.PolicyEntryInf {
	return plc.policyEntry
}

func (plc *Policy) Match(pe policy.PolicyEntryInf) bool {
	if plc.status == firewall.POLICY_INACTIVE {
		return false
	}

	// 如果策略引用了地址、服务对象，先重新加载这些对象
	if len(plc.srcObject) > 0 || len(plc.dstObject) > 0 || len(plc.srvObject) > 0 {
		// 重新加载源地址对象
		for _, objName := range plc.srcObject {
			ng, _, ok := plc.objects.Network("", objName)
			if ok {
				plc.policyEntry.AddSrc(ng)
			}
		}

		// 重新加载目标地址对象
		for _, objName := range plc.dstObject {
			ng, _, ok := plc.objects.Network("", objName)
			if ok {
				plc.policyEntry.AddDst(ng)
			}
		}

		// 重新加载服务对象
		for _, objName := range plc.srvObject {
			srv, _, ok := plc.objects.Service(objName)
			if ok {
				plc.policyEntry.AddService(srv)
			}
		}
	}

	return plc.policyEntry.Match(pe)
}

func (plc *Policy) FromZones() []string {
	return []string{}
}

func (plc *Policy) ToZones() []string {
	return []string{}
}

func (plc *Policy) FromPorts() []api.Port {
	return nil
}

func (plc *Policy) ToPorts() []api.Port {
	return nil
}

func (plc *Policy) Extended() map[string]interface{} {
	return map[string]interface{}{
		"SrcObjectCli": plc.srcObjectCli,
		"DstObjectCli": plc.dstObjectCli,
		"SrvObjectCli": plc.srvObjectCli,
		"SrcZone":      []string{},
		"DstZone":      []string{},
		"SrcAddr":      plc.srcAddr,
		"SrcObject":    plc.srcObject,
		"DstAddr":      plc.dstAddr,
		"DstObject":    plc.dstObject,
		"Srv":          plc.srv,
		"SrvObject":    plc.srvObject,
		// "IPType":       plc.ipType,
		// "ID":           plc.id,
	}
}

// GetSourceAddressObject 获取策略使用的源地址对象
func (plc *Policy) GetSourceAddressObject() (firewall.FirewallNetworkObject, bool) {
	if plc.policyEntry == nil || plc.objects == nil {
		return nil, false
	}

	// 如果策略有源地址对象名称，尝试查找
	if len(plc.srcObject) > 0 {
		objName := plc.srcObject[0]
		// 从 networkMap 中查找
		if obj, found := plc.objects.networkMap[objName]; found {
			return obj, true
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
		// 从 networkMap 中查找
		if obj, found := plc.objects.networkMap[objName]; found {
			return obj, true
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
		// 从 serviceMap 中查找
		if obj, found := plc.objects.serviceMap[objName]; found {
			return obj, true
		}
	}

	return nil, false
}

func (plc *Policy) parseExtendedMap(extMap map[string]string, cli string) {
	src := network.NewNetworkGroup()
	dst := network.NewNetworkGroup()
	s := &service.Service{}

	if extMap["src_host_any"] != "" {
		switch extMap["src_host_any"] {
		case "any":
			net, _ := network.ParseIPNet("0.0.0.0/0")
			src.Add(net)
			net2, _ := network.ParseIPNet("::/0")
			src.Add(net2)
		case "any4":
			net, _ := network.ParseIPNet("0.0.0.0/0")
			src.Add(net)
		case "any6":
			net, _ := network.ParseIPNet("::/0")
			src.Add(net)
		default:
			panic(fmt.Sprintf("unknown source address, map:%+v", extMap))
		}
	} else if extMap["src_host"] != "" {
		net, err := network.ParseIPNet(extMap["src_host"])
		if err != nil {
			panic(err)
		}
		src.Add(net)
	} else if extMap["src_ip"] != "" {
		net, err := network.ParseIPNet(extMap["src_ip"] + "/" + extMap["src_mask"])
		if err != nil {
			panic(err)
		}
		src.Add(net)
	} else if extMap["src_ifc"] != "" {
		// ToDo: 梳理ASA策略中的interface参数的功能
		// fmt.Println(extMap["src_ifc"])
		// fmt.Println(ps.Node.GetPort(extMap["src_ifc"]))
		m := plc.node.GetPortByNameOrAlias(extMap["src_ifc"]).(*ASAPort).GetIpList()
		for _, ip := range m[network.IPv4] {
			net, err := network.ParseIPNet(ip)
			if err != nil {
				panic(err)
			}
			src.Add(net)
		}

		for _, ip := range m[network.IPv6] {
			net, err := network.ParseIPNet(ip)
			if err != nil {
				panic(err)
			}
			src.Add(net)
		}

		// panic(fmt.Sprintf("current not support interface: %s, map:%+v", extMap["src_ifc"], extMap))
	} else if extMap["src_addr_obj"] != "" {
		ng, objCli, ok := plc.objects.Network("", extMap["src_addr_obj"])
		if !ok {
			panic(fmt.Sprintf("get source address object failed, obj: %s, map: %+v", extMap["src_addr_obj"], extMap))
		}
		src.AddGroup(ng)
		plc.srcObject = append(plc.srcObject, extMap["src_addr_obj"])
		plc.srcObjectCli = append(plc.srcObjectCli, objCli)
	} else {
		panic(fmt.Sprintf("unknown source address: %+v", extMap))
	}

	if extMap["dst_host_any"] != "" {
		switch extMap["dst_host_any"] {
		case "any":
			net, _ := network.ParseIPNet("0.0.0.0/0")
			dst.Add(net)
			net2, _ := network.ParseIPNet("::/0")
			dst.Add(net2)
		case "any4":
			net, _ := network.ParseIPNet("0.0.0.0/0")
			dst.Add(net)
		case "any6":
			net, _ := network.ParseIPNet("::/0")
			dst.Add(net)
		default:
			panic(fmt.Sprintf("unknown destination address, map:%+v", extMap))
		}
	} else if extMap["dst_host"] != "" {
		net, err := network.ParseIPNet(extMap["dst_host"])
		if err != nil {
			panic(err)
		}
		dst.Add(net)

	} else if extMap["dst_ip"] != "" {
		net, err := network.ParseIPNet(extMap["dst_ip"] + "/" + extMap["dst_mask"])
		if err != nil {
			panic(err)
		}
		dst.Add(net)
	} else if extMap["dst_ifc"] != "" {
		// ToDo: 梳理ASA策略中的interface参数的功能
		// ps.Node.GetPort(extMap["src_ifc"]).(*ASAPort).MainIpv4()
		m := plc.node.GetPortByNameOrAlias(extMap["dst_ifc"]).(*ASAPort).GetIpList()
		for _, ip := range m[network.IPv4] {
			net, err := network.ParseIPNet(ip)
			if err != nil {
				panic(err)
			}
			dst.Add(net)
		}

		for _, ip := range m[network.IPv6] {
			net, err := network.ParseIPNet(ip)
			if err != nil {
				panic(err)
			}
			dst.Add(net)
		}

		// panic(fmt.Sprintf("current not support interface: %s, map:%+v", extMap["dst_ifc"], extMap))
	} else if extMap["dst_addr_obj"] != "" {
		ng, objCli, ok := plc.objects.Network("", extMap["dst_addr_obj"])
		if !ok {
			panic(fmt.Sprintf("get destination address object failed, obj: %s, map: %+v", extMap["dst_addr_obj"], extMap))
		}
		plc.dstObjectCli = append(plc.dstObjectCli, objCli)
		plc.dstObject = append(plc.dstObject, extMap["dst_addr_obj"])
		dst.AddGroup(ng)
		src.AddGroup(ng)
	} else {
		panic(fmt.Sprintf("unknown destination address: %+v", extMap))
	}

	if extMap["protocol"] == "icmp" || extMap["protocol"] == "icmp6" {

		if extMap["icmp_type_obj"] != "" {
			if icmpService, objCli, ok := plc.objects.Service(extMap["icmp_type_obj"]); !ok {
				panic(fmt.Sprintf("get service object failed, obj: %s, map: %+v", extMap["icmp_type_obj"], extMap))
			} else {
				plc.srvObject = append(plc.srvObject, extMap["icmp_type_obj"])
				plc.srvObjectCli = append(plc.srvObjectCli, objCli)
				s.Add(icmpService)
			}
		} else if extMap["icmp_type_num"] != "" {
			// func NewICMPProto(p IPProto, it int, ic int) (*ICMPProto, error) {

			p, err := ASAParseProtocol(extMap["protocol"])
			if err != nil {
				panic(err)
			}
			it, err := strconv.Atoi(extMap["icmp_type_num"])
			if err != nil {
				panic(err)
			}
			icmp, err := service.NewICMPProto(service.IPProto(p), it, service.ICMP_DEFAULT_CODE)
			if err != nil {
				panic(err)
			}
			s.Add(icmp)
		} else if extMap["icmp_type_name"] != "" {
			p, err := ASAParseProtocol(extMap["protocol"])
			if err != nil {
				panic(err)
			}
			// Todo:需要处理icmp与icmp6的差异
			it, err := ASAIcmpParse(extMap["icmp_type_name"])
			if err != nil {
				panic(err)
			}
			icmp, err := service.NewICMPProto(service.IPProto(p), it, service.ICMP_DEFAULT_CODE)
			if err != nil {
				panic(err)
			}
			s.Add(icmp)
		} else {
			p, err := ASAParseProtocol(extMap["protocol"])
			if err != nil {
				panic(err)
			}

			icmp, err := service.NewL3Protocol(service.IPProto(p))
			if err != nil {
				panic(err)
			}

			s.Add(icmp)

			// panic(fmt.Sprintf("icmp service parse failed, %+v", extMap))
		}

	} else {
		if extMap["acl_service"] != "" {
			if sv, objCli, ok := plc.objects.Service(extMap["acl_service"]); !ok {
				panic(fmt.Sprintf("get service failed, obj:%s, map:%+v", extMap["acl_service"], extMap))
			} else {
				s.Add(sv)
				plc.srvObject = append(plc.srvObject, extMap["acl_service"])
				plc.srvObjectCli = append(plc.srvObjectCli, objCli)
			}
		} else {

			if extMap["dst_service_obj"] != "" {
				// if sv, ok := plc.objects.Service(extMap["dst_service_obj"]); !ok {
				// panic(fmt.Sprintf("get service failed, obj:%s, map:%+v", extMap["dst_service_obj"], extMap))
				// } else {
				// s.Add(sv)
				// }
				if sv, ok := plc.objects.L4Port(extMap["dst_service_obj"]); !ok {
					panic(fmt.Sprintf("get service failed, obj:%s, map:%+v", extMap["dst_service_obj"], extMap))
				} else {
					p, err := ASAParseProtocol(extMap["protocol"])
					if err != nil {
						panic(err)
					}
					srv, err := service.NewService(service.IPProto(p), nil, sv, service.ICMP_TYPE_NIL, service.ICMP_CODE_NIL)
					if err != nil {
						panic(err)
					}

					s.Add(srv)
				}

			} else {
				var sportL4, dportL4 *service.L4Port
				if extMap["src_op"] != "" {
					s1, err := ASAPortParse(extMap["src_port1"], extMap["protocol"])
					if err != nil {
						panic(fmt.Sprintf("l4 port parse failed, port:%s, map:%+v", extMap["src_port1"], extMap))
					}

					s2 := -1
					if extMap["src_port2"] != "" {
						s2, err = ASAPortParse(extMap["src_port2"], extMap["protocol"])
						if err != nil {
							panic(fmt.Sprintf("l4 port parse failed, port:%s, map:%+v", extMap["src_port2"], extMap))
						}
					}

					op, err := service.StringToOp(extMap["src_op"])
					if err != nil {
						panic(err)
					}

					sportL4, err = service.NewL4Port(op, s1, s2, 0)
					if err != nil {
						panic(fmt.Sprintf("create l4 port failed, map:%+v, err:%s", extMap, err))
					}
				}

				if extMap["dst_op"] != "" {
					d1, err := ASAPortParse(extMap["dst_port1"], extMap["protocol"])
					if err != nil {
						panic(fmt.Sprintf("l4 port parse failed, port:%s, map:%+v", extMap["drc_port1"], extMap))
					}

					d2 := -1
					if extMap["dst_port2"] != "" {
						d2, err = ASAPortParse(extMap["dst_port2"], extMap["protocol"])
						if err != nil {
							panic(fmt.Sprintf("l4 port parse failed, port:%s, map:%+v", extMap["drc_port2"], extMap))
						}
					}

					op, err := service.StringToOp(extMap["dst_op"])
					if err != nil {
						panic(fmt.Sprintf("create l4 port failed, map:%+v, err:%s", extMap, err))
					}

					dportL4, err = service.NewL4Port(op, d1, d2, 0)
					if err != nil {
						panic(err)
					}
				}

				p, err := ASAParseProtocol(extMap["protocol"])
				if err != nil {
					panic(err)
				}

				if sportL4 == nil && dportL4 == nil {
					l3Service, err := service.NewL3Protocol(service.IPProto(p))
					if err != nil {
						panic(err)
					}
					s.Add(l3Service)
				} else {
					l4Service, err := service.NewL4Service(service.IPProto(p), sportL4, dportL4)
					if err != nil {
						panic(err)
					}
					s.Add(l4Service)
				}

			}

		}
	}

	pe := policy.NewPolicyEntry()
	pe.AddSrc(src)
	pe.AddDst(dst)
	pe.AddService(s)
	plc.name = extMap["name"]

	if extMap["action"] == "permit" {
		plc.action = firewall.POLICY_PERMIT
	}

	if extMap["action"] == "deny" {
		plc.action = firewall.POLICY_DENY
	}

	plc.cli = cli
	plc.policyEntry = pe

	// fmt.Println(extMap)
	// fmt.Println(pe)
	// fmt.Println("-----------------------------------------------------")
}

func (plc *Policy) parseIcmp(cli string) {
	icmpRegexMap := map[string]string{
		"regex": `
            (?P<name>\S+)\s*
            (?P<type>extended)\s*
            (?P<action>permit|deny)\s*
            (?P<protocol>icmp)\s*
            (
                (?P<src_host_any>any[46]?) |
                (host\s(?P<src_host>[\d.a-fA-F:]+)) |
                ((?P<src_ip>[\d.]+)\s(?P<src_mask>[\d.]+)) |
                (?P<src_ip6>[\da-fA-F:\.]+\/[\d+]) |
                (interface\s(?P<src_ifc>\S+)) |
                ((object-group|object)\s(?P<src_addr_obj>\S+))
            )\s*

            (
                (?P<dst_host_any>any[46]?) |
                (host\s(?P<dst_host>[\d.a-fA-F:]+)) |
                ((?P<dst_ip>[\d.]+)\s(?P<dst_mask>[\d.]+)) |
                (?P<dst_ip6>[\da-fA-F:\.]+\/[\d+]) |
                (interface\s(?P<dst_ifc>\S+)) |
                ((object-group|object)\s*(?P<dst_addr_obj>\S+))
            )\s*

            (
                (object-group\s(?P<icmp_type_obj>\S+)) |
                (?P<icmp_type_num>\d+) |
                (?P<icmp_type_name>alternate-address|conversion-error|echo|echo-reply|information-reply|information-request|mask-reply|mask-request|mobile-redirect|parameter-problem|redirect|router-advertisement
|router-solicitation|source-quench|time-exceeded|timestamp-reply|timestamp-request|traceroute|unreachable)
            )?\s*
            (
                (?P<status>inactive)
            )?
		`,
		"name":  "icmp",
		"flags": "mx",
		"pcre":  "true",
	}

	icmpResult, err := text.SplitterProcessOneTime(icmpRegexMap, cli)
	if err != nil {
		if err == text.ErrNoMatched {
			return
		} else {
			panic(err)
		}
	}

	icmpMap, ok := icmpResult.One()
	if !ok {
		panic(fmt.Sprintf("parse extended access list failed, cli: %s, map: %+v", cli, icmpMap))

	}

	plc.parseExtendedMap(icmpMap, cli)

}

func (plc *Policy) parseIcmp6(cli string) {
	icmp6RegexMap := map[string]string{
		"regex": `
            (?P<name>\S+)\s*
            (?P<type>extended)\s*
            (?P<action>permit|deny)\s*
            (?P<protocol>icmp6)\s*

            (
                (?P<src_host_any>any[46]?) |
                (host\s(?P<src_host>[\d.a-fA-F:]+)) |
                ((?P<src_ip>[\d.]+)\s(?P<src_mask>[\d.]+)) |
                (?P<src_ip6>[\da-fA-F:\.]+\/[\d+]) |
                (interface\s(?P<src_ifc>\S+)) |
                ((object-group|object)\s(?P<src_addr_obj>\S+))
            )\s*

            (
                (?P<dst_host_any>any[46]?) |
                (host\s(?P<dst_host>[\d.a-fA-F:]+)) |
                ((?P<dst_ip>[\d.]+)\s(?P<dst_mask>[\d.]+)) |
                (?P<dst_ip6>[\da-fA-F:\.]+\/[\d+]) |
                (interface\s(?P<dst_ifc>\S+)) |
                ((object-group|object)\s*(?P<dst_addr_obj>\S+))
            )\s*

            (
                (object-group\s(?P<icmp_type_obj>\S+)) |
                (?P<icmp_type_num>\d+) |
                (?P<icmp_type_name>echo|echo-reply|membership-query|membership-reduction|membership-report|neighbor-advertisement|neighbor-redirect|neighbor-solicitation|packet-too-big|parameter-problem|router-advertisement|router-renumbering|router-solicitation|time-exceeded|unreachable)
            )?\s*
            (
                (?P<status>inactive)
            )?

		`,
		"name":  "icmp6",
		"flags": "mx",
		"pcre":  "true",
	}

	icmp6Result, err := text.SplitterProcessOneTime(icmp6RegexMap, cli)
	if err != nil {
		if err == text.ErrNoMatched {
			return
		} else {
			panic(err)
		}
	}

	icmp6Map, ok := icmp6Result.One()
	if !ok {
		panic(fmt.Sprintf("parse extended access list failed, cli: %s, map: %+v", cli, icmp6Map))

	}

	plc.parseExtendedMap(icmp6Map, cli)

}

func (plc *Policy) parseExtended(cli string) {
	extendedRegexMap := map[string]string{
		"regex": `
         access-list\s
             (?P<name>\S+)\s*
             ((line\s(?P<line>\d+)\s+)?)
             (?P<type>extended)\s*
             (?P<action>permit|deny)\s*

             (
                ((object-group|object)\s(?P<acl_service>\S+)) |
                (?P<protocol>tcp|udp|sctp|ah|eigrp|esp|gre|igmp|
                  igrp|ip|ipinip|ipsec|nos|ospf|pcp|pim|snp|sctp)
             )\s*
             (
                (?P<src_host_any>any[46]?) |
                (host\s(?P<src_host>[\d.a-fA-F:]+)) |
                ((?P<src_ip>[\d.]+)\s(?P<src_mask>[\d.]+)) |
                (?P<src_ip6>[\da-fA-F:\.]+\/[\d+]) |
                (interface\s(?P<src_ifc>\S+)) |
                ((object-group|object)\s(?P<src_addr_obj>\S+))
            )\s*
            (
                ((?P<src_op>neq|eq|lt|gt|range)\s(?P<src_port1>\S+)[ ]*(?P<src_port2>\S+)?)
                #|
                #(object-group\s(\S+))
            )?\s*
            (
                (?P<dst_host_any>any[46]?) |
                (host\s(?P<dst_host>[\d.a-fA-F:]+)) |
                ((?P<dst_ip>[\d.]+)\s(?P<dst_mask>[\d.]+)) |
                (?P<dst_ip6>[\da-fA-F:\.]+\/[\d+]) |
                (interface\s(?P<dst_ifc>\S+)) |
                ((object-group|object)\s*(?P<dst_addr_obj>\S+))
            )\s*

            (
                ((?P<dst_op>neq|eq|lt|gt|range)\s(?P<dst_port1>\S+)) |
                (object-group\s(?P<dst_service_obj>\S+))
            )?\s*
            (
                (?P<status>inactive) |
				(?P<dst_port2>\S+)
            )?
		`,
		"name":  "extended",
		"flags": "mx",
		"pcre":  "true",
	}
	// ((?P<dst_op>neq|eq|lt|gt|range)\s(?P<dst_port1>\S+)[ ]*(?P<dst_port2>\S+)?) |

	extendedResult, err := text.SplitterProcessOneTime(extendedRegexMap, cli)
	if err != nil {
		if err == text.ErrNoMatched {
			return
		} else {
			panic(err)
		}
	}

	extendedMap, ok := extendedResult.One()
	if !ok {
		panic(fmt.Sprintf("parse extended access list failed, cli: %s, map: %+v", cli, extendedMap))

	}

	plc.parseExtendedMap(extendedMap, cli)
}

func (plc *Policy) parsePolicyLine(cli string) {
	catagoryRegexMap := map[string]string{
		"regex": `access-list \S+ ((line \d+)\s)?(?P<type>\S+)`,
		"name":  "catagory",
		"flags": "m",
		"pcre":  "true",
	}

	catagoryResult, err := text.SplitterProcessOneTime(catagoryRegexMap, cli)
	if err != nil {
		if err == text.ErrNoMatched {
			return
		} else {
			panic(err)
		}
	}

	catagoryMap, ok := catagoryResult.One()
	if !ok {
		panic(fmt.Sprintf("access list catagory failed, cli: %s", cli))
	}

	if catagoryMap["type"] == "standard" {
		plc.parseStandard(cli)
	} else if catagoryMap["type"] == "extended" {
		extendedCatagoryRegexMap := map[string]string{
			"regex": `access-list \S+ extended (\S+) (?P<protocol>\S+)`,
			"name":  "catagory",
			"flags": "m",
			"pcre":  "true",
		}

		extendedCatagoryResult, err := text.SplitterProcessOneTime(extendedCatagoryRegexMap, cli)
		if err != nil {
			if err == text.ErrNoMatched {
				return
			} else {
				panic(err)
			}
		}

		extendCatagoryMap, ok := extendedCatagoryResult.One()
		if !ok {
			panic("extended access list catagory failed")
		}

		if extendCatagoryMap["protocol"] == "icmp" {
			plc.parseIcmp(cli)
		} else if extendCatagoryMap["protocol"] == "icmp6" {
			plc.parseIcmp6(cli)
		} else {
			plc.parseExtended(cli)
		}
	}
}

func (plc *Policy) parseStandard(cli string) {
	standardRegexMap := map[string]string{
		"regex": `
			access-list\s
            (?P<name>\S+)\sstandard\s
            (?P<action>\S+)\s
            (?P<host>host)?(?P<net>[\d\.]+)?\s
            (?P<ip_or_mask>\S+)
            (\s(?P<status>status))?
		`,
		"name":  "standard",
		"flags": "mx",
		"pcre":  "true",
	}

	standardResult, err := text.SplitterProcessOneTime(standardRegexMap, cli)
	if err != nil {
		if err == text.ErrNoMatched {
			return
		} else {
			panic(err)
		}
	}

	standardMap, ok := standardResult.One()
	if !ok {
		panic(fmt.Sprintf("parse standard access list failed, cli: %s", cli))
	}

	src := network.NewNetworkGroup()
	if standardMap["host"] != "" {
		net, err := network.ParseIPNet(standardMap["ip_or_mask"])
		if err != nil {
			panic(err)
		}
		src.Add(net)
	} else {
		net, err := network.ParseIPNet(standardMap["net"] + "/" + standardMap["ip_or_mask"])
		if err != nil {
			panic(err)
		}
		src.Add(net)
	}

	pe := policy.NewPolicyEntry()
	pe.AddSrc(src)
	plc.cli = cli
	plc.name = standardMap["name"]
	if standardMap["status"] == "inactive" {
		plc.status = firewall.POLICY_INACTIVE
	}

	if standardMap["action"] == "permit" {
		plc.action = firewall.POLICY_PERMIT
	}

	if standardMap["action"] == "deny" {
		plc.action = firewall.POLICY_DENY
	}

	plc.policyEntry = pe

}

type PolicySet struct {
	objects   *ASAObjectSet
	node      *ASANode
	policySet map[string][]*Policy
}

// 实现 TypeInterface 接口
func (ps *PolicySet) TypeName() string {
	return "ASAPolicySet"
}

// policySetJSON 用于序列化和反序列化
type policySetJSON struct {
	PolicySet map[string][]*Policy `json:"policy_set"`
}

// MarshalJSON 实现 JSON 序列化
func (ps *PolicySet) MarshalJSON() ([]byte, error) {
	return json.Marshal(policySetJSON{
		PolicySet: ps.policySet,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (ps *PolicySet) UnmarshalJSON(data []byte) error {
	var psj policySetJSON
	if err := json.Unmarshal(data, &psj); err != nil {
		return err
	}

	ps.policySet = psj.PolicySet

	// objects 和 node 字段被忽略，需要在其他地方单独设置

	return nil
}

func (ps *PolicySet) Match(name string, pe policy.PolicyEntryInf) (bool, firewall.FirewallPolicy) {
	if policyList, ok := ps.policySet[name]; !ok {
		return false, nil
	} else {
		for _, p := range policyList {
			if p.Match(pe) {
				return true, p
			}
		}
	}

	return false, nil
}

func (ps *PolicySet) addPolicy(name string, plc *Policy) {
	ps.policySet[name] = append(ps.policySet[name], plc)
}

func (ps *PolicySet) parseConfig(config string) {
	regexMap := map[string]string{
		"regex": `(?P<all>(access-list[^\n]+\n)+)`,
		"name":  "acl",
		"flags": "s",
		"pcre":  "true",
	}

	regexResult, err := text.SplitterProcessOneTime(regexMap, config)
	if err != nil {
		if err == text.ErrNoMatched {
			return
		} else {
			panic(err)
		}
	}

	var lines []string
	for it := regexResult.Iterator(); it.HasNext(); {
		_, _, aclMap := it.Next()
		lines = append(lines, aclMap["all"])
	}

	oneLine := strings.Join(lines, "\n")

	lines = lines[:0]
	for _, line := range strings.Split(oneLine, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines = append(lines, line)
	}

	for _, line := range lines {
		plc := &Policy{
			node:    ps.node,
			objects: ps.objects,
		}
		plc.parsePolicyLine(line)
		ps.addPolicy(plc.name, plc)
	}
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallPolicy)(nil)).Elem(), "ASAPolicy", reflect.TypeOf(Policy{}))
}

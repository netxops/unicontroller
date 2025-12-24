package asa

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/flexrange"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/service"
	"github.com/netxops/utils/text"
	"github.com/netxops/utils/validator"
)

//
// type firewall.FirewallServiceObject interface {
// Cli() string
// Name() string
// Service(map[string]firewall.FirewallServiceObject) *service.Service
// NeedProcessRefs() bool
// }

//
// type firewall.FirewallNetworkObject interface {
// Cli() string
// Name() string
// Network(map[string]firewall.FirewallNetworkObject) *network.NetworkGroup
// NeedProcessRefs() bool
// }

type Pool struct{}

type ASAPoolSet struct{}

type asaService struct {
	catagory firewall.FirewallObjectType
	cli      string
	name     string
	service  *service.Service
	// refs     []firewall.FirewallServiceObject
	refNames []string
}

// 实现 TypeInterface 接口
func (as *asaService) TypeName() string {
	return "ASAService"
}

// asaServiceJSON 用于序列化和反序列化
type asaServiceJSON struct {
	Catagory firewall.FirewallObjectType `json:"catagory"`
	Cli      string                      `json:"cli"`
	Name     string                      `json:"name"`
	Service  json.RawMessage             `json:"service"`
	RefNames []string                    `json:"ref_names"`
}

// MarshalJSON 实现 JSON 序列化
func (as *asaService) MarshalJSON() ([]byte, error) {
	serviceRaw, err := json.Marshal(as.service)
	if err != nil {
		return nil, fmt.Errorf("error marshaling service: %w", err)
	}

	return json.Marshal(asaServiceJSON{
		Catagory: as.catagory,
		Cli:      as.cli,
		Name:     as.name,
		Service:  serviceRaw,
		RefNames: as.refNames,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (as *asaService) UnmarshalJSON(data []byte) error {
	var asj asaServiceJSON
	if err := json.Unmarshal(data, &asj); err != nil {
		return err
	}

	as.catagory = asj.Catagory
	as.cli = asj.Cli
	as.name = asj.Name
	as.refNames = asj.RefNames

	as.service = &service.Service{}
	if err := json.Unmarshal(asj.Service, as.service); err != nil {
		return fmt.Errorf("error unmarshaling service: %w", err)
	}

	return nil
}

func (as *asaService) Name() string {
	return as.name
}

func (as *asaService) Cli() string {
	return as.cli
}

func (as *asaService) Type() firewall.FirewallObjectType {
	return as.catagory
}

// func (as *asaService) Service(serviceMap map[string]firewall.FirewallServiceObject) *service.Service {
func (as *asaService) Service(node firewall.FirewallNode) *service.Service {
	asa := node.(*ASANode)
	s := as.service.Copy().(*service.Service)

	serviceMap := asa.objectSet.serviceMap

	for _, ref := range as.refNames {
		if refObj, ok := serviceMap[ref]; !ok {
			panic(fmt.Sprintf("can not find ref object: %s", ref))
		} else {
			s.Add(refObj.Service(node))
		}
	}

	return s
}

type asaL4Port struct {
	catagory  firewall.FirewallObjectType
	cli       string
	name      string
	l4port    *service.L4Port
	protocols []service.IPProto
	refNames  []string
}

func (as *asaL4Port) Name() string {
	return as.name
}

func (as *asaL4Port) Cli() string {
	return as.cli
}

func (as *asaL4Port) Type() firewall.FirewallObjectType {
	return as.catagory
}

func (as *asaL4Port) L4Port(l4portMap map[string]firewall.FirewallL4PortObject) *service.L4Port {
	dr := as.l4port.Copy().(*flexrange.DataRange)
	s := &service.L4Port{
		DataRange: *dr,
	}
	// s := as.l4port.Copy().(*service.L4Port)

	for _, ref := range as.refNames {
		if refObj, ok := l4portMap[ref]; !ok {
			panic(fmt.Sprintf("can not find ref object: %s", ref))
		} else {
			s.Add(refObj.L4Port(l4portMap))
		}
	}

	return s
}

//
// func (as *asaService) NeedProcessRefs() bool {
// if len(as.refNames) > 0 && len(as.refs) == 0 {
// return true
// }
//
// return false
// }

type asaNetwork struct {
	catagory firewall.FirewallObjectType
	cli      string
	name     string
	hasNat   bool
	network  *network.NetworkGroup
	refs     []firewall.FirewallNetworkObject
	refNames []string
}

// 实现 TypeInterface 接口
func (an *asaNetwork) TypeName() string {
	return "ASANetwork"
}

// asaNetworkJSON 用于序列化和反序列化
type asaNetworkJSON struct {
	Catagory firewall.FirewallObjectType `json:"catagory"`
	Cli      string                      `json:"cli"`
	Name     string                      `json:"name"`
	HasNat   bool                        `json:"has_nat"`
	Network  json.RawMessage             `json:"network"`
	RefNames []string                    `json:"ref_names"`
}

// MarshalJSON 实现 JSON 序列化
func (an *asaNetwork) MarshalJSON() ([]byte, error) {
	networkRaw, err := json.Marshal(an.network)
	if err != nil {
		return nil, fmt.Errorf("error marshaling network: %w", err)
	}

	return json.Marshal(asaNetworkJSON{
		Catagory: an.catagory,
		Cli:      an.cli,
		Name:     an.name,
		HasNat:   an.hasNat,
		Network:  networkRaw,
		RefNames: an.refNames,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (an *asaNetwork) UnmarshalJSON(data []byte) error {
	var anj asaNetworkJSON
	if err := json.Unmarshal(data, &anj); err != nil {
		return err
	}

	an.catagory = anj.Catagory
	an.cli = anj.Cli
	an.name = anj.Name
	an.hasNat = anj.HasNat
	an.refNames = anj.RefNames

	an.network = &network.NetworkGroup{}
	if err := json.Unmarshal(anj.Network, an.network); err != nil {
		return fmt.Errorf("error unmarshaling network: %w", err)
	}

	// 注意：refs 字段不会被序列化和反序列化，因为它包含接口类型
	// 如果需要，你可能需要在反序列化后手动重建这个字段

	return nil
}

func (an *asaNetwork) Name() string {
	return an.name
}

func (an *asaNetwork) Cli() string {
	return an.cli
}

func (an *asaNetwork) Type() firewall.FirewallObjectType {
	return an.catagory
}

func (an *asaNetwork) WithNat() {
	an.hasNat = true
}

func (an *asaNetwork) HasNat() bool {
	return an.hasNat
}

// func (an *asaNetwork) NeedProcessRefs() bool {
// if len(an.refNames) > 0 && len(an.refs) == 0 {
// return true
// }
//
// return false
// }
func (an *asaNetwork) Network(node firewall.FirewallNode) *network.NetworkGroup {
	asa := node.(*ASANode)
	networkMap := asa.objectSet.networkMap
	ng := an.network.Copy().(*network.NetworkGroup)
	for _, ref := range an.refNames {
		if refObj, ok := networkMap[ref]; !ok {
			panic(fmt.Sprintf("can not find ref object: %s", ref))
		} else {
			ng.AddGroup(refObj.Network(asa))
		}

	}

	return ng
}

type ASAObjectSet struct {
	node       *ASANode
	serviceMap map[string]firewall.FirewallServiceObject
	networkMap map[string]firewall.FirewallNetworkObject
	l4portMap  map[string]firewall.FirewallL4PortObject
}

// 实现 TypeInterface 接口
func (aos *ASAObjectSet) TypeName() string {
	return "ASAObjectSet"
}

// asaObjectSetJSON 用于序列化和反序列化
type asaObjectSetJSON struct {
	ServiceMap map[string]json.RawMessage `json:"service_map"`
	NetworkMap map[string]json.RawMessage `json:"network_map"`
	L4PortMap  map[string]json.RawMessage `json:"l4port_map"`
}

// MarshalJSON 实现 JSON 序列化
func (aos *ASAObjectSet) MarshalJSON() ([]byte, error) {
	serviceMap := make(map[string]json.RawMessage)
	for k, v := range aos.serviceMap {
		data, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		serviceMap[k] = data
	}

	networkMap := make(map[string]json.RawMessage)
	for k, v := range aos.networkMap {
		data, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		networkMap[k] = data
	}

	l4portMap := make(map[string]json.RawMessage)
	for k, v := range aos.l4portMap {
		data, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		l4portMap[k] = data
	}

	return json.Marshal(asaObjectSetJSON{
		ServiceMap: serviceMap,
		NetworkMap: networkMap,
		L4PortMap:  l4portMap,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (aos *ASAObjectSet) UnmarshalJSON(data []byte) error {
	var aosj asaObjectSetJSON
	if err := json.Unmarshal(data, &aosj); err != nil {
		return err
	}

	aos.serviceMap = make(map[string]firewall.FirewallServiceObject)
	for k, v := range aosj.ServiceMap {
		var obj firewall.FirewallServiceObject
		if err := json.Unmarshal(v, &obj); err != nil {
			return err
		}
		aos.serviceMap[k] = obj
	}

	aos.networkMap = make(map[string]firewall.FirewallNetworkObject)
	for k, v := range aosj.NetworkMap {
		var obj firewall.FirewallNetworkObject
		if err := json.Unmarshal(v, &obj); err != nil {
			return err
		}
		aos.networkMap[k] = obj
	}

	aos.l4portMap = make(map[string]firewall.FirewallL4PortObject)
	for k, v := range aosj.L4PortMap {
		var obj firewall.FirewallL4PortObject
		if err := json.Unmarshal(v, &obj); err != nil {
			return err
		}
		aos.l4portMap[k] = obj
	}

	// node 字段不会被序列化和反序列化，需要在其他地方单独处理

	return nil
}

func NewASAObjectSet(node *ASANode) *ASAObjectSet {
	return &ASAObjectSet{
		node:       node,
		serviceMap: map[string]firewall.FirewallServiceObject{},
		networkMap: map[string]firewall.FirewallNetworkObject{},
		l4portMap:  map[string]firewall.FirewallL4PortObject{},
	}
}

func parseObjectGroupIcmpType(cli string, infoMap map[string]string) firewall.FirewallServiceObject {
	regexMap := map[string]string{
		"regex": `
    (icmp-object\s(?P<icmp_type>\S+)) |
    (group-object\s(?P<obj_gp>\S+))
		`,
		"name":  "network",
		"flags": "mx",
		"pcre":  "true",
	}

	result, err := text.SplitterProcessOneTime(regexMap, cli)
	if err != nil {
		panic(err)
	}

	obj := &asaService{
		catagory: firewall.GROUP_ICMP_TYPE,
		cli:      cli,
		name:     infoMap["name"],
	}

	s := &service.Service{}
	for it := result.Iterator(); it.HasNext(); {
		_, _, resultMap := it.Next()
		// fmt.Println(resultMap)
		if resultMap["icmp_type"] != "" {
			ic, err := ASAIcmpParse(resultMap["icmp_type"])
			if err != nil {
				panic(err)
			}
			icmp, err := service.NewICMPProto(service.ICMP, ic, service.ICMP_DEFAULT_CODE)
			if err != nil {
				panic(err)
			}
			s.Add(icmp)
		} else if resultMap["obj_gp"] != "" {
			obj.refNames = append(obj.refNames, resultMap["obj_gp"])
		} else {
			panic(fmt.Sprintf("unknown cli:%s", cli))
		}
	}
	obj.service = s

	return obj

}

func parseObjectGroupProtocol(cli string, infoMap map[string]string) firewall.FirewallServiceObject {
	regexMap := map[string]string{
		"regex": `
    (protocol-object\s(?P<protocol>\S+)) |
    (group-object\s(?P<protocol_group_object>\S+))
		`,
		"name":  "network",
		"flags": "mx",
		"pcre":  "true",
	}

	obj := &asaService{
		catagory: firewall.GROUP_PROTOCOL,
		cli:      cli,
		name:     infoMap["name"],
	}

	s := &service.Service{}

	result, err := text.SplitterProcessOneTime(regexMap, cli)
	if err != nil {
		panic(err)
	}

	for it := result.Iterator(); it.HasNext(); {
		_, _, resultMap := it.Next()
		if resultMap["protocol"] != "" {
			p, err := ASAParseProtocol(resultMap["protocol"])
			if err != nil {
				panic(err)
			}
			l3, err := service.NewL3Protocol(service.IPProto(p))
			if err != nil {
				panic(err)
			}
			s.Add(l3)
		} else if resultMap["protocol_group_object"] != "" {
			obj.refNames = append(obj.refNames, resultMap["protocol_group_object"])
		} else {
			panic(fmt.Sprintf("unknown cli:%s", cli))
		}
	}

	obj.service = s

	return obj
}

func parseObjectService(cli string, infoMap map[string]string) firewall.FirewallServiceObject {
	regexMap := map[string]string{
		"regex": `
    (service\s
        (?P<ip_proto>ah|eigrp|esp|gre|igmp|igrp|ip|ipinip|ipsec|nos|ospf|pcp|pim|snp|icmp|tcp|udp)\s*$
    ) |
    (service-object\s(?P<ip_protocol_num>\d+)\s*$) |
    (service\s
        icmp\s
        (?P<icmp_type>\S+)?\s*(?P<icmp_code>\S+)\s*$
    ) |
    (service\s(?P<protocol>tcp|udp)\s*
        (source\s
            (?P<s_op>eq|lt|gt|neq|range)\s
            (?P<sport1>\S+)[ ]*
            (?P<sport2>\S+)?
        )?\s*
        (destination\s
            (?P<d_op>eq|lt|gt|neq|range)\s
            (?P<dport1>\S+)[ ]*
            (?P<dport2>\S+)?
        )?
        \s*$
    )
		`,
		"name":  "service",
		"flags": "mx",
		"pcre":  "true",
	}

	result, err := text.SplitterProcessOneTime(regexMap, cli)
	if err != nil {
		panic(err)
	}

	obj := &asaService{
		catagory: firewall.OBJECT_SERVICE,
		cli:      cli,
		name:     infoMap["name"],
	}
	obj.service = &service.Service{}
	for it := result.Iterator(); it.HasNext(); {
		_, _, resultMap := it.Next()
		if resultMap["ip_proto"] != "" {
			protocol, err := ASAParseProtocol(resultMap["ip_proto"])
			if err != nil {
				panic(err)
			}

			p, err := service.NewL3Protocol(service.IPProto(protocol))
			if err != nil {
				panic(err)
			}
			obj.service.Add(p)
		} else if resultMap["ip_protocol_num"] != "" {
		} else if resultMap["icmp_type"] != "" {
			it, err := ASAIcmpParse(resultMap["icmp_type"])
			if err != nil {
				panic(err)
			}
			ic := service.ICMP_DEFAULT_CODE
			if resultMap["icmp_code"] != "" {
				if !validator.IsInt(resultMap["icmp_code"]) {
					panic(fmt.Sprintf("current not support icmp code:%s", resultMap["icmp_code"]))
				}
				icParsed, err := strconv.Atoi(resultMap["icmp_code"])
				if err != nil {
					panic(fmt.Sprintf("invalid icmp code:%s", resultMap["icmp_code"]))
				}
				ic = icParsed
			}

			p, err := service.NewICMPProto(service.ICMP, it, ic)
			if err != nil {
				panic(err)
			}

			obj.service.Add(p)
		} else if resultMap["protocol"] != "" {
			var sportL4, dportL4 *service.L4Port
			protocol, err := ASAParseProtocol(resultMap["protocol"])
			if err != nil {
				panic(err)
			}

			if resultMap["s_op"] != "" {
				sport1, err := ASAPortParse(resultMap["sport1"], resultMap["protocol"])
				if err != nil {
					panic(sport1)
				}

				s1, err := ASAPortParse(resultMap["sport1"], resultMap["protocol"])
				if err != nil {
					panic(err)
				}

				s2 := -1
				if resultMap["sport2"] != "" {
					s2, err = ASAPortParse(resultMap["sport2"], resultMap["protocol"])
					if err != nil {
						panic(err)
					}
				}

				op, err := service.StringToOp(resultMap["s_op"])
				if err != nil {
					panic(err)
				}

				sportL4, err = service.NewL4Port(op, s1, s2, 0)
				if err != nil {
					panic(err)
				}
			}

			if resultMap["d_op"] != "" {
				dport1, err := ASAPortParse(resultMap["dport1"], resultMap["protocol"])
				if err != nil {
					panic(dport1)
				}

				d1, err := ASAPortParse(resultMap["dport1"], resultMap["protocol"])
				if err != nil {
					panic(err)
				}

				d2 := -1
				if resultMap["dport2"] != "" {
					d2, err = ASAPortParse(resultMap["dport2"], resultMap["protocol"])
					if err != nil {
						panic(err)
					}
				}

				op, err := service.StringToOp(resultMap["d_op"])
				if err != nil {
					panic(err)
				}

				dportL4, err = service.NewL4Port(op, d1, d2, 0)
				if err != nil {
					panic(err)
				}
			}

			s, err := service.NewL4Service(service.IPProto(protocol), sportL4, dportL4)
			if err != nil {
				panic(err)
			}

			obj.service.Add(s)
		} else {
			panic(fmt.Sprintf("unknown cli:%s", cli))
		}

	}

	return obj
}

func parseL4PortObject(cli string, infoMap map[string]string) firewall.FirewallL4PortObject {
	regexMap := map[string]string{
		"regex": `
    (?P<cli>
        (port-object\s(?P<op>\S+)\s(?P<s1>\S+)[ ]*(?P<s2>\S+)?) |

        (service-object\sobject\s(?P<service_object>\S+)) |

        (
            (service-object\s
                (?P<ip_proto>ah|eigrp|esp|gre|igmp|igrp|ip|ipinip|ipsec|nos|ospf|pcp|pim|snp|icmp)\s*$
            ) |
            (service-object\s(?P<ip_protocol_num>\d+)) |
            (service-object\s
                icmp\s
                (?P<icmp_type>\S+)?\s*(?P<icmp_code>\S+)\s*$
            ) |
            (service-object\s(?P<protocol>tcp|udp)\s*
                (source\s
                    (?P<s_op>eq|lt|gt|neq|range)\s
                    (?P<sport1>\S+)[ ]*
                    (?P<sport2>\S+)?
                )?\s*
                (destination\s
                    (?P<d_op>eq|lt|gt|neq|range)\s
                    (?P<dport1>\S+)[ ]*
                    (?P<dport2>\S+)?
                )?\s*
            )
        ) |

        (group-object\s(?P<obj_gp>\S+)\s*)
    )


		`,
		"name":  "service",
		"flags": "mx",
		"pcre":  "true",
	}

	result, err := text.SplitterProcessOneTime(regexMap, cli)
	if err != nil {
		panic(err)
	}

	obj := &asaL4Port{
		catagory: firewall.L4PORT,
		cli:      cli,
		name:     infoMap["name"],
	}

	// obj.l4port = &service.Service{}
	for it := result.Iterator(); it.HasNext(); {
		_, _, resultMap := it.Next()

		if resultMap["op"] != "" {
			protocol := infoMap["additions"]
			s1, err := ASAPortParse(resultMap["s1"], protocol)
			if err != nil {
				panic(err)
			}

			s2 := -1
			if resultMap["s2"] != "" {
				s2, err = ASAPortParse(resultMap["s2"], protocol)
				if err != nil {
					panic(err)
				}
			}

			op, err := service.StringToOp(resultMap["op"])
			if err != nil {
				panic(err)
			}

			l4, err := service.NewL4Port(op, s1, s2, 0)
			if err != nil {
				panic(err)
			}

			protocolList := []int{}
			if strings.ToLower(protocol) == "tcp-udp" {
				protocolList = append(protocolList, 17)
				protocolList = append(protocolList, 6)
			} else {
				p, err := ASAParseProtocol(protocol)
				if err != nil {
					panic(err)
				}
				protocolList = append(protocolList, p)
			}

			for _, p := range protocolList {
				obj.protocols = append(obj.protocols, service.IPProto(p))
			}
			if obj.l4port == nil {
				obj.l4port = l4
			} else {
				obj.l4port.Add(l4)
			}
		}
	}

	return obj

}

func parseObjectGroupService(cli string, infoMap map[string]string) firewall.FirewallServiceObject {
	regexMap := map[string]string{
		"regex": `
    (?P<cli>
        (port-object\s(?P<op>\S+)\s(?P<s1>\S+)[ ]*(?P<s2>\S+)?) |

        (service-object\sobject\s(?P<service_object>\S+)) |

        (
            (service-object\s
                (?P<ip_proto>ah|eigrp|esp|gre|igmp|igrp|ip|ipinip|ipsec|nos|ospf|pcp|pim|snp|icmp)\s*$
            ) |
            (service-object\s(?P<ip_protocol_num>\d+)) |
            (service-object\s
                icmp\s
                (?P<icmp_type>\S+)?\s*(?P<icmp_code>\S+)\s*$
            ) |
            (service-object\s(?P<protocol>tcp|udp)\s*
                (source\s
                    (?P<s_op>eq|lt|gt|neq|range)\s
                    (?P<sport1>\S+)[ ]*
                    (?P<sport2>\S+)?
                )?\s*
                (destination\s
                    (?P<d_op>eq|lt|gt|neq|range)\s
                    (?P<dport1>\S+)[ ]*
                    (?P<dport2>\S+)?
                )?\s*
            )
        ) |

        (group-object\s(?P<obj_gp>\S+)\s*)
    )


		`,
		"name":  "service",
		"flags": "mx",
		"pcre":  "true",
	}

	result, err := text.SplitterProcessOneTime(regexMap, cli)
	if err != nil {
		panic(err)
	}

	obj := &asaService{
		catagory: firewall.GROUP_SERVICE,
		cli:      cli,
		name:     infoMap["name"],
	}
	obj.service = &service.Service{}
	for it := result.Iterator(); it.HasNext(); {
		_, _, resultMap := it.Next()
		if resultMap["op"] != "" {
			protocol := infoMap["additions"]
			s1, err := ASAPortParse(resultMap["s1"], protocol)
			if err != nil {
				panic(err)
			}

			s2 := -1
			if resultMap["s2"] != "" {
				s2, err = ASAPortParse(resultMap["s2"], protocol)
				if err != nil {
					panic(err)
				}
			}

			op, err := service.StringToOp(resultMap["op"])
			if err != nil {
				panic(err)
			}

			l4, err := service.NewL4Port(op, s1, s2, 0)
			if err != nil {
				panic(err)
			}

			protocolList := []int{}
			if strings.ToLower(protocol) == "tcp-udp" {
				protocolList = append(protocolList, 17)
				protocolList = append(protocolList, 6)
			} else {
				p, err := ASAParseProtocol(protocol)
				if err != nil {
					panic(err)
				}
				protocolList = append(protocolList, p)
			}

			for _, p := range protocolList {
				s, err := service.NewL4Service(service.IPProto(p), nil, l4)
				if err != nil {
					panic(err)
				}

				obj.service.Add(s)

			}
		} else if resultMap["service_object"] != "" {
			obj.refNames = append(obj.refNames, resultMap["service_object"])
		} else if resultMap["ip_proto"] != "" {
			protocol, err := ASAParseProtocol(resultMap["ip_proto"])
			if err != nil {
				panic(err)
			}

			p, err := service.NewL3Protocol(service.IPProto(protocol))
			if err != nil {
				panic(err)
			}
			obj.service.Add(p)
		} else if resultMap["ip_protocol_num"] != "" {
		} else if resultMap["icmp_type"] != "" {
			it, err := ASAIcmpParse(resultMap["icmp_type"])
			if err != nil {
				panic(err)
			}
			ic := service.ICMP_DEFAULT_CODE
			if resultMap["icmp_code"] != "" {
				if !validator.IsInt(resultMap["icmp_code"]) {
					panic(fmt.Sprintf("current not support icmp code:%s", resultMap["icmp_code"]))
				}
				icParsed, err := strconv.Atoi(resultMap["icmp_code"])
				if err != nil {
					panic(fmt.Sprintf("invalid icmp code:%s", resultMap["icmp_code"]))
				}
				ic = icParsed
			}

			p, err := service.NewICMPProto(service.ICMP, it, ic)
			if err != nil {
				panic(err)
			}

			obj.service.Add(p)
		} else if resultMap["protocol"] != "" {
			var sportL4, dportL4 *service.L4Port
			protocol, err := ASAParseProtocol(resultMap["protocol"])
			if err != nil {
				panic(err)
			}

			if resultMap["s_op"] != "" {
				sport1, err := ASAPortParse(resultMap["sport1"], resultMap["protocol"])
				if err != nil {
					panic(sport1)
				}

				s1, err := ASAPortParse(resultMap["sport1"], resultMap["protocol"])
				if err != nil {
					panic(err)
				}

				s2 := -1
				if resultMap["sport2"] != "" {
					s2, err = ASAPortParse(resultMap["sport2"], resultMap["protocol"])
					if err != nil {
						panic(err)
					}
				}

				op, err := service.StringToOp(resultMap["s_op"])
				if err != nil {
					panic(err)
				}

				sportL4, err = service.NewL4Port(op, s1, s2, 0)
				if err != nil {
					panic(err)
				}
			}
			if resultMap["d_op"] != "" {
				dport1, err := ASAPortParse(resultMap["dport1"], resultMap["protocol"])
				if err != nil {
					panic(dport1)
				}

				d1, err := ASAPortParse(resultMap["dport1"], resultMap["protocol"])
				if err != nil {
					panic(err)
				}

				d2 := -1
				if resultMap["dport2"] != "" {
					d2, err = ASAPortParse(resultMap["dport2"], resultMap["protocol"])
					if err != nil {
						panic(err)
					}
				}

				op, err := service.StringToOp(resultMap["d_op"])
				if err != nil {
					panic(err)
				}

				dportL4, err = service.NewL4Port(op, d1, d2, 0)
				if err != nil {
					panic(err)
				}
			}

			s, err := service.NewL4Service(service.IPProto(protocol), sportL4, dportL4)
			if err != nil {
				panic(err)
			}

			obj.service.Add(s)
		} else if resultMap["obj_gp"] != "" {
			obj.refNames = append(obj.refNames, resultMap["obj_gp"])
		} else {
			panic(fmt.Sprintf("unknown cli:%s", cli))
		}
	}

	return obj
}

func parseObjectGroupNetwork(cli string, infoMap map[string]string) firewall.FirewallNetworkObject {
	regexMap := map[string]string{
		"regex": `(?P<cli>(?P<cmd>(network|group)-object)\s(?P<s1>\S+)[ ]*(?P<s2>\S+)?[ ]*(?P<s3>\S+)?)`,
		"name":  "network",
		"flags": "mx",
		"pcre":  "true",
	}

	result, err := text.SplitterProcessOneTime(regexMap, cli)
	if err != nil {
		panic(err)
	}

	obj := &asaNetwork{
		catagory: firewall.GROUP_NETWORK,
		cli:      cli,
		name:     infoMap["name"],
	}
	obj.network = &network.NetworkGroup{}

	for it := result.Iterator(); it.HasNext(); {
		_, _, resultMap := it.Next()
		if resultMap["cmd"] == "group-object" {
			obj.refNames = append(obj.refNames, resultMap["s1"])
		} else if resultMap["s1"] == "host" {
			net, err := network.ParseIPNet(resultMap["s2"])
			if err != nil {
				panic(err)
			}

			obj.network.Add(net)
		} else if resultMap["s1"] == "object" {
			obj.refNames = append(obj.refNames, resultMap["s2"])
		} else if resultMap["s1"] == "range" {
			// 处理 range 命令：network-object range {start} {end}
			net, err := network.NewNetworkFromString(fmt.Sprintf("%s-%s", resultMap["s2"], resultMap["s3"]))
			if err != nil {
				panic(err)
			}
			obj.network.Add(net)
		} else if resultMap["s2"] != "" {
			net, err := network.NewNetworkFromString(fmt.Sprintf("%s/%s", resultMap["s1"], resultMap["s2"]))
			if err != nil {
				panic(err)
			}
			obj.network.Add(net)
		} else if validator.IsIPv6AddressWithMask(resultMap["s1"]) {
			net, err := network.ParseIPNet(resultMap["s1"])
			if err != nil {
				panic(err)
			}
			obj.network.Add(net)
		} else {
			panic(fmt.Sprintf("unknown error: cli:%s, result:%+v", cli, resultMap))
		}
	}

	return obj
}

func parseObjectNetwork(cli string, infoMap map[string]string) firewall.FirewallNetworkObject {
	regexMap := map[string]string{
		"regex": `
    (host\s(?P<host>\S+)) |
    (fqdn\s(?P<dns>\S+)) |
    (subnet\s(((?P<ip>\S+)\s(?P<mask>\S+)) | (?P<ipv6>\S+))) |
    (range\s(?P<start>\S+)\s(?P<end>\S+))
		`,
		"name":  "network",
		"flags": "mx",
		"pcre":  "true",
	}

	result, err := text.SplitterProcessOneTime(regexMap, cli)
	if err != nil {
		panic(err)
	}

	obj := &asaNetwork{
		catagory: firewall.OBJECT_NETWORK,
		cli:      cli,
		name:     infoMap["name"],
	}
	obj.network = &network.NetworkGroup{}

	for it := result.Iterator(); it.HasNext(); {
		_, _, resultMap := it.Next()

		if resultMap["dns"] != "" {
			panic(fmt.Sprintf("current not support dns object: %s", cli))
		}

		if resultMap["host"] != "" {
			net, err := network.ParseIPNet(resultMap["host"])
			if err != nil {
				panic(err)
			}

			obj.network.Add(net)
		} else if resultMap["ipv6"] != "" {
			net, err := network.ParseIPNet(resultMap["ipv6"])
			if err != nil {
				panic(err)
			}

			obj.network.Add(net)
		} else if resultMap["ip"] != "" {
			net, err := network.ParseIPNet(resultMap["ip"] + "/" + resultMap["mask"])
			if err != nil {
				panic(err)
			}

			obj.network.Add(net)
		} else {
			net, err := network.NewNetworkFromString(resultMap["start"] + "-" + resultMap["end"])
			if err != nil {
				panic(err)
			}

			obj.network.Add(net)
		}
	}

	return obj
}

func (asa *ASAObjectSet) prepare(cli string) {
	regexMap := map[string]string{
		"regex": `^(?P<catagory>object-group|object) (?P<type>\S+) (?P<name>\S+)( (?P<additions>\S+))?`,
		"name":  "prepare",
		"flags": "m",
		"pcre":  "true",
	}

	result, err := text.SplitterProcessOneTime(regexMap, cli)
	if err != nil {
		panic(err)
	}

	for it := result.Iterator(); it.HasNext(); {
		_, _, resultMap := it.Next()
		if resultMap["catagory"] == "object" {
			if resultMap["type"] == "network" {
				obj := parseObjectNetwork(cli, resultMap)
				asa.networkMap[resultMap["name"]] = obj
			}
			if resultMap["type"] == "service" {
				obj := parseObjectService(cli, resultMap)
				asa.serviceMap[resultMap["name"]] = obj
			}
		} else if resultMap["catagory"] == "object-group" {
			if resultMap["type"] == "network" {
				obj := parseObjectGroupNetwork(cli, resultMap)
				asa.networkMap[resultMap["name"]] = obj
			}

			if resultMap["type"] == "service" {
				if resultMap["additions"] == "" {
					obj := parseObjectGroupService(cli, resultMap)
					asa.serviceMap[resultMap["name"]] = obj
				} else {
					obj := parseL4PortObject(cli, resultMap)
					asa.l4portMap[resultMap["name"]] = obj
				}
			}

			if resultMap["type"] == "protocol" {
				obj := parseObjectGroupProtocol(cli, resultMap)
				asa.serviceMap[resultMap["name"]] = obj
			}
			if resultMap["type"] == "icmp-type" {
				obj := parseObjectGroupIcmpType(cli, resultMap)
				asa.serviceMap[resultMap["name"]] = obj
			}

		}
	}
}

func (asa *ASAObjectSet) parseObjectSecion(config string) []string {
	var sections []string
	sectionRegexMap := map[string]string{
		"regex": `(?P<all>^object[^\n]+(?!\n\s*nat)(\n [^\n]+)+)`,
		"name":  "section",
		"flags": "m",
		"pcre":  "true",
	}

	sectionResult, err := text.SplitterProcessOneTime(sectionRegexMap, config)
	if err != nil {
		if err == text.ErrNoMatched {
			return []string{}
		} else {
			panic(err)
		}
	}

	for it := sectionResult.Iterator(); it.HasNext(); {
		_, _, sectionMap := it.Next()
		sections = append(sections, sectionMap["all"])
		asa.prepare(sectionMap["all"])
	}

	return sections

}

func (asa *ASAObjectSet) parseConfig(config string) {
	asa.parseObjectSecion(config)
}

// func (asa *ASAObjectSet) process() {
// for name, obj := range asa.serviceMap {
// fmt.Println(name, obj.Service(asa.serviceMap))
// }
//
// for name, obj := range asa.networkMap {
// fmt.Println(name, obj.Network(asa.networkMap))
// }
//
// }
func (as *ASAObjectSet) GetObjectByNetworkGroup(ng *network.NetworkGroup, searchType firewall.ObjectSearchType) (firewall.FirewallNetworkObject, bool) {
	for _, object := range as.networkMap {
		if object.Network(as.node).Same(ng) {
			switch searchType {
			case firewall.SEARCH_OBJECT_OR_GROUP:
				return object, true
			case firewall.SEARCH_OBJECT:
				if object.Type() == firewall.OBJECT_NETWORK {
					return object, true
				}
			case firewall.SEARCH_GROUP:
				if object.Type() == firewall.GROUP_NETWORK {
					return object, true
				}
			}
		}
	}
	return nil, false
}

func (as *ASAObjectSet) GetObjectByService(ng *service.Service, searchType firewall.ObjectSearchType) (firewall.FirewallServiceObject, bool) {
	for _, object := range as.serviceMap {
		if object.Service(as.node).Same(ng) {
			switch searchType {
			case firewall.SEARCH_OBJECT_OR_GROUP:
				return object, true
			case firewall.SEARCH_OBJECT:
				if object.Type() == firewall.OBJECT_SERVICE {
					return object, true
				}

			case firewall.SEARCH_GROUP:
				if object.Type() == firewall.GROUP_SERVICE {
					return object, true
				}
			}
		}
	}
	return nil, false
}

func (as *ASAObjectSet) Network(zone, name string) (*network.NetworkGroup, string, bool) {
	if obj, ok := as.networkMap[name]; ok {
		return obj.Network(as.node), obj.Cli(), ok
	} else {
		return nil, "", false
		// ng := obj.Network(as.node)
		// return ng, "", true
	}
}

func (as *ASAObjectSet) Service(name string) (*service.Service, string, bool) {
	if obj, ok := as.serviceMap[name]; ok {
		ng := obj.Service(as.node)
		return ng, "", true
	} else {
		return nil, "", false
	}
}

func (as *ASAObjectSet) L4Port(name string) (*service.L4Port, bool) {
	if obj, ok := as.l4portMap[name]; !ok {
		return nil, ok
	} else {
		ng := obj.L4Port(as.l4portMap)
		return ng, true
	}
}

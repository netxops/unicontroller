package asa

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

	"github.com/davecgh/go-spew/spew"
)

// type NatRuleSet struct{}
//
// type firewall.NatType int
//
// const (
// firewall.STATIC_NAT firewall.NatType = iota + 1
// firewall.DYNAMIC_NAT
// )

type AsaNatStatus int

const (
	ASA_NAT_ACTIVE AsaNatStatus = iota
	ASA_NAT_INACTIVE
)

// type firewall.NatMatchState int
//
// const (
// ASA_NAT_MATCH_NONE firewall.NatMatchState = iota
// ASA_NAT_MATCH_OK
// ASA_NAT_MATCH_NOT_OK
// )

type NatRule struct {
	objects            *ASAObjectSet
	name               string
	node               *ASANode
	from               string
	to                 string
	natType            firewall.NatType
	afterAuto          bool
	cli                string
	status             AsaNatStatus
	orignal            policy.PolicyEntryInf
	translate          policy.PolicyEntryInf
	realSrcObject      string
	realSrcObjectCli   string
	mappedSrcObject    string
	mappedSrcObjectCli string
	mappedDstObject    string
	mappedDstObjectCli string
	realDstObject      string
	realDstObjectCli   string
	realSrvObject      string
	realSrvObjectCli   string
	mappedSrvObject    string
	mappedSrvObjectCli string
}

// 实现 TypeInterface 接口
func (nr *NatRule) TypeName() string {
	return "ASANatRule"
}

// natRuleJSON 用于序列化和反序列化
type natRuleJSON struct {
	Name               string           `json:"name"`
	From               string           `json:"from"`
	To                 string           `json:"to"`
	NatType            firewall.NatType `json:"nat_type"`
	AfterAuto          bool             `json:"after_auto"`
	CLI                string           `json:"cli"`
	Status             AsaNatStatus     `json:"status"`
	Original           json.RawMessage  `json:"original"`
	Translate          json.RawMessage  `json:"translate"`
	RealSrcObject      string           `json:"real_src_object"`
	RealSrcObjectCli   string           `json:"real_src_object_cli"`
	MappedSrcObject    string           `json:"mapped_src_object"`
	MappedSrcObjectCli string           `json:"mapped_src_object_cli"`
	MappedDstObject    string           `json:"mapped_dst_object"`
	MappedDstObjectCli string           `json:"mapped_dst_object_cli"`
	RealDstObject      string           `json:"real_dst_object"`
	RealDstObjectCli   string           `json:"real_dst_object_cli"`
	RealSrvObject      string           `json:"real_srv_object"`
	RealSrvObjectCli   string           `json:"real_srv_object_cli"`
	MappedSrvObject    string           `json:"mapped_srv_object"`
	MappedSrvObjectCli string           `json:"mapped_srv_object_cli"`
}

// MarshalJSON 实现 JSON 序列化
func (nr *NatRule) MarshalJSON() ([]byte, error) {
	originalRaw, err := json.Marshal(nr.orignal)
	if err != nil {
		return nil, err
	}

	translateRaw, err := json.Marshal(nr.translate)
	if err != nil {
		return nil, err
	}

	return json.Marshal(natRuleJSON{
		Name:               nr.name,
		From:               nr.from,
		To:                 nr.to,
		NatType:            nr.natType,
		AfterAuto:          nr.afterAuto,
		CLI:                nr.cli,
		Status:             nr.status,
		Original:           originalRaw,
		Translate:          translateRaw,
		RealSrcObject:      nr.realSrcObject,
		RealSrcObjectCli:   nr.realSrcObjectCli,
		MappedSrcObject:    nr.mappedSrcObject,
		MappedSrcObjectCli: nr.mappedSrcObjectCli,
		MappedDstObject:    nr.mappedDstObject,
		MappedDstObjectCli: nr.mappedDstObjectCli,
		RealDstObject:      nr.realDstObject,
		RealDstObjectCli:   nr.realDstObjectCli,
		RealSrvObject:      nr.realSrvObject,
		RealSrvObjectCli:   nr.realSrvObjectCli,
		MappedSrvObject:    nr.mappedSrvObject,
		MappedSrvObjectCli: nr.mappedSrvObjectCli,
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
	nr.natType = nrj.NatType
	nr.afterAuto = nrj.AfterAuto
	nr.cli = nrj.CLI
	nr.status = nrj.Status
	nr.realSrcObject = nrj.RealSrcObject
	nr.realSrcObjectCli = nrj.RealSrcObjectCli
	nr.mappedSrcObject = nrj.MappedSrcObject
	nr.mappedSrcObjectCli = nrj.MappedSrcObjectCli
	nr.mappedDstObject = nrj.MappedDstObject
	nr.mappedDstObjectCli = nrj.MappedDstObjectCli
	nr.realDstObject = nrj.RealDstObject
	nr.realDstObjectCli = nrj.RealDstObjectCli
	nr.realSrvObject = nrj.RealSrvObject
	nr.realSrvObjectCli = nrj.RealSrvObjectCli
	nr.mappedSrvObject = nrj.MappedSrvObject
	nr.mappedSrvObjectCli = nrj.MappedSrvObjectCli

	// 反序列化 Original
	var original policy.PolicyEntryInf
	if err := json.Unmarshal(nrj.Original, &original); err != nil {
		return err
	}
	nr.orignal = original

	// 反序列化 Translate
	var translate policy.PolicyEntryInf
	if err := json.Unmarshal(nrj.Translate, &translate); err != nil {
		return err
	}
	nr.translate = translate

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
	return map[string]interface{}{}
}
func (rule *NatRule) match(from, to string, entry policy.PolicyEntryInf) firewall.NatMatchState {
	if rule.status == ASA_NAT_INACTIVE {
		return firewall.NAT_MATCH_NONE
	}

	if rule.natType == firewall.STATIC_NAT {
		if rule.from == "any" || rule.to == "any" {
		} else {
			if from != rule.from && from != rule.to {
				return firewall.NAT_MATCH_NONE
			}
		}

		if to == "" {
			if from == rule.from || rule.to == "any" {
				firewall.PrintDebug("rule.orignal", rule.orignal, "entry", entry)
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
				firewall.PrintDebug("translate reverse", reverse, "entry", entry)
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
		if from == rule.from && to == rule.to {
			firewall.PrintDebug("rule.orignal", rule.orignal, "entry", entry)
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

// func (rule *NatRule) natTranslate(from, to string, entry *policy.Intent) (bool, policy.PolicyEntryInf, firewall.MeetIntentStatus) {
// var meetStatus firewall.MeetIntentStatus
// state := rule.match(from, to, entry)
// if state == ASA_NAT_MATCH_NONE || state == ASA_NAT_MATCH_NOT_OK {
// return false, nil, firewall.MEET_INTENT_NO
// }
// if rule.natType == firewall.STATIC_NAT {
// if from == rule.from {
// ok, tranlateTo, msg := entry.Translate(rule.translate)
// if !ok {
// panic(msg)
// }
//
// intentGen := entry.GenerateIntentPolicyEntry()
// translateGen := rule.translate.GenerateSorucePolicyEntry()
// if translateGen.IsSame(intentGen) {
// meetStatus = firewall.MEET_INTENT_OK
// }
//
// return true, tranlateTo, meetStatus
// } else {
// reverse := rule.translate.Reverse()
// ok, tranlateTo, msg := entry.Translate(reverse)
// if !ok {
// panic(msg)
// }
//
// intentGen := entry.GenerateIntentPolicyEntry()
// translateGen := reverse.GenerateSorucePolicyEntry()
// if translateGen.IsSame(intentGen) {
// meetStatus = firewall.MEET_INTENT_OK
// }
//
// return true, tranlateTo, meetStatus
// }
// } else {
// ok, tranlateTo, msg := entry.Translate(rule.translate)
// if !ok {
// panic(msg)
// }
// intentGen := entry.GenerateIntentPolicyEntry()
// translateGen := rule.translate.GenerateSorucePolicyEntry()
// if translateGen.IsSame(intentGen) {
// meetStatus = firewall.MEET_INTENT_OK
// }
//
// return true, tranlateTo, meetStatus
// }
// }

func (rule *NatRule) natTranslate(from, to string, entry *policy.Intent) (bool, policy.PolicyEntryInf) {
	// var meetStatus firewall.MeetIntentStatus
	state := rule.match(from, to, entry)
	if state == firewall.NAT_MATCH_NONE || state == firewall.NAT_MATCH_NOT_OK {
		return false, nil
	}
	if rule.natType == firewall.STATIC_NAT {
		if from == rule.from {
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

func (rule *NatRule) parseTwiceConfig(cli string) {
	orignal := policy.NewPolicyEntry()
	translate := policy.NewPolicyEntry()

	// nat [(real_ifc,mapped_ifc)] [line | {after-object [line]}] source static real_ob [mapped_obj | interface [ipv6]] [destination static {mapped_obj | interface [ipv6]} real_obj] [service real_src_mapped_dest_svc_obj mapped_src_real_dest_svc_obj] [net-to-net] [dns] [unidirectional | no-proxy-arp] [inactive] [description desc]
	// nat (inside,outside) source static 0.0.0.0/0 0.0.0.0/0 destination static 203.0.113.100 10.1.1.100 service TCP_80 TCP_8080
	// nat (inside,outside) source static 0.0.0.0/0 0.0.0.0/0 destination static 203.0.113.100 10.1.1.100 service TCP_80 TCP_8080
	// Ports—(Optional.) Specify the service keyword along with the real and mapped service objects. For source port translation, the objects must specify the source service.
	// The order of the service objects in the command for source port translation is service real_obj mapped_obj.
	// For destination port translation, the objects must specify the destination service.
	// The order of the service objects for destination port translation is service mapped_obj real_obj.
	// In the rare case where you specify both the source and destination ports in the object, the first service object contains the real source port/mapped destination port;
	// the second service object contains the mapped source port/real destination port.
	// For identity port translation, simply use the same service object for both the real and mapped ports (source and/or destination ports, depending on your configuration).
	//
	// 例子：
	// hostname(config)# nat (inside,dmz) source static MyInsNet MyInsNet_mapped destination static Server1 Server1 service REAL_SRC_SVC MAPPED_SRC_SVC
	natRegexMap := map[string]string{
		"regex": `
            ^nat\s\( (?P<real_ifc>.*?),(?P<mapped_ifc>.*?) \)?  \s
            (?P<after_auto>after-auto)?\s*
            source\s
            (?P<nat_type>\S+)\s

            (?P<real_src>\S+)\s
            (
                (
                    (pat-pool\s
                        (
                            (?P<pat_src_ifc>interface) |
                            ((?P<pat_obj>\S+)([ ](?P<pat_obj_src_ifc>interface))?)
                        )
                    ) | 
                    (?P<src_ifc>interface) |
                    (?P<mapped_src_obj>\S+)
                )
                (\s
                    (
                        (?P<mapped_fallback_ifc>interface) 
                    )
                )?

            )\s*

            (
                destination\s
                static\s
                (?P<mapped_dest>\S+)\s
                (?P<real_dest>\S+)\s*
            )?
            (
                service\s
                (?P<real_svc>\S+)\s
                (?P<mapped_svc>\S+)\s*
            )?
            (?P<dns>dns)?\s*
            (?P<state>inactive)?\s*
		`,
		"name":  "nat",
		"flags": "mx",
		"pcre":  "true",
	}

	natResult, err := text.SplitterProcessOneTime(natRegexMap, cli)
	if err != nil {
		panic(err)
	}

	natMap, ok := natResult.One()
	if !ok {
		panic(fmt.Sprintf("parse nat config failed, cli: %s", cli))
	}

	realSrc := network.NewNetworkGroup()
	realDst := network.NewNetworkGroup()
	mappedSrc := network.NewNetworkGroup()
	mappedDst := network.NewNetworkGroup()
	realService := &service.Service{}
	mappedService := &service.Service{}

	if natMap["real_src"] != "" {
		switch natMap["real_src"] {
		case "any":
			net, _ := network.ParseIPNet("0.0.0.0/0")
			realSrc.Add(net)
		default:
			ng, objCli, ok := rule.objects.Network("", natMap["real_src"])
			if !ok {
				panic(fmt.Sprintf("get network object failed, obj:%s, cli:%s", natMap["real_src"], cli))
			}

			rule.realSrcObject = natMap["real_src"]
			rule.realSrcObjectCli = objCli
			realSrc.AddGroup(ng)
		}
	} else {
		panic(fmt.Sprintf("parse real source address failed, cli:%s, map:%+v", cli, natMap))
	}

	if natMap["src_ifc"] != "" || natMap["pat_src_ifc"] != "" {
		var portName string
		if v, ok := natMap["real_ifc"]; ok {
			portName = v
		}

		ipv4 := rule.node.GetPortByNameOrAlias(portName).(*ASAPort).MainIpv4()
		ipv6 := rule.node.GetPortByNameOrAlias(portName).(*ASAPort).MainIpv6()
		if realSrc.IsIPv4() {
			if ipv4 != "" {
				net, err := network.ParseIPNet(ipv4)
				if err != nil {
					panic(err)
				}
				net, _ = network.ParseIPNet(net.IP.String())
				mappedSrc.Add(net)
			}
		}
		if realSrc.IsIPv6() {
			if ipv6 != "" {
				net, err := network.ParseIPNet(ipv6)
				if err != nil {
					panic(err)
				}
				net, _ = network.ParseIPNet(net.IP.String())
				mappedSrc.Add(net)
			}

		}
	} else if natMap["mapped_src_obj"] != "" {
		if natMap["mapped_src_obj"] == "any" {
			net, _ := network.ParseIPNet("0.0.0.0/0")
			mappedSrc.Add(net)
		} else {
			net, objCli, ok := rule.objects.Network("", natMap["mapped_src_obj"])
			if !ok {
				panic(fmt.Sprintf("can not find address object: %s", natMap["mapped_src_obj"]))
			}
			rule.mappedSrcObject = natMap["mapped_src_obj"]
			rule.mappedSrcObjectCli = objCli
			mappedSrc.AddGroup(net)
		}
	} else {
		if natMap["pat_obj"] != "" {
			net, objCli, ok := rule.objects.Network("", natMap["pat_obj"])
			if !ok {
				panic(fmt.Sprintf("can not find address object: %s", natMap["pat_obj"]))
			}

			rule.mappedSrcObject = natMap["pat_obj"]
			rule.mappedSrcObjectCli = objCli
			mappedSrc.AddGroup(net)
		} else {
			panic(fmt.Sprintf("NatRule parse failed, map: %+v", natMap))
		}
	}

	if natMap["mapped_dest"] != "" {
		if natMap["mapped_dest"] == "interface" {
			var portName string
			if v, ok := natMap["real_ifc"]; ok {
				portName = v
			}

			ipv4 := rule.node.GetPortByNameOrAlias(portName).(*ASAPort).MainIpv4()
			ipv6 := rule.node.GetPortByNameOrAlias(portName).(*ASAPort).MainIpv6()
			if realSrc.IsIPv4() {
				if ipv4 != "" {
					net, err := network.ParseIPNet(ipv4)
					if err != nil {
						panic(err)
					}
					net, _ = network.ParseIPNet(net.IP.String())
					mappedDst.Add(net)
				}

			}
			if realSrc.IsIPv6() {
				if ipv6 != "" {
					net, err := network.ParseIPNet(ipv6)
					if err != nil {
						panic(err)
					}
					net, _ = network.ParseIPNet(net.IP.String())
					mappedDst.Add(net)
				}
			}

		} else {
			net, objCli, ok := rule.objects.Network("", natMap["mapped_dest"])
			if !ok {
				panic(fmt.Sprintf("can not find address object: %s", natMap["mapped_dest"]))
			}

			rule.mappedDstObject = natMap["mapped_dest"]
			rule.mappedDstObjectCli = objCli
			mappedDst.AddGroup(net)
		}
	}

	if natMap["real_dest"] != "" {
		if natMap["real_dest"] == "any" {
			net, _ := network.ParseIPNet("0.0.0.0/0")
			realDst.Add(net)
		} else {
			net, objCli, ok := rule.objects.Network("", natMap["real_dest"])
			if !ok {
				panic(fmt.Sprintf("can not find address object: %s", natMap["real_dest"]))
			}
			rule.realDstObject = natMap["real_dest"]
			rule.realDstObjectCli = objCli
			realDst.AddGroup(net)
		}
	}

	if natMap["real_svc"] != "" {
		s, objCli, ok := rule.objects.Service(natMap["real_svc"])
		if !ok {
			panic(fmt.Sprintf("can not find service object: %s", natMap["real_svc"]))
		}
		rule.realSrvObject = natMap["real_svc"]
		rule.realSrvObjectCli = objCli
		realService.Add(s)
	}

	if natMap["mapped_svc"] != "" {
		if natMap["mapped_svc"] == "any" {
			s := realService.Copy().(*service.Service)
			mappedService.Add(s)
		} else {
			s, objCli, ok := rule.objects.Service(natMap["mapped_svc"])
			if !ok {
				panic(fmt.Sprintf("can not find service object: %s", natMap["real_svc"]))
			}
			rule.mappedSrvObject = natMap["mapped_svc"]
			rule.mappedSrvObjectCli = objCli
			mappedService.Add(s)
		}
	}

	orignal.AddSrc(realSrc)

	if realDst.IsEmpty() {
		if realSrc.IsIPv4() {
			net, _ := network.ParseIPNet("0.0.0.0/0")
			realDst.Add(net)
		} else {
			net, _ := network.ParseIPNet("::/0")
			realDst.Add(net)
		}
	}
	orignal.AddDst(realDst)

	if realService.IsEmpty() {
		s := service.NewL3ProtocolFromString("ip")
		realService.Add(s)
	}
	orignal.AddService(realService)

	translate.AddSrc(mappedSrc)

	if mappedService.IsEmpty() {
		s := service.NewL3ProtocolFromString("ip")
		mappedService.Add(s)
	}
	translate.AddService(mappedService)

	if mappedDst.IsEmpty() {
		if realSrc.IsIPv4() {
			net, _ := network.ParseIPNet("0.0.0.0/0")
			mappedDst.Add(net)
		} else {
			net, _ := network.ParseIPNet("::/0")
			mappedDst.Add(net)
		}
	}
	translate.AddDst(mappedDst)

	rule.orignal = orignal
	rule.translate = translate
	if natMap["nat_type"] == "static" {
		rule.natType = firewall.STATIC_NAT
	} else {
		rule.natType = firewall.DYNAMIC_NAT
	}

	if natMap["status"] == "inactive" {
		rule.status = ASA_NAT_INACTIVE
	} else {
		rule.status = ASA_NAT_ACTIVE
	}
	rule.from = natMap["real_ifc"]
	rule.to = natMap["mapped_ifc"]
	rule.cli = cli
	if _, ok := natMap["after_auto"]; ok {
		rule.afterAuto = true
	} else {
		rule.afterAuto = false
	}
	// fmt.Println("----------------->>>", cli)
	// fmt.Println("----------------->>>orignal:", orignal)
	// fmt.Println("----------------->>>translate:", translate)
}

func (rule *NatRule) parseObjectNat(cli string) {
	natRegexMap := map[string]string{
		"regex": `
			(?P<object>object)\s
			network\s
			(?P<object_name>\S+)[\r\n]+
			\s+nat\s+\( (?P<real_ifc>.*?),(?P<mapped_ifc>.*?) \)?  \s+
			(?P<nat_type>\S+)\s+
			(?P<mapped>\S+)\s*
			(
				service\s+
				(?P<protocol>\S+)\s+
				(?P<real_port>\S+)\s+
				(?P<mapped_port>\S+)\s*
			)?
			(?P<dns>dns)?
			(?P<state>inactive)?\s*
		`,
		"name":  "nat",
		"flags": "mx",
		"pcre":  "true",
	}

	natResult, err := text.SplitterProcessOneTime(natRegexMap, cli)
	if err != nil {
		panic(err)
	}

	natMap, ok := natResult.One()
	if !ok {
		panic(fmt.Sprintf("parse nat config failed, cli: %s", cli))
	}

	realSrc := network.NewNetworkGroup()
	realDst := network.NewNetworkGroup()
	mappedSrc := network.NewNetworkGroup()
	mappedDst := network.NewNetworkGroup()
	realService := &service.Service{}
	mappedService := &service.Service{}

	objName := natMap["object_name"]
	realObject, _, ok := rule.objects.Network("", objName)
	if !ok {
		panic(fmt.Sprintf("can not find address object: %s", objName))
	}
	realSrc.AddGroup(realObject)

	if natMap["mapped"] == "interface" {
		var portName string
		if v, ok := natMap["mapped_ifc"]; ok {
			portName = v
		}

		ipv4 := rule.node.GetPortByNameOrAlias(portName).(*ASAPort).MainIpv4()
		ipv6 := rule.node.GetPortByNameOrAlias(portName).(*ASAPort).MainIpv6()
		if realSrc.IsIPv4() {
			if ipv4 != "" {
				net, err := network.ParseIPNet(ipv4)
				if err != nil {
					panic(err)
				}
				net, _ = network.ParseIPNet(net.IP.String())
				mappedSrc.Add(net)
			}

		}
		if realSrc.IsIPv6() {
			if ipv6 != "" {
				net, err := network.ParseIPNet(ipv6)
				if err != nil {
					panic(err)
				}
				net, _ = network.ParseIPNet(net.IP.String())
				mappedSrc.Add(net)
			}

		}

	} else if natMap["mapped"] != "" {
		// 先检查是否有对应的对象
		ng, objCli, ok := rule.objects.Network("", natMap["mapped"])
		if ok {
			// 对象存在，使用对象
			rule.mappedSrcObject = natMap["mapped"]
			rule.mappedSrcObjectCli = objCli
			mappedSrc.AddGroup(ng)
		} else {
			// 对象不存在，尝试解析 IP 地址
			net, err := network.ParseIPNet(natMap["mapped"])
			if err != nil {
				panic(fmt.Sprintf("can not find address object and can not parse as IP address: %s", natMap["mapped"]))
			}
			mappedSrc.Add(net)
		}
	}

	if natMap["protocol"] != "" {
		p, err := ASAParseProtocol(natMap["protocol"])
		if err != nil {
			panic(err)
		}

		port, err := ASAPortParse(natMap["real_port"], natMap["protocol"])
		if err != nil {
			panic(err)
		}

		// func NewL4Port(op L4PortOperator, port int, port2 int, base int) (*L4Port, error) {
		srcL4Port, err := service.NewL4Port(service.EQ, port, -1, 0)
		if err != nil {
			panic(err)
		}

		realS, err := service.NewService(service.IPProto(p), srcL4Port, nil, service.ICMP_TYPE_NIL, service.ICMP_CODE_NIL)
		if err != nil {
			panic(err)
		}

		realService.Add(realS)

		// 处理 mapped_port，创建 mappedService
		if natMap["mapped_port"] != "" {
			mappedPort, err := ASAPortParse(natMap["mapped_port"], natMap["protocol"])
			if err != nil {
				panic(err)
			}

			mappedL4Port, err := service.NewL4Port(service.EQ, mappedPort, -1, 0)
			if err != nil {
				panic(err)
			}

			mappedS, err := service.NewService(service.IPProto(p), mappedL4Port, nil, service.ICMP_TYPE_NIL, service.ICMP_CODE_NIL)
			if err != nil {
				panic(err)
			}

			mappedService.Add(mappedS)
		}
	}

	orignal := policy.NewPolicyEntry()
	translate := policy.NewPolicyEntry()
	orignal.AddSrc(realSrc)

	if realService.IsEmpty() {
		s := service.NewL3ProtocolFromString("ip")
		realService.Add(s)
	}
	orignal.AddService(realService)

	if realSrc.IsIPv4() {
		net, _ := network.ParseIPNet("0.0.0.0/0")
		realDst.Add(net)
	} else {
		net, _ := network.ParseIPNet("::/0")
		realDst.Add(net)
	}
	orignal.AddDst(realDst)

	translate.AddSrc(mappedSrc)

	if mappedService.IsEmpty() {
		s := service.NewL3ProtocolFromString("ip")
		mappedService.Add(s)
	}
	translate.AddService(mappedService)

	if realSrc.IsIPv4() {
		net, _ := network.ParseIPNet("0.0.0.0/0")
		mappedDst.Add(net)
	} else {
		net, _ := network.ParseIPNet("::/0")
		mappedDst.Add(net)
	}
	translate.AddDst(mappedDst)

	rule.cli = cli
	rule.orignal = orignal
	rule.translate = translate

	if natMap["nat_type"] == "static" {
		rule.natType = firewall.STATIC_NAT
	} else {
		rule.natType = firewall.DYNAMIC_NAT
	}

	if natMap["status"] == "inactive" {
		rule.status = ASA_NAT_INACTIVE
	} else {
		rule.status = ASA_NAT_ACTIVE
	}

	rule.from = natMap["real_ifc"]
	rule.to = natMap["mapped_ifc"]

	rule.name = natMap["object_name"]

	// fmt.Println("----------->>>", cli)
	// fmt.Println("----------->>>orignal:", orignal)
	// fmt.Println("----------->>>translate:", translate)
}

type Nats struct {
	TwiceNat  []*NatRule
	ObjectNat []*NatRule
	AfterAuto []*NatRule
	objects   *ASAObjectSet
	node      *ASANode
}

// 实现 TypeInterface 接口
func (n *Nats) TypeName() string {
	return "ASANats"
}

// natsJSON 用于序列化和反序列化
type natsJSON struct {
	TwiceNat  []*NatRule `json:"twice_nat"`
	ObjectNat []*NatRule `json:"object_nat"`
	AfterAuto []*NatRule `json:"after_auto"`
}

// MarshalJSON 实现 JSON 序列化
func (n *Nats) MarshalJSON() ([]byte, error) {
	return json.Marshal(natsJSON{
		TwiceNat:  n.TwiceNat,
		ObjectNat: n.ObjectNat,
		AfterAuto: n.AfterAuto,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (n *Nats) UnmarshalJSON(data []byte) error {
	var nj natsJSON
	if err := json.Unmarshal(data, &nj); err != nil {
		return err
	}

	n.TwiceNat = nj.TwiceNat
	n.ObjectNat = nj.ObjectNat
	n.AfterAuto = nj.AfterAuto

	// objects 和 node 字段被忽略，需要在其他地方单独设置

	return nil
}

func (nat *Nats) parseSection(config string) []string {
	sectionRegexMap := map[string]string{
		"regex": `(?P<all>(^object network[^\n]+\n\s*nat.*?$)|(^nat \(.*?$))`,
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

	var sections []string
	for it := sectionResult.Iterator(); it.HasNext(); {
		_, _, sectionMap := it.Next()
		sections = append(sections, sectionMap["all"])
	}

	return sections
}

func (nat *Nats) parseConfig(config string) {
	sections := nat.parseSection(config)
	for _, cli := range sections {
		rule := &NatRule{
			objects: nat.objects,
			node:    nat.node,
		}
		if strings.Index(cli, "object network") > -1 {
			rule.parseObjectNat(cli)
			nat.ObjectNat = append(nat.ObjectNat, rule)
		} else {
			rule.parseTwiceConfig(cli)
			if rule.afterAuto {
				nat.AfterAuto = append(nat.AfterAuto, rule)
			} else {
				nat.TwiceNat = append(nat.TwiceNat, rule)
				spew.Dump(rule.orignal)
				spew.Dump(rule.translate)
			}
		}
	}
}

func (nat *Nats) inputNat(intent *policy.Intent, inPort api.Port) (bool, *policy.Intent, *NatRule) {
	for _, ruleList := range [][]*NatRule{nat.TwiceNat, nat.ObjectNat, nat.AfterAuto} {
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
	for _, ruleList := range [][]*NatRule{nat.TwiceNat, nat.ObjectNat, nat.AfterAuto} {
		for _, rule := range ruleList {
			ok, tranlateTo := rule.natTranslate(inPort.Name(), outPort.Name(), intent)
			if ok {
				return ok, tranlateTo.(*policy.Intent), rule
			}
		}
	}

	return false, nil, nil
}

func (nat *Nats) inputNatTargetCheck(intent *policy.Intent, inPort, outPort api.Port) (bool, *NatRule) {
	// 利用intent的realIp生成新的PolicyEntry，该PolicyEntry的源地址为realIp地址
	target := intent.GenerateIntentPolicyEntry()
	for _, ruleList := range [][]*NatRule{nat.TwiceNat, nat.ObjectNat, nat.AfterAuto} {
		for _, rule := range ruleList {
			ok := rule.matchDnatTarget(target)
			if ok {
				return true, rule
			}
		}
	}

	return false, nil
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*firewall.FirewallNatRule)(nil)).Elem(), "ASANatRule", reflect.TypeOf(NatRule{}))
}

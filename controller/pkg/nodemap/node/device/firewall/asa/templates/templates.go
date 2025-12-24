package templates

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/name"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/policy"
	"github.com/netxops/utils/service"
	"github.com/netxops/utils/tools"
	"github.com/netxops/utils/validator"

	pongo2 "github.com/flosch/pongo2/v4"
)

// const (
// DEFAULT_OBJECT_NAME_ADDTION = "IP"
// )
type ASATemplates struct {
	*firewall.Naming
}

func NewASATemplates(node firewall.FirewallNode) *ASATemplates {
	return &ASATemplates{
		firewall.NewNaming(node),
	}
}

type templatesInputParams struct {
	// required []string
	// optional []string
	template string
}

var (
	objectNetworkParam = templatesInputParams{
		template: `
		object network {{ objectName }}
		  {{ addressType }} {{ address }}
		`,
	}
	objectNetworkNatParam = templatesInputParams{
		template: `
		object network {{ objectName }}
		  nat ({{ realIfc }},{{ mappedIfc }}) {{ natType }} {{  }}
		`,
	}
)

type TemplateType int

const (
	ASA_OBJECT_NETWORK TemplateType = iota
	ASA_OBJECT_SERVICE
	ASA_OBJECT_NETWORK_DYNAMIC_ADDRESS
	ASA_OBJECT_NETWORK_DYNAMIC_OBJECT
	ASA_OBJECT_NETWORK_DYNAMIC_INTERFACE
	ASA_OBJECT_NETWORK_DYNAMIC_PAT
	ASA_OBJECT_NETWORK_STATIC
	ASA_OBJECT_NETWORK_STATIC_IP
	ASA_OBJECT_NETWORK_DYNAMIC
	ASA_TWICE_NAT

	ASA_NAT_DYNAMIC_OBJECT
	ASA_NAT_DYNAMIC_OBJECT_SERVICE
	ASA_NAT_DYNAMIC_INTERFACE_SERVICE
	ASA_EXTENDED_ACL_L4PORT
	ASA_EXTENDED_ACL_SRV
)

var (
	templateMap = map[TemplateType]string{
		ASA_OBJECT_NETWORK:           "object network {{ objectName}}\n  {{ objectType }} {{ address }}",
		ASA_OBJECT_SERVICE:           "object service {{ objectName}}\n  {{ objectType }} {{ service }}",
		ASA_OBJECT_NETWORK_STATIC:    "object network {{ objectName}}\n  nat ({{from}},{{to}}) {{ natType }} {{ natObject }} {{ serviceCli }}",
		ASA_OBJECT_NETWORK_STATIC_IP: "object network {{ objectName}}\n  nat ({{from}},{{to}}) {{ natType }} {{ natObject }}",
		ASA_OBJECT_NETWORK_DYNAMIC:   "object network {{ objectName}}\n  nat ({{from}},{{to}}) {{ natType }} {{ natObject }}",
		ASA_TWICE_NAT:                "nat ({{from}},{{to}}) source {{natType}} {{realSrcObj}} {{mappedSrcObj}} {{dstCli}} {{serviceCli}}",
		ASA_EXTENDED_ACL_L4PORT:      "access-list {{aclName}} extended {{action}} {{protocol}} {{srcCli}} {{dstCli}} {{l4portCli}}",
		ASA_EXTENDED_ACL_SRV:         "access-list {{aclName}} extended {{action}} {{serviceCli}} {{srcCli}} {{dstCli}}",
	}
)

func (at *ASATemplates) MakeExtendedAccessList(aclName string, intent *policy.Intent) string {
	at.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("OBJ_{{SIMPLE}}", "_", nil))
	at.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("SRV_{{SIMPLE}}", "_", nil))

	var clis = []string{}
	var srcObjectName, dstObjectName, cli string

	var srcCli string
	if intent.Src() == nil || intent.Src().IsEmpty() {
		if intent.Dst().IsIPv4() {
			srcObjectName = "any4"
		} else if intent.Dst().IsIPv6() {
			srcObjectName = "any6"
		} else {
			srcObjectName = "any"
		}
		srcCli = srcObjectName
	} else {
		srcObjectName, cli = at.MakeNetworkGroupCli(intent, intent.Src(), name.REUSE_GROUP_OR_NEW, "")
		if cli != "" {
			clis = append(clis, cli)
		}

		srcCli = fmt.Sprintf("object-group %s", srcObjectName)
	}

	var dstCli string
	if intent.Dst() == nil || intent.Dst().IsEmpty() {
		if intent.Src().IsIPv4() {
			dstObjectName = "any4"
		} else if intent.Src().IsIPv6() {
			dstObjectName = "any6"
		} else {
			dstObjectName = "any"
		}
		dstCli = dstObjectName
	} else {
		dstObjectName, cli = at.MakeNetworkGroupCli(intent, intent.Dst(), name.REUSE_GROUP_OR_NEW, "")
		if cli != "" {
			clis = append(clis, cli)
		}
		dstCli = fmt.Sprintf("object-group %s", dstObjectName)
	}

	var serviceObjectName, l4portObjectName, protocol string
	var l4portCli, serviceCli string
	if intent.Service() == nil || intent.Service().IsEmpty() {
		protocol = "ip"
	} else {
		p := intent.Service().MustProtocol()
		protocol = strings.ToLower(p.String())
		if p == service.IP {
		} else if p == service.TCP || p == service.UDP {
			l4portObjectName, cli = at.MakeL4PortGroupCli(intent, intent.Service(), name.REUSE_GROUP_OR_NEW, "")
			if cli != "" {
				clis = append(clis, cli)
			}
			l4portCli = fmt.Sprintf("object-group %s", l4portObjectName)
		} else {
			serviceObjectName, cli = at.MakeServiceGroupCli(intent, intent.Service(), name.REUSE_OR_NEW, "")
			if cli != "" {
				clis = append(clis, cli)
			}
			serviceCli = fmt.Sprintf("object-group %s", serviceObjectName)
		}
	}

	var tpl *pongo2.Template
	if serviceObjectName != "" {
		tpl, _ = pongo2.FromString(templateMap[ASA_EXTENDED_ACL_SRV])
	} else {
		tpl, _ = pongo2.FromString(templateMap[ASA_EXTENDED_ACL_L4PORT])
	}

	// ASA_EXTENDED_ACL_L4PORT:      "access-list {{aclName}} extended {{action}} {{protocol}} {{srcCli}} {{dstCli}} {{l4portCli}}",
	// ASA_EXTENDED_ACL_SRV:         "access-list {{aclName}} extended {{action}} {{serviceCli}} {{srcCli}} {{dstCli}}",
	var err error
	cli, err = tpl.Execute(pongo2.Context{
		"aclName":    aclName,
		"action":     "permit",
		"protocol":   protocol,
		"srcCli":     srcCli,
		"dstCli":     dstCli,
		"l4portCli":  l4portCli,
		"serviceCli": serviceCli,
	})
	if err != nil {
		panic(err)
	}

	clis = append(clis, cli)

	return strings.Join(clis, "\n")
}

// func (at *ASATemplates) MakeServiceGroupCli(intent *policy.Intent, ng *network.NetworkGroup, rule name.NamingRuleType, additionName string) (objectName, cli string) {
//
// }

func (at *ASATemplates) MakeServiceGroupCli(intent *policy.Intent, sg *service.Service, rule name.NamingRuleType, additionName string) (objectName, cli string) {
	at.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("GRP_{{SIMPLE}}", "_", nil))
	at.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("GRP_{{SIMPLE}}", "_", nil))

	grpFormatter := name.NewFormatter("GRP_{{UUID}}", "_", nil)
	grpFormatter.WithFunc("UUID", name.UUID)
	at.WithFormatter(name.COMPLEX_NETWORK, grpFormatter)

	srpFormatter := name.NewFormatter("GRP_{{UUID}}", "_", nil)
	srpFormatter.WithFunc("UUID", name.UUID)
	at.WithFormatter(name.COMPLEX_SERVICE, srpFormatter)

	clis := []string{}

	input := name.NewServiceNamingInput(intent, sg)
	input.WithRule(rule)
	input.WithAddition(additionName)
	var err error
	var reuse string
	objectName, reuse, err = at.NameService(input)
	if err != nil {
		panic(err)
	}
	if objectName == "" && reuse == "" {
		panic("unknown error")
	}

	if objectName != "" {
		for it := sg.Iterator(); it.HasNext(); {
			_, e := it.Next()
			switch e.(type) {
			case *service.L3Protocol:
				clis = append(clis, fmt.Sprintf("  service-object %s", strings.ToLower(e.Protocol().String())))
			case *service.ICMPProto:
				e.WithStrFunc(func() string {
					icmp := e.(*service.ICMPProto)
					if icmp.IcmpType != service.ICMP_DEFAULT_TYPE {
						if icmp.IcmpCode != service.ICMP_DEFAULT_CODE {
							return fmt.Sprintf("%s %d %d", strings.ToLower(e.Protocol().String()), icmp.IcmpType, icmp.IcmpCode)
						} else {
							return fmt.Sprintf("%s %d", strings.ToLower(e.Protocol().String()), icmp.IcmpType)
						}
					} else {
						return fmt.Sprintf("%s", strings.ToLower(e.Protocol().String()))
					}
				})

				clis = append(clis, fmt.Sprintf("  service-object %s", e.String()))
			case *service.L4Service:
				e.WithStrFunc(func() string {
					ss := []string{}
					l4 := e.(*service.L4Service)
					p := strings.ToLower(e.Protocol().String())

					slist := []string{}
					dlist := []string{}
					if l4.SrcPort() == nil {
						// ss = append(ss, fmt.Sprintf("source range 0 65535"))
					} else {
						sport := l4.SrcPort()
						for it := sport.Iterator(); it.HasNext(); {
							_, s := it.Next()
							if s.Low().Cmp(s.High()) == 0 {
								slist = append(slist, fmt.Sprintf("source eq %d", s.Low()))
							} else {
								slist = append(slist, fmt.Sprintf("source range %d %d", s.Low(), s.High()))
							}
						}
					}

					if l4.DstPort() == nil {
						// ss = append(ss, fmt.Sprintf("destination range 0 65535"))
					} else {
						dport := l4.DstPort()
						for it := dport.Iterator(); it.HasNext(); {
							_, d := it.Next()
							if d.Low().Cmp(d.High()) == 0 {
								dlist = append(dlist, fmt.Sprintf("destination eq %d", d.Low()))
							} else {
								dlist = append(dlist, fmt.Sprintf("destination range %d %d", d.Low(), d.High()))
							}
						}
					}

					if len(slist) == 0 {
						slist = append(slist, "source range 0 65535")
					}

					if len(dlist) == 0 {
						dlist = append(dlist, "destination range 0 65535")
					}

					for _, sl := range slist {
						for _, dl := range dlist {
							ss = append(ss, fmt.Sprintf("%s %s", sl, dl))
						}
					}

					result := []string{}
					for _, d := range ss {
						result = append(result, fmt.Sprintf("  service-object %s %s", p, d))
					}

					return strings.Join(result, "\n")
				})

				clis = append(clis, e.String())
			}
		}

		cli = fmt.Sprintf("object-group service %s\n%s", objectName, strings.Join(clis, "\n"))

		return

	} else {
		objectName = reuse
		return
	}
}

func (at *ASATemplates) MakeL4PortGroupCli(intent *policy.Intent, sg *service.Service, rule name.NamingRuleType, additionName string) (objectName, cli string) {
	at.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("GRP_{{SIMPLE}}", "_", nil))
	at.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("GRP_{{SIMPLE}}", "_", nil))
	grpFormatter := name.NewFormatter("GRP_{{UUID}}", "_", nil)
	grpFormatter.WithFunc("UUID", name.UUID)
	at.WithFormatter(name.COMPLEX_NETWORK, grpFormatter)

	srpFormatter := name.NewFormatter("GRP_{{UUID}}", "_", nil)
	srpFormatter.WithFunc("UUID", name.UUID)
	at.WithFormatter(name.COMPLEX_SERVICE, srpFormatter)

	clis := []string{}

	input := name.NewServiceNamingInput(intent, sg)
	input.WithRule(rule)
	input.WithAddition(additionName)
	var err error
	var reuse string
	objectName, reuse, err = at.NameService(input)
	if err != nil {
		panic(err)
	}
	if objectName == "" && reuse == "" {
		panic("unknown error")
	}

	protocol := sg.MustProtocol()
	if !(protocol == service.TCP || protocol == service.UDP) {
		panic(fmt.Sprintf("%+v, create L4PortGroupCli failed", sg))
	}

	if objectName != "" {
		for it := sg.Iterator(); it.HasNext(); {
			_, e := it.Next()
			switch e.(type) {
			case *service.L3Protocol:
				clis = append(clis, "port-object range 0 65535")
			case *service.L4Service:
				dport := e.(*service.L4Service).DstPort()
				if dport != nil {
					strFunc := func() string {
						cs := []string{}
						for it := dport.Iterator(); it.HasNext(); {
							_, e := it.Next()
							if e.Low().Cmp(e.High()) == 0 {
								cs = append(cs, fmt.Sprintf("  port-object eq %d", e.Low()))
							} else {
								cs = append(cs, fmt.Sprintf("  port-object range %d %d", e.Low(), e.High()))
							}
						}
						return strings.Join(cs, "\n")
					}
					// dport.WithStrFunc(func() string {
					// 	cs := []string{}
					// 	for it := dport.Iterator(); it.HasNext(); {
					// 		_, e := it.Next()
					// 		if e.Low().Cmp(e.High()) == 0 {
					// 			cs = append(cs, fmt.Sprintf("  port-object eq %d", e.Low()))
					// 		} else {
					// 			cs = append(cs, fmt.Sprintf("  port-object range %d %d", e.Low(), e.High()))
					// 		}
					// 	}
					// 	return strings.Join(cs, "\n")
					// })

					clis = append(clis, strFunc())
				} else {
					clis = append(clis, "port-object range 0 65535")
				}
			}
		}
		if len(clis) == 0 {
			panic(fmt.Sprintf("service: %+v, create l4port group failed", sg))
		}

		cli = fmt.Sprintf("object-group service %s %s\n%s", objectName, strings.ToLower(protocol.String()), strings.Join(clis, "\n"))

		return

	} else {
		objectName = reuse
		return
	}
}

func (at *ASATemplates) MakeNetworkGroupCli(intent *policy.Intent, ng *network.NetworkGroup, rule name.NamingRuleType, additionName string) (objectName, cli string) {
	at.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("GRP_{{SIMPLE}}", "_", nil))
	at.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("GRP_{{SIMPLE}}", "_", nil))
	// at.WithFormatter(name.COMPLEX_NETWORK, name.NewFormatter("GRP_{{UUID}}", "_", nil))
	grpFormatter := name.NewFormatter("GRP_{{UUID}}", "_", nil)
	grpFormatter.WithFunc("UUID", name.UUID)
	at.WithFormatter(name.COMPLEX_NETWORK, grpFormatter)
	// at.WithFormatter(name.COMPLEX_SERVICE, name.NewFormatter("SRV_{{UUID}}", "_", nil))

	srpFormatter := name.NewFormatter("GRP_{{UUID}}", "_", nil)
	srpFormatter.WithFunc("UUID", name.UUID)
	at.WithFormatter(name.COMPLEX_SERVICE, srpFormatter)

	clis := []string{}

	input := name.NewNetworkNamingInput(intent, ng)
	input.WithRule(rule)
	input.WithAddition(additionName)
	var err error
	var reuse string
	objectName, reuse, err = at.NameNetwork(input, nil)
	if err != nil {
		panic(err)
	}
	if objectName == "" && reuse == "" {
		panic("unknown error")
	}

	if objectName != "" {
		for _, nl := range []*network.NetworkList{ng.IPv4(), ng.IPv6()} {
			for _, ip := range nl.List() {
				switch ip.AddressType() {
				case network.HOST:
					if ip.Type() == network.IPv4 {
						clis = append(clis, fmt.Sprintf("  network-object %s %s", ip.First().String(), "255.255.255.255"))
					} else {
						clis = append(clis, fmt.Sprintf("  network-object %s/%d", ip.First().String(), 128))
					}
				case network.SUBNET:
					ipnet, _ := ip.IPNet()
					if ip.Type() == network.IPv4 {
						clis = append(clis, fmt.Sprintf("  network-object %s %s", ipnet.IP.String(), network.MasktoIP(ipnet.Mask).String()))
					} else {
						clis = append(clis, fmt.Sprintf("  network-object %s/%d", ipnet.IP.String(), ipnet.Mask.Prefix()))
					}

				case network.RANGE:
					iprange := ip.(*network.IPRange)
					cidrs := iprange.CIDRs()
					if ip.Type() == network.IPv4 {
						for _, ipnet := range cidrs {
							clis = append(clis, fmt.Sprintf("  network-object %s %s", ipnet.IP.String(), network.MasktoIP(ipnet.Mask).String()))
						}
					} else {
						for _, ipnet := range cidrs {
							clis = append(clis, fmt.Sprintf("  network-object %s/%d", ipnet.IP.String(), ipnet.Mask.Prefix()))
						}

					}

				default:
					panic("unknown error")
				}

			}

		}
		if len(clis) == 0 {
			panic("unknow error")
		}

		cli = fmt.Sprintf("object-group network %s\n%s", objectName, strings.Join(clis, "\n"))
		return
	} else {
		objectName = reuse
		return
	}
}

func (at *ASATemplates) MakeTwiceStaticNatCli(from, out api.Port, intent *policy.Intent) string {
	at.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("OBJ_{{SIMPLE}}", "_", nil))
	at.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("SRV_{{SIMPLE}}", "_", nil))
	// at.WithFormatter(name.COMPLEX_NETWORK, name.NewFormatter("OBJ_{{UUID}}", "_", nil))
	// at.WithFormatter(name.COMPLEX_SERVICE, name.NewFormatter("SRV_{{UUID}}", "_", nil))

	grpFormatter := name.NewFormatter("OBJ_{{UUID}}", "_", nil)
	grpFormatter.WithFunc("UUID", name.UUID)
	at.WithFormatter(name.COMPLEX_NETWORK, grpFormatter)

	srpFormatter := name.NewFormatter("SRV_{{UUID}}", "_", nil)
	srpFormatter.WithFunc("UUID", name.UUID)
	at.WithFormatter(name.COMPLEX_SERVICE, srpFormatter)

	// ASA_TWICE_NAT:                "nat ({{from}},{{to}}) source {{natType}} {{realSrcObj}} {{mappedSrcObj}} {{destination}} static {{realDstObj}} {{mappedDstObj}} service {{realService}} {{mappedService}}",
	// 1.首先获取object network名称，必须新建

	clis := []string{}
	// 1、生成realSrcObj和mappedSrcObj
	var err error

	genPe := intent.GenerateIntentPolicyEntry()

	realSrcObj, cli := at.MakeNetworkObjectCli(intent, genPe.Dst(), name.REUSE_OR_NEW, "")
	if cli != "" {
		clis = append(clis, cli)
	}
	var mappedSrcObj string
	mappedSrcObj, cli = at.MakeNetworkObjectCli(intent, intent.Dst(), name.REUSE_OR_NEW, "")
	if cli != "" {
		clis = append(clis, cli)
	}

	// }

	// 3、生成realDstObj

	var dstCli string
	var realDstObj, mappedDstObj string
	if !intent.Dst().IsEmpty() {
		var ng *network.NetworkGroup
		if intent.Src().IsIPv4() {
			ng, _ = network.NewNetworkGroupFromString("0.0.0.0/0")
		} else if intent.Src().IsIPv6() {
			ng, _ = network.NewNetworkGroupFromString("::/0")
		} else {
			panic(fmt.Sprintf("current not support mix ipv4 and ipv6"))
		}
		if !intent.Src().Same(ng) {
			realDstObj, cli = at.MakeNetworkObjectCli(intent, intent.Src(), name.REUSE_OR_NEW, "")
			if cli != "" {
				clis = append(clis, cli)
			}
			mappedDstObj = realDstObj

			dstCli = fmt.Sprintf("destination static %s %s", realDstObj, mappedDstObj)

		}
	}

	// 4、生成realService
	var serviceCli string
	var realService, mappedService string
	if !intent.Service().IsEmpty() && intent.Service().Protocol() != service.IP {
		mappedService, cli = at.MakeServiceObjectCli(intent, intent.Service().Reverse().(*service.Service), name.REUSE_OR_NEW, "")
		if cli != "" {
			clis = append(clis, cli)
		}
		// realService = mappedService
		realService, cli = at.MakeServiceObjectCli(intent, genPe.Service().Reverse().(*service.Service), name.REUSE_OR_NEW, "")
		if cli != "" {
			clis = append(clis, cli)
		}

		serviceCli = fmt.Sprintf("service %s %s", realService, mappedService)
	}

	tpl, _ := pongo2.FromString(templateMap[ASA_TWICE_NAT])

	// 4、生成命令行
	cli, err = tpl.Execute(pongo2.Context{
		// "objectName":    objectName,
		"natType":      "static",
		"realSrcObj":   realSrcObj,
		"mappedSrcObj": mappedSrcObj,
		"dstCli":       dstCli,
		"serviceCli":   serviceCli,
		"from":         out.Name(),
		"to":           from.Name(),
	})
	if err != nil {
		panic(err)
	}

	clis = append(clis, cli)
	return strings.Join(clis, "\n")

	// return ""
}

func (at *ASATemplates) MakeTwiceDynamicNatCli(from, out api.Port, intent *policy.Intent) string {
	at.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("OBJ_{{SIMPLE}}", "_", nil))
	at.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("SRV_{{SIMPLE}}", "_", nil))
	// ASA_TWICE_NAT:                "nat ({{from}},{{to}}) source {{natType}} {{realSrcObj}} {{mappedSrcObj}} {{destination}} static {{realDstObj}} {{mappedDstObj}} service {{realService}} {{mappedService}}",
	// 1.首先获取object network名称，必须新建

	clis := []string{}
	// 1、生成realSrcObj
	var err error

	realSrcObj, cli := at.MakeNetworkObjectCli(intent, intent.Src(), name.REUSE_OR_NEW, "")
	if cli != "" {
		clis = append(clis, cli)
	}

	// 2、生成mappedObj
	var mappedSrcObj string
	ng, _ := network.NewNetworkGroupFromString(intent.Snat)
	mappedSrcObj, cli = at.MakeNetworkObjectCli(intent, ng, name.REUSE_OR_NEW, "")
	if cli != "" {
		clis = append(clis, cli)
	}
	// }

	// 3、生成realDstObj

	var dstCli string
	var realDstObj, mappedDstObj string
	if !intent.Dst().IsEmpty() {
		realDstObj, cli = at.MakeNetworkObjectCli(intent, intent.Dst(), name.REUSE_OR_NEW, "")
		if cli != "" {
			clis = append(clis, cli)
		}
		mappedDstObj = realDstObj

		dstCli = fmt.Sprintf("destination static %s %s", realDstObj, mappedDstObj)
	}

	// 4、生成realService
	var serviceCli string
	var realService, mappedService string
	if !intent.Service().IsEmpty() && intent.Service().Protocol() != service.IP {
		realService, cli = at.MakeServiceObjectCli(intent, intent.Service(), name.REUSE_OR_NEW, "")
		if cli != "" {
			clis = append(clis, cli)
		}
		mappedService = realService
		serviceCli = fmt.Sprintf("service %s %s", realService, mappedService)
	}

	tpl, _ := pongo2.FromString(templateMap[ASA_TWICE_NAT])

	// 4、生成命令行
	cli, err = tpl.Execute(pongo2.Context{
		// "objectName":    objectName,
		"natType":      "dynamic",
		"realSrcObj":   realSrcObj,
		"mappedSrcObj": mappedSrcObj,
		"dstCli":       dstCli,
		"serviceCli":   serviceCli,
		// "from":       from.Name(),
		// "to":         out.Name(),
		"from": from.Name(),
		"to":   out.Name(),
	})
	if err != nil {
		panic(err)
	}

	clis = append(clis, cli)
	return strings.Join(clis, "\n")
}

func (at *ASATemplates) MakeNetworkObjectCli(intent *policy.Intent, ng *network.NetworkGroup, rule name.NamingRuleType, additionName string) (objectName, cli string) {
	at.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("OBJ_{{SIMPLE}}", "_", nil))
	at.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("SRV_{{SIMPLE}}", "_", nil))

	input := name.NewNetworkNamingInput(intent, ng)
	input.WithRule(rule)
	input.WithAddition(additionName)
	var err error
	var reuse string
	objectName, reuse, err = at.NameNetwork(input, nil)
	if err != nil {
		panic(err)
	}
	if objectName == "" && reuse == "" {
		panic("unknown error")
	}

	if objectName != "" {
		tpl, err := pongo2.FromString(templateMap[ASA_OBJECT_NETWORK])
		if err != nil {
			panic(err)
		}

		net := ng.GenerateNetwork()

		var objectType, address string
		switch net.AddressType() {
		case network.HOST:
			objectType = "host"
			address = net.First().String()
		case network.SUBNET:
			objectType = "subnet"
			if net.Type() == network.IPv4 {
				address = fmt.Sprintf("%s %s", net.(*network.IPNet).IP, network.MasktoIP(net.(*network.IPNet).Mask))
			} else {
				address = fmt.Sprintf("%s", net)
			}
		case network.RANGE:
			objectType = "range"
			address = fmt.Sprintf("%s %s", net.(*network.IPRange).First(), net.(*network.IPRange).Last())
		}
		cli, err = tpl.Execute(pongo2.Context{"objectName": objectName, "objectType": objectType, "address": address})
		if err != nil {
			panic(err)
		}

		return

	} else {
		objectName = reuse
		return
	}
}

func (at *ASATemplates) MakeServiceObjectCli(intent *policy.Intent, sg *service.Service, rule name.NamingRuleType, additionName string) (objectName, cli string) {
	at.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("OBJ_{{SIMPLE}}", "_", nil))
	at.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("SRV_{{SIMPLE}}", "_", nil))

	grpFormatter := name.NewFormatter("GRP_{{UUID}}", "_", nil)
	grpFormatter.WithFunc("UUID", name.UUID)
	at.WithFormatter(name.COMPLEX_NETWORK, grpFormatter)

	srpFormatter := name.NewFormatter("SRV_{{UUID}}", "_", nil)
	srpFormatter.WithFunc("UUID", name.UUID)
	at.WithFormatter(name.COMPLEX_SERVICE, srpFormatter)

	input := name.NewServiceNamingInput(intent, sg)
	input.WithRule(rule)
	input.WithAddition(additionName)

	objectName, reuse, err := at.NameService(input)
	if err != nil {
		panic(err)
	}

	if objectName == "" && reuse == "" {
		panic("unknown error")
	}

	if objectName != "" {
		tpl, err := pongo2.FromString(templateMap[ASA_OBJECT_SERVICE])
		if err != nil {
			panic(err)
		}

		s := sg.MustOneServiceEntry()
		var out string
		if s.Protocol() == service.ICMP || s.Protocol() == service.ICMP6 {
			s.WithStrFunc(func() string {
				// var strList []string
				strList := []string{strings.ToLower(s.Protocol().String())}
				switch s.(type) {
				case *service.L3Protocol:
					// strList = []string{"icmp"}
				case *service.ICMPProto:
					if s.(*service.ICMPProto).IcmpType != service.ICMP_DEFAULT_TYPE {
						strList = append(strList, fmt.Sprintf("%d", s.(*service.ICMPProto).IcmpType))
						if s.(*service.ICMPProto).IcmpCode != service.ICMP_DEFAULT_CODE {
							strList = append(strList, fmt.Sprintf("%d", s.(*service.ICMPProto).IcmpCode))
						}
					}
				}
				return strings.Join(strList, " ")
			})

			out = s.String()
		} else if s.Protocol() == service.TCP || s.Protocol() == service.UDP {
			s.WithStrFunc(func() string {
				p := strings.ToLower(s.Protocol().String())
				strList := []string{p}

				l4SrcPort := s.(*service.L4Service).SrcPort()
				l4DstPort := s.(*service.L4Service).DstPort()
				if l4SrcPort == nil {
					// strList = append(strList, "source 0 65535")
				} else {
					if len(l4SrcPort.L) != 1 {
						panic(fmt.Sprintf("current not support multiple src port range, %+v", l4SrcPort.L))
					}
					if l4SrcPort.L[0].Low().Cmp(l4SrcPort.L[0].High()) == 0 {
						strList = append(strList, fmt.Sprintf("source eq %d", l4SrcPort.L[0].Low()))
					} else {
						strList = append(strList, fmt.Sprintf("source range %d %d", l4SrcPort.L[0].Low(), l4SrcPort.L[0].High()))
					}
				}

				if l4DstPort == nil {
					// strList = append(strList, "source 0 65535")
				} else {
					if len(l4DstPort.L) != 1 {
						panic(fmt.Sprintf("current not support multiple dst port range, %+v", l4DstPort.L))
					}
					if l4DstPort.L[0].Low().Cmp(l4DstPort.L[0].High()) == 0 {
						strList = append(strList, fmt.Sprintf("destination eq %d", l4DstPort.L[0].Low()))
					} else {
						strList = append(strList, fmt.Sprintf("destination range %d %d", l4DstPort.L[0].Low(), l4DstPort.L[0].High()))
					}
				}
				return strings.Join(strList, " ")

			})
			out = s.String()
		} else {
			var strList []string
			if s.Protocol() == service.IP {
				strList = []string{"ip"}
			} else {
				strList = []string{fmt.Sprintf("%d", s.Protocol())}
			}
			out = strings.Join(strList, " ")
		}

		cli, err = tpl.Execute(pongo2.Context{"objectName": objectName, "objectType": "service", "service": out})
		if err != nil {
			panic(err)
		}

		return
	} else {
		objectName = reuse
		return
	}
}

// ASA_OBJECT_NETWORK_STATIC: "object network {{ objectName}}\n  {{ natType }} {{ natObject }} {{ service }}",

// ciscoasa(config)# object network obj-192.168.100.210
// ciscoasa(config-network-object)# nat (inside,outside) static ?
//
// network-object mode commands/options:
// A.B.C.D             Mapped IP address
// WORD                Mapped network object/object-group name
// X:X:X:X::X/<0-128>  Enter an IPv6 prefix
// interface           Use interface address as mapped IP
//
// network-object mode commands/options:
// dns           Use the created xlate to rewrite DNS record
// net-to-net    Use Net to net mapping of IPv4 to IPv6 address(es)
// no-proxy-arp  Disable proxy ARP on the egress interface
// route-lookup  Perform route lookup for this rule
// service       Define port mapping
// <cr>
// ciscoasa(config-network-object)# nat (inside,outside) static 1.1.1.1 se
// ciscoasa(config-network-object)# nat (inside,outside) static 1.1.1.1 service ?
//
// network-object mode commands/options:
// sctp  SCTP to be used as transport protocol
// tcp   TCP to be used as transport protocol
// udp   UDP to be used as transport protocol
//
// func (at *ASATemplates) MakeObjectStaticNatCli(n string, from, out api.Port, intent *policy.Intent, ref firewall.ObjectReferenceMethod) string {
func (at *ASATemplates) MakeObjectStaticNatCli(from, out api.Port, intent *policy.Intent) string {
	//
	// 1.以Intent的real_ip为基础创建object，以real_port为addition，方便object name的创建
	// at.MakeNetworkObjectCli(intent, ng *network.NetworkGroup, rule name.NamingRuleType, additionName string) (objectName, cli string) {
	// intent.RealIp
	//
	// chain := validator.NewValidateChain()
	// chain.Add(ASADnatTargetServiceValidator{})
	// chain.Add(ASADnatTargetIsExistValidator{})
	// chain.Add(ASADnatMppaedAddressValidator{})

	// validateResult := chain.Validate(map[string]interface{}{ // "intent":  intent,
	// "node":    at.Node(),
	// "inPort":  from,
	// "outPort": out,
	// })

	// if !validateResult.Status() {
	// panic(validateResult.Msg())
	// }

	at.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("OBJ_{{SIMPLE}}", "_", nil))
	at.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("SRV_{{SIMPLE}}", "_", nil))

	at.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("OBJ_{{SIMPLE}}", "_", nil))

	genPe := intent.GenerateIntentPolicyEntry()

	var targetPort, realPort, addition string
	if genPe.Service().Protocol() == service.IP {

	} else {
		format, _ := tools.NewPairFormatter("%s %s")
		targetPortList := intent.Service().DstPortList(format)
		realPortList := genPe.Service().DstPortList(format)

		if len(targetPortList) != 1 || len(realPortList) != 1 {
			panic(fmt.Sprint("target port:", targetPortList, ", real port:", realPortList))
		}
		targetPort = targetPortList[0]
		realPort = realPortList[0]
		addition = realPort
	}

	clis := []string{}
	// 1、生成object network的名称
	input := name.NewNetworkNamingInput(intent, genPe.Dst())
	input.WithRule(name.NEW)
	input.WithAddition(addition)

	var err error
	// objectName, _, err := at.NameNetwork(input)
	// if err != nil {
	// panic(err)
	// }
	// if at.Node().HasObjectName(objectName) {
	// panic(fmt.Sprint("object name ", objectName, " is exist"))
	// }

	objectName, cli := at.MakeNetworkObjectCli(intent, genPe.Dst(), name.NEW, "")
	clis = append(clis, cli)

	// addressOrObject, cli = at.MakeNetworkObjectCli(intent, intent.Dst(), name.REUSE_OBJECT_OR_NEW, "")
	// clis = append(clis, cli)

	// 2、根据事件情况生成Mapped地址相关信息
	net := intent.Dst().GenerateNetwork()
	var addressOrObject string

	switch net.AddressType() {
	case network.HOST:
		addressOrObject = net.First().String()
	case network.SUBNET:
		if net.Type() == network.IPv4 {
			addressOrObject, cli = at.MakeNetworkObjectCli(intent, intent.Dst(), name.REUSE_OBJECT_OR_NEW, "")
			clis = append(clis, cli)
		} else {
			addressOrObject = fmt.Sprintf("%s", net)
		}
	}

	// 3、针对端口映射，需要生成serviceCli
	var serviceCli, natType, natObject string
	natType = "static"
	natObject = addressOrObject
	var tpl *pongo2.Template
	if realPort != "" {
		// serivce protocol realPort mappedPort
		serviceCli = fmt.Sprintf("service %s %s %s", strings.ToLower(intent.Service().Protocol().String()), realPort, targetPort)
		tpl, err = pongo2.FromString(templateMap[ASA_OBJECT_NETWORK_STATIC])
		if err != nil {
			panic(err)
		}
	} else {
		tpl, err = pongo2.FromString(templateMap[ASA_OBJECT_NETWORK_STATIC_IP])
	}

	// 4、生成命令行
	cli, err = tpl.Execute(pongo2.Context{
		"objectName": objectName,
		"natType":    natType,
		"natObject":  natObject,
		// "from":       from.Name(),
		// "to":         out.Name(),
		"from":       from.Name(),
		"to":         out.Name(),
		"serviceCli": serviceCli,
	})
	if err != nil {
		panic(err)
	}

	clis = append(clis, cli)
	return strings.Join(clis, "\n")
}

// func (at *ASATemplates) MakeObjectDynamicNatCli(from, out api.Port, intent *policy.Intent) string {
func (at *ASATemplates) MakeObjectDynamicNatCli(from, out api.Port, intent *policy.Intent) string {
	// ASA_OBJECT_NETWORK_STATIC: "object network {{ objectName}}\n  nat ({{from},{{to}}}) {{ natType }} {{ natObject }} {{ service }}",
	// 利用intent的real_ip创建object
	//
	at.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("OBJ_{{SIMPLE}}", "_", nil))
	at.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("SRV_{{SIMPLE}}", "_", nil))

	// func (ns *NameStrategy) WithFormatter(selector FormatSelector, format *Formatter) *NameStrategy {

	// 1.首先获取object network名称，必须新建

	clis := []string{}
	// 1、生成object network的名称

	var err error

	objectName, cli := at.MakeNetworkObjectCli(intent, intent.Src(), name.NEW, "")
	clis = append(clis, cli)

	// 2. 创建object network实体
	// at.MakeNetworkObjectCli()

	mapped := intent.Snat
	if mapped == "interface" {
	} else {
		ng, err := network.NewNetworkGroupFromString(mapped)
		if err != nil {
			panic(fmt.Sprintf("parse snat error, snat:%s", mapped))
		}
		if ng.AddressType() == network.HOST {
			mapped = ng.HostList()[0]
		} else {
			mapped, cli = at.MakeNetworkObjectCli(intent, ng, name.REUSE_OBJECT_OR_NEW, "")
			clis = append(clis, cli)
		}
	}

	tpl, _ := pongo2.FromString(templateMap[ASA_OBJECT_NETWORK_DYNAMIC])
	// 4、生成命令行
	cli, err = tpl.Execute(pongo2.Context{
		"objectName": objectName,
		"natType":    "dynamic",
		"natObject":  mapped,
		"from":       from.Name(),
		"to":         out.Name(),
		// "serviceCli": serviceCli,
	})
	if err != nil {
		panic(err)
	}

	clis = append(clis, cli)
	return strings.Join(clis, "\n")

	return ""
}

type ASADnatTargetServiceValidator struct{}

func (dp ASADnatTargetServiceValidator) Validate(data map[string]interface{}) validator.Result {
	var intent *policy.Intent
	var genPe policy.PolicyEntryInf
	var result validator.Result
	func() {
		defer func() {
			if r := recover(); r != nil {
				result = validator.NewValidateResult(false, fmt.Sprint(r))
			}
		}()

		intent = data["intent"].(*policy.Intent)
		genPe = intent.GenerateIntentPolicyEntry()
	}()

	if result != nil {
		return result
	}

	s := genPe.Service().MustSimpleServiceEntry()
	if !(s.Protocol() == service.IP || s.Protocol() == service.TCP || s.Protocol() == service.UDP) {
		return validator.NewValidateResult(false, fmt.Sprint("static nat not support portocol: ", s.Protocol()))
	}

	// var addition string
	switch s.(type) {
	case *service.L3Protocol:
		// addition = fmt.Sprint(s.Protocol())
		if s.Protocol() != service.IP {
			return validator.NewValidateResult(false, fmt.Sprint("static nat not support L3 portocol: ", s.Protocol()))
		}
	case *service.L4Service:
		e := s.(*service.L4Service).DstPort().List()[0]
		if e.Count().Cmp(big.NewInt(1)) != 0 {
			return validator.NewValidateResult(false, fmt.Sprint("static nat not support multiple port: ", s.(*service.L4Service).DstPort()))
		}
		// default:
		// return validator.NewValidateResult(false, fmt.Sprint("unknown error"))
		// panic("unknown error")
	}

	return validator.NewValidateResult(true, "")
}

type ASADnatTargetIsExistValidator struct{}

func (dv ASADnatTargetIsExistValidator) Validate(data map[string]interface{}) validator.Result {
	node := data["node"].(firewall.FirewallNode)
	intent := data["intent"].(*policy.Intent)
	inPort := data["inPort"].(api.Port)
	outPort := data["outPort"].(api.Port)
	ok, rule := node.InputNatTargetCheck(intent, inPort, outPort)
	if ok {
		return validator.NewValidateResult(false, fmt.Sprint("target server nat is exist. ", rule))
	}

	return validator.NewValidateResult(true, "")
}

type ASADnatMppaedAddressValidator struct{}

func (dv ASADnatMppaedAddressValidator) Validate(data map[string]interface{}) validator.Result {
	intent := data["intent"].(*policy.Intent)
	dst := intent.Dst()

	if !(dst.AddressType() == network.HOST || dst.AddressType() == network.SUBNET) {
		return validator.NewValidateResult(false, fmt.Sprint("dnat only support host and subnet, dst: ", dst))
	}

	return validator.NewValidateResult(true, "")
}

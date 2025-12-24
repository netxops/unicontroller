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
	"github.com/netxops/utils/validator"

	"github.com/flosch/pongo2/v4"
)

// MakeStaticNatCli(from, out api.Port, intent *policy.Intent) string
// MakeDynamicNatCli(from, out api.Port, intent *policy.Intent) string
// MakeInputPolicyCli(from, out api.Port, intent *policy.Intent) string
// MakeOutputPolicyCli(from, out api.Port, intent *policy.Intent) string

type SRXTemplates struct {
	*firewall.Naming
}

func NewSRXTemplates(node firewall.FirewallNode) *SRXTemplates {
	return &SRXTemplates{
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
	SRX_OBJECT_NETWORK TemplateType = iota
	SRX_GLOBAL_OBJECT_NETWORK
	SRX_GROUP_NETWORK
	SRX_GLOBAL_GROUP_NETWORK

	SRX_OBJECT_SERVICE
	SRX_OBJECT_NETWORK_DYNAMIC_ADDRESS
	SRX_OBJECT_NETWORK_DYNAMIC_OBJECT
	SRX_OBJECT_NETWORK_DYNAMIC_INTERFACE
	SRX_OBJECT_NETWORK_DYNAMIC_PAT
	SRX_OBJECT_NETWORK_STATIC
	SRX_OBJECT_NETWORK_STATIC_IP
	SRX_OBJECT_NETWORK_DYNAMIC
	SRX_TWICE_NAT

	SRX_NAT_DYNAMIC_OBJECT
	SRX_NAT_DYNAMIC_OBJECT_SERVICE
	SRX_NAT_DYNAMIC_INTERFACE_SERVICE
	SRX_EXTENDED_ACL_L4PORT
	SRX_EXTENDED_ACL_SRV
)

var (
	templateMap = map[TemplateType]string{
		SRX_OBJECT_NETWORK:           "set security zones security-zone {{zone}} address-book address {{objectName}} {{addressCli}}",
		SRX_GLOBAL_OBJECT_NETWORK:    "set address-book global address {{name}} {{addressCli}}",
		SRX_GROUP_NETWORK:            "set security zones security-zone {{zone}} address-book address-set {{name}} {{addressCli}}",
		SRX_GLOBAL_GROUP_NETWORK:     "set security zones security-zone {{zone}} address-book address-set {{name}} {{addressCli}}",
		SRX_OBJECT_SERVICE:           "object service {{ objectName}}\n  {{ objectType }} {{ service }}",
		SRX_OBJECT_NETWORK_STATIC:    "object network {{ objectName}}\n  nat ({{from}},{{to}}) {{ natType }} {{ natObject }} {{ serviceCli }}",
		SRX_OBJECT_NETWORK_STATIC_IP: "object network {{ objectName}}\n  nat ({{from}},{{to}}) {{ natType }} {{ natObject }}",
		SRX_OBJECT_NETWORK_DYNAMIC:   "object network {{ objectName}}\n  nat ({{from}},{{to}}) {{ natType }} {{ natObject }}",
		SRX_TWICE_NAT:                "nat ({{from}},{{to}}) source {{natType}} {{realSrcObj}} {{mappedSrcObj}} {{dstCli}} {{serviceCli}}",
		SRX_EXTENDED_ACL_L4PORT:      "access-list {{aclName}} extended {{action}} {{protocol}} {{srcCli}} {{dstCli}} {{l4portCli}}",
		SRX_EXTENDED_ACL_SRV:         "access-list {{aclName}} extended {{action}} {{serviceCli}} {{srcCli}} {{dstCli}}",
	}
)

func (rt *SRXTemplates) MakePoolCli(intent *policy.Intent, natType firewall.NatType) (string, string) {
	rt.WithFormatter(name.SIMPLE_POOL, name.NewFormatter("POOL_{{SHORT_ID6}}", "_", map[string]func(interface{}) string{"SHORT_ID6": name.ShortId6}))
	var ng *network.NetworkGroup
	var srv *service.Service
	var err error
	genPe := intent.GenerateIntentPolicyEntry()

	if natType == firewall.DYNAMIC_NAT {
		ng = genPe.Src()
		// ng, err = network.NewNetworkGroupFromString(intent.Snat)
	} else {
		// ng, err = network.NewNetworkGroupFromString(intent.RealIp)
		ng = genPe.Dst()
		srv = genPe.Service()
	}
	if err != nil {
		panic(err)
	}

	input := name.NewPoolNamingInput(intent, ng, srv)

	input.WithRule(name.REUSE_OR_NEW)
	input.WithAddition("")
	// var err error
	var reuse, objectName string
	objectName, reuse, err = rt.NamePool(input, natType)
	if err != nil {
		panic(err)
	}

	if objectName == "" {
		return reuse, ""
	}

	objectName, err = firewall.GetName(objectName, "_", rt.Node().HasPoolName)
	if err != nil {
		panic(err)
	}

	baseCli := fmt.Sprintf("set security nat source pool %s", objectName)

	clis := []string{}

	for _, nl := range []*network.NetworkList{ng.IPv4(), ng.IPv6()} {
		for _, ip := range nl.List() {
			switch ip.AddressType() {
			case network.HOST, network.SUBNET:
				ipnet, _ := ip.IPNet()
				clis = append(clis, fmt.Sprintf("%s address %s", baseCli, ipnet.String()))
			case network.RANGE:
				iprange := ip.(*network.IPRange)
				clis = append(clis, fmt.Sprintf("%s address %s to %s", baseCli, iprange.First(), iprange.Last()))
			}

		}

	}

	return objectName, strings.Join(clis, "\n")
}

// func (rt *SRXTemplates) MakePolicyRule(from, to api.Port, intent *policy.Intent, simple bool) (flyObjectsMap map[string][]interface{}, cmdList *command.HttpCmdList, moveRule []string) {
func (rt *SRXTemplates) MakePolicyRule(from, to api.Port, intent *policy.Intent) string {
	rt.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("{{SIMPLE}}", "_", nil))
	rt.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("{{SIMPLE}}", "_", nil))

	clis := []string{}
	var srcObjectName, dstObjectName, cli string
	var err error

	ruleName := fmt.Sprintf("%s_%s", intent.TicketNumber, intent.SubTicket)

	ruleName, err = firewall.GetName(ruleName, "_", rt.Node().HasPolicyName)
	if err != nil {
		panic(err)
	}
	//
	var srcCli string
	baseCli := fmt.Sprintf("set security policies from-zone %s to-zone %s policy %s", from.(firewall.ZoneFirewall).Zone(), to.(firewall.ZoneFirewall).Zone(), ruleName)
	if intent.Src() == nil || intent.Src().IsEmpty() {
		if intent.Dst().IsIPv4() {
			srcObjectName = "any-ipv4"
		} else if intent.Dst().IsIPv6() {
			srcObjectName = "any-ipv6"
		} else {
			srcObjectName = "any"
		}
		srcCli = fmt.Sprintf("%s match source-address %s", baseCli, srcObjectName)
	} else {
		// subObjectName, c := rt.MakeNetworkObjectCli(intent, g, rule, "", zone)
		srcObjectName, cli = rt.MakeNetworkGroupCli(intent, intent.Src(), name.REUSE_GROUP_OR_NEW, "", from)
		if cli != "" {
			clis = append(clis, cli)
		}

		srcCli = fmt.Sprintf("%s match source-address %s", baseCli, srcObjectName)
	}

	var dstCli string
	if intent.Dst() == nil || intent.Dst().IsEmpty() {
		if intent.Src().IsIPv4() {
			dstObjectName = "any-ipv4"
		} else if intent.Src().IsIPv6() {
			dstObjectName = "any-ipv6"
		} else {
			dstObjectName = "any"
		}
		dstCli = fmt.Sprintf("%s match destination-address %s", baseCli, dstObjectName)
	} else {
		dstObjectName, cli = rt.MakeNetworkGroupCli(intent, intent.Dst(), name.REUSE_GROUP_OR_NEW, "", to)
		if cli != "" {
			clis = append(clis, cli)
		}
		dstCli = fmt.Sprintf("%s match destination-address %s", baseCli, dstObjectName)
	}

	var serviceCli, serviceObjectName string
	if intent.Service() == nil || intent.Service().IsEmpty() || intent.Service().Protocol() == service.IP {
		serviceObjectName = "application any"

		serviceCli = fmt.Sprintf("%s match application %s", baseCli, serviceObjectName)
	} else {
		serviceObjectName, cli = rt.MakeServiceGroupCli(intent, intent.Service(), name.REUSE_GROUP_OR_NEW, "")
		if cli != "" {
			clis = append(clis, cli)
		}

		serviceCli = fmt.Sprintf("%s match application %s", baseCli, serviceObjectName)
	}

	clis = append(clis, srcCli)
	clis = append(clis, dstCli)
	clis = append(clis, serviceCli)
	clis = append(clis, fmt.Sprintf("%s then permit", baseCli))

	// clis = append(clis, cli)

	return strings.Join(clis, "\n")
}

// func (rt *SRXTemplates) MakeServiceGroupCli(intent *policy.Intent, ng *network.NetworkGroup, rule name.NamingRuleType, additionName string) (objectName, cli string) {
//
// }

func (rt *SRXTemplates) MakeServiceGroupCli(intent *policy.Intent, sg *service.Service, rule name.NamingRuleType, additionName string) (objectName, cli string) {
	rt.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("SRV_{{SIMPLE}}", "_", nil))
	srpFormatter := name.NewFormatter("SRV_{{UUID}}", "_", nil)
	srpFormatter.WithFunc("UUID", name.UUID)
	rt.WithFormatter(name.COMPLEX_SERVICE, srpFormatter)

	clis := []string{}

	input := name.NewServiceNamingInput(intent, sg)
	input.WithRule(rule)
	input.WithAddition(additionName)
	var err error
	var reuse string
	objectName, reuse, err = rt.NameService(input)
	if err != nil {
		panic(err)
	}
	if objectName == "" && reuse == "" {
		panic("unknown error")
	}

	baseCli := fmt.Sprintf("set applications application-set %s", objectName)
	if objectName != "" {
		for it := sg.Iterator(); it.HasNext(); {
			_, e := it.Next()

			switch e.(type) {
			case *service.L3Protocol:
				sv := &service.Service{}
				sv.Add(e)
				subObjectName, subCli := rt.MakeServiceObjectCli(intent, sv, rule, "")
				if subCli != "" {
					clis = append(clis, subCli)
				}
				clis = append(clis, fmt.Sprintf("%s application %s", baseCli, subObjectName))
			case *service.ICMPProto, *service.L4Service:
				e.WithStrFunc(func() string {
					strList := []string{}
					sv := &service.Service{}
					sv.Add(e)
					subObjectName, subCli := rt.MakeServiceObjectCli(intent, sv, rule, "")
					if subCli != "" {
						strList = append(strList, subCli)
					}
					strList = append(strList, fmt.Sprintf("%s application %s", baseCli, subObjectName))

					return strings.Join(strList, "\n")
				})

				clis = append(clis, e.String())
			}
		}

		// cli = fmt.Sprintf("object-group service %s\n%s", objectName, strings.Join(clis, "\n"))

		cli = strings.Join(clis, "\n")
		return

	} else {
		objectName = reuse
		return
	}
}

func (rt *SRXTemplates) MakeNetworkGroupCli(intent *policy.Intent, ng *network.NetworkGroup, rule name.NamingRuleType, additionName string, port api.Port) (objectName, cli string) {
	rt.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("GRP_{{SIMPLE}}", "_", map[string]func(interface{}) string{"SIMPLE": Simple}))
	rt.WithFormatter(name.COMPLEX_NETWORK, name.NewFormatter("GRP_{{UUID}}", "_", nil))

	clis := []string{}

	input := name.NewNetworkNamingInput(intent, ng)
	input.WithRule(rule)
	input.WithAddition(additionName)
	var err error
	var reuse string
	objectName, reuse, err = rt.NameNetwork(input, nil)
	if err != nil {
		panic(err)
	}
	if objectName == "" && reuse == "" {
		panic("unknown error")
	}

	subObjectNameList := []string{}

	if objectName != "" {
		for _, nl := range []*network.NetworkList{ng.IPv4(), ng.IPv6()} {
			for _, ip := range nl.List() {
				switch ip.AddressType() {
				case network.HOST:
					ipnet, _ := ip.IPNet()
					g := network.NewNetworkGroup()
					g.Add(ipnet)
					subObjectName, c := rt.MakeNetworkObjectCli(intent, g, name.REUSE_OBJECT_OR_NEW, "", port)
					if c != "" {
						clis = append(clis, c)
					}
					subObjectNameList = append(subObjectNameList, subObjectName)

				case network.SUBNET:
					ipnet, _ := ip.IPNet()
					g := network.NewNetworkGroup()
					g.Add(ipnet)
					subObjectName, c := rt.MakeNetworkObjectCli(intent, g, name.REUSE_OBJECT_OR_NEW, "", port)
					if c != "" {
						clis = append(clis, c)
					}
					subObjectNameList = append(subObjectNameList, subObjectName)

				case network.RANGE:
					iprange := ip.(*network.IPRange)
					g := network.NewNetworkGroup()
					g.Add(iprange)
					subObjectName, c := rt.MakeNetworkObjectCli(intent, g, name.REUSE_OBJECT_OR_NEW, "", port)

					if c != "" {
						clis = append(clis, c)
					}
					subObjectNameList = append(subObjectNameList, subObjectName)
					//

				default:
					panic("unknown error")
				}

			}

		}
		//
		// if len(clis) == 0 {
		// panic("unknow error")
		// }

		tpl, _ := pongo2.FromString(templateMap[SRX_GROUP_NETWORK])

		for _, name := range subObjectNameList {
			c, err := tpl.Execute(pongo2.Context{
				"zone":       port.(firewall.ZoneFirewall).Zone(),
				"name":       objectName,
				"addressCli": "address " + name,
			})
			if err != nil {
				panic(err)
			}

			clis = append(clis, c)
		}

		cli = strings.Join(clis, "\n")

		return
	} else {
		objectName = reuse
		return
	}
}

func (rt *SRXTemplates) MakeStaticNatCli(from, out api.Port, ruleSet string, intent *policy.Intent) string {
	rt.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("{{SIMPLE}}", "_", nil))
	rt.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("{{SIMPLE}}", "_", nil))
	rt.WithFormatter(name.COMPLEX_NETWORK, name.NewFormatter("{{UUID}}", "_", nil))
	rt.WithFormatter(name.COMPLEX_SERVICE, name.NewFormatter("{{UUID}}", "_", nil))

	clis := []string{}
	var err error

	ruleName := fmt.Sprintf("%s_%s", intent.TicketNumber, intent.SubTicket)
	ruleName, err = firewall.GetName(ruleName, "_", rt.Node().HasNatName)
	if err != nil {
		panic(err)
	}

	baseCli := fmt.Sprintf("set security nat static rule-set %s rule %s", ruleSet, ruleName)

	if !(intent.Src() == nil || intent.Src().IsEmpty()) {
		for _, nl := range []*network.NetworkList{intent.Src().IPv4(), intent.Src().IPv6()} {
			// for _, ip := range nl.List() {
			// switch ip.AbbrNet.(type) {
			// case *network.IPNet:
			// ipnet := ip.AbbrNet.(*network.IPNet)
			// clis = append(clis, fmt.Sprintf("%s match source-address %s", baseCli, ipnet.String()))
			// case *network.IPRange:
			// iprange := ip.AbbrNet.(*network.IPRange)
			// cidrs := iprange.CIDRs()
			// for _, net := range cidrs {
			// clis = append(clis, fmt.Sprintf("%s match source-address %s", baseCli, net.String()))
			// }
			// }
			// }
			//

			for _, ip := range nl.List() {
				switch ip.AddressType() {
				case network.HOST, network.SUBNET:
					ipnet, _ := ip.IPNet()
					clis = append(clis, fmt.Sprintf("%s match source-address %s", baseCli, ipnet.String()))
				case network.RANGE:
					iprange := ip.(*network.IPRange)
					cidrs := iprange.CIDRs()
					for _, net := range cidrs {
						clis = append(clis, fmt.Sprintf("%s match source-address %s", baseCli, net.String()))
					}

				}
			}

		}

	}
	if !(intent.Dst() == nil || intent.Dst().IsEmpty()) {
		for _, nl := range []*network.NetworkList{intent.Dst().IPv4(), intent.Dst().IPv6()} {
			// for _, ip := range nl.List() {
			// switch ip.AbbrNet.(type) {
			// case *network.IPNet:
			// ipnet := ip.AbbrNet.(*network.IPNet)
			// clis = append(clis, fmt.Sprintf("%s match destination-address %s", baseCli, ipnet.String()))
			// case *network.IPRange:
			// iprange := ip.AbbrNet.(*network.IPRange)
			// cidrs := iprange.CIDRs()
			// for _, net := range cidrs {
			// clis = append(clis, fmt.Sprintf("%s match destination-address %s", baseCli, net.String()))
			// }
			// }
			// }

			for _, ip := range nl.List() {
				switch ip.AddressType() {
				case network.HOST, network.SUBNET:
					ipnet, _ := ip.IPNet()
					clis = append(clis, fmt.Sprintf("%s match destination-address %s", baseCli, ipnet.String()))
				case network.RANGE:
					iprange := ip.(*network.IPRange)
					cidrs := iprange.CIDRs()
					for _, net := range cidrs {
						clis = append(clis, fmt.Sprintf("%s match destination-address %s", baseCli, net.String()))
					}
				}
			}

		}

	}

	if !intent.Service().IsEmpty() {
		srv := intent.Service().MustOneServiceEntry()
		if srv.Protocol() == service.IP {
		} else if srv.Protocol() == service.TCP || srv.Protocol() == service.UDP {
			sport := srv.(*service.L4Service).SrcPort()
			if !sport.IsFull() {
				for it := sport.Iterator(); it.HasNext(); {
					_, e := it.Next()
					if e.Low().Cmp(e.High()) == 0 {
						clis = append(clis, fmt.Sprintf("%s match source-port %d", baseCli, e.Low()))
					} else {
						clis = append(clis, fmt.Sprintf("%s match source-port %d", baseCli, e.Low()))
						clis = append(clis, fmt.Sprintf("%s match source-port to %d", baseCli, e.High()))
					}
				}
			}
			dport := srv.(*service.L4Service).DstPort()
			if !dport.IsFull() {
				for it := dport.Iterator(); it.HasNext(); {
					_, e := it.Next()
					if e.Low().Cmp(e.High()) == 0 {
						clis = append(clis, fmt.Sprintf("%s match destination-port %d", baseCli, e.Low()))
					} else {
						clis = append(clis, fmt.Sprintf("%s match destination-port %d", baseCli, e.Low()))
						clis = append(clis, fmt.Sprintf("%s match destination-port to %d", baseCli, e.High()))
					}
				}
			}
		} else {
		}
	}

	genPe := intent.GenerateIntentPolicyEntry()
	if !(genPe.Dst() == nil || genPe.Dst().IsEmpty()) {
		net := genPe.Dst().GenerateNetwork()
		switch net.AddressType() {
		case network.HOST, network.SUBNET:
			clis = append(clis, fmt.Sprintf("%s then static-nat prefix %s", baseCli, net.String()))
		case network.RANGE:
			mappedObj, c := rt.MakeNetworkObjectCli(intent, genPe.Dst(), name.REUSE_OR_NEW, "", out)
			if c != "" {
				clis = append(clis, c)
			}

			clis = append(clis, fmt.Sprintf("%s then static-nat prefix-name %s", baseCli, mappedObj))
		}

	}

	if !genPe.Service().IsEmpty() {
		srv := genPe.Service().MustOneServiceEntry()
		if srv.Protocol() == service.IP {
		} else if srv.Protocol() == service.TCP || srv.Protocol() == service.UDP {
			dport := srv.(*service.L4Service).DstPort()
			if !dport.IsFull() {
				for it := dport.Iterator(); it.HasNext(); {
					_, e := it.Next()
					if e.Low().Cmp(e.High()) == 0 {
						clis = append(clis, fmt.Sprintf("%s then static-nat prefix mapped-port %d", baseCli, e.Low()))
					} else {
						clis = append(clis, fmt.Sprintf("%s then static-nat prefix mapped-port %d", baseCli, e.Low()))
						clis = append(clis, fmt.Sprintf("%s then static-nat prefix mapped-port to %d", baseCli, e.High()))
					}
				}
			}
		} else {
		}
	}

	return strings.Join(clis, "\n")

}

func (rt *SRXTemplates) MakeDestinationNatCli(from, out, ruleSet string, intent *policy.Intent) string {
	rt.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("{{SIMPLE}}", "_", nil))
	rt.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("{{SIMPLE}}", "_", nil))
	rt.WithFormatter(name.COMPLEX_NETWORK, name.NewFormatter("{{UUID}}", "_", nil))
	rt.WithFormatter(name.COMPLEX_SERVICE, name.NewFormatter("{{UUID}}", "_", nil))

	clis := []string{}
	var err error

	ruleName := fmt.Sprintf("%s_%s", intent.TicketNumber, intent.SubTicket)
	ruleName, err = firewall.GetName(ruleName, "_", rt.Node().HasNatName)
	if err != nil {
		panic(err)
	}

	baseCli := fmt.Sprintf("set security nat destination rule-set %s rule %s", ruleSet, ruleName)

	if !(intent.Src() == nil || intent.Src().IsEmpty()) {
		for _, nl := range []*network.NetworkList{intent.Src().IPv4(), intent.Src().IPv6()} {
			for _, ip := range nl.List() {
				switch ip.(type) {
				case *network.IPNet:
					ipnet := ip.(*network.IPNet)
					clis = append(clis, fmt.Sprintf("%s match source-address %s", baseCli, ipnet.String()))
				case *network.IPRange:
					iprange := ip.(*network.IPRange)
					cidrs := iprange.CIDRs()
					for _, net := range cidrs {
						clis = append(clis, fmt.Sprintf("%s match source-address %s", baseCli, net.String()))
					}
				}
			}

		}

	}

	if !(intent.Dst() == nil || intent.Dst().IsEmpty()) {
		for _, nl := range []*network.NetworkList{intent.Dst().IPv4(), intent.Dst().IPv6()} {
			for _, ip := range nl.List() {
				switch ip.(type) {
				case *network.IPNet:
					ipnet := ip.(*network.IPNet)
					clis = append(clis, fmt.Sprintf("%s match destination-address %s", baseCli, ipnet.String()))
				case *network.IPRange:
					iprange := ip.(*network.IPRange)
					cidrs := iprange.CIDRs()
					for _, net := range cidrs {
						clis = append(clis, fmt.Sprintf("%s match destination-address %s", baseCli, net.String()))
					}
				}
			}

		}

	}

	if !intent.Service().IsEmpty() {
		srv := intent.Service().MustOneServiceEntry()
		if srv.Protocol() == service.IP {
		} else if srv.Protocol() == service.TCP || srv.Protocol() == service.UDP {
			dport := srv.(*service.L4Service).SrcPort()
			if !dport.IsFull() {
				for it := dport.Iterator(); it.HasNext(); {
					_, e := it.Next()
					if e.Low().Cmp(e.High()) == 0 {
						clis = append(clis, fmt.Sprintf("%s match destination-port %d", baseCli, e.Low()))
					} else {
						clis = append(clis, fmt.Sprintf("%s match destination-port %d to %d", baseCli, e.Low(), e.High()))
					}
				}
			}
		} else {
		}
	}

	genPe := intent.GenerateIntentPolicyEntry()
	if !(genPe.Dst() == nil || genPe.Dst().IsEmpty()) {
		// net := genPe.Dst().GenerateNetwork()
		poolName, poolCli := rt.MakePoolCli(intent, firewall.DESTINATION_NAT)
		if poolCli != "" {
			clis = append(clis, poolCli)
		}
		clis = append(clis, fmt.Sprintf("%s then destination-nat pool %s", baseCli, poolName))

	}

	return strings.Join(clis, "\n")

}

func (rt *SRXTemplates) MakeSourceNatCli(fromZone, outZone string, ruleSet string, intent *policy.Intent) string {
	rt.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("{{SIMPLE}}", "_", nil))
	rt.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("{{SIMPLE}}", "_", nil))
	rt.WithFormatter(name.COMPLEX_NETWORK, name.NewFormatter("{{UUID}}", "_", nil))
	rt.WithFormatter(name.COMPLEX_SERVICE, name.NewFormatter("{{UUID}}", "_", nil))

	clis := []string{}
	var err error

	ruleName := fmt.Sprintf("%s_%s", intent.TicketNumber, intent.SubTicket)
	ruleName, err = firewall.GetName(ruleName, "_", rt.Node().HasNatName)
	if err != nil {
		panic(err)
	}

	baseCli := fmt.Sprintf("set security nat source rule-set %s rule %s", ruleSet, ruleName)

	if !(intent.Src() == nil || intent.Src().IsEmpty()) {
		for _, nl := range []*network.NetworkList{intent.Src().IPv4(), intent.Src().IPv6()} {
			for _, ip := range nl.List() {
				switch ip.AddressType() {
				case network.HOST, network.SUBNET:
					ipnet, _ := ip.IPNet()
					clis = append(clis, fmt.Sprintf("%s match source-address %s", baseCli, ipnet.String()))
				case network.RANGE:
					iprange := ip.(*network.IPRange)
					cidrs := iprange.CIDRs()
					for _, net := range cidrs {
						clis = append(clis, fmt.Sprintf("%s match source-address %s", baseCli, net.String()))
					}

				}
			}

		}
	}

	if !(intent.Dst() == nil || intent.Dst().IsEmpty()) {
		for _, nl := range []*network.NetworkList{intent.Dst().IPv4(), intent.Dst().IPv6()} {
			for _, ip := range nl.List() {
				switch ip.AddressType() {
				case network.HOST, network.SUBNET:
					ipnet, _ := ip.IPNet()
					clis = append(clis, fmt.Sprintf("%s match destination-address %s", baseCli, ipnet.String()))
				case network.RANGE:
					iprange := ip.(*network.IPRange)
					cidrs := iprange.CIDRs()
					for _, net := range cidrs {
						clis = append(clis, fmt.Sprintf("%s match destination-address %s", baseCli, net.String()))
					}
				}
			}

		}
	}

	if !intent.Service().IsEmpty() {
		srv := intent.Service().MustOneServiceEntry()
		if srv.Protocol() == service.IP {
		} else if srv.Protocol() == service.TCP || srv.Protocol() == service.UDP {
			dport := srv.(*service.L4Service).DstPort()
			if !dport.IsFull() {
				for it := dport.Iterator(); it.HasNext(); {
					_, e := it.Next()
					if e.Low().Cmp(e.High()) == 0 {
						clis = append(clis, fmt.Sprintf("%s match destination-port %d", baseCli, e.Low()))
					} else {
						clis = append(clis, fmt.Sprintf("%s match destination-port %d to %d", baseCli, e.Low(), e.High()))
					}
				}
			}
		} else {
		}
	}

	var ps []string
	genPe := intent.GenerateIntentPolicyEntry()
	if !(genPe.Src() == nil || genPe.Src().IsEmpty()) {

		portNetworkGroup := rt.Node().(api.Node).GetPortByNameOrAlias(outZone).NetworkGroup()
		if portNetworkGroup.MatchNetworkGroup(genPe.Src()) {
			clis = append(clis, fmt.Sprintf("%s then source-nat interface", baseCli))
		} else {
			poolName, poolCli := rt.MakePoolCli(intent, firewall.DYNAMIC_NAT)
			if poolCli != "" {
				// clis = append(clis, poolCli)
				ps = append(ps, poolCli)
			}
			clis = append(clis, fmt.Sprintf("%s then source-nat pool %s", baseCli, poolName))

		}

	}
	if len(ps) > 0 {
		for index := len(ps) - 1; index >= 0; index-- {
			clis = append(clis[0:1], clis[0:]...)
			clis[0] = ps[index]
		}
	}
	return strings.Join(clis, "\n")
}

func (rt *SRXTemplates) MakeNetworkObjectCli(intent *policy.Intent, ng *network.NetworkGroup, rule name.NamingRuleType, additionName string, port api.Port) (objectName, cli string) {
	// func NewFormatter(format, sep string, callMap map[string]func(interface{}) string) *Formatter {
	rt.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("{{SIMPLE}}", "_", map[string]func(interface{}) string{"SIMPLE": Simple}))

	input := name.NewNetworkNamingInput(intent, ng)
	input.WithRule(rule)
	input.WithAddition(additionName)
	var err error
	var reuse string
	objectName, reuse, err = rt.NameNetwork(input, port)
	if err != nil {
		panic(err)
	}
	if objectName == "" && reuse == "" {
		panic("unknown error")
	}

	var addressCli string
	if objectName != "" {
		tpl, err := pongo2.FromString(templateMap[SRX_OBJECT_NETWORK])
		if err != nil {
			panic(err)
		}

		net := ng.GenerateNetwork()

		switch net.AddressType() {
		case network.HOST, network.SUBNET:
			addressCli = net.String()
		case network.RANGE:
			addressCli = fmt.Sprintf("range-address %s to %s", net.(*network.IPRange).First(), net.(*network.IPRange).Last())
		}

		cli, err = tpl.Execute(pongo2.Context{"objectName": objectName, "addressCli": addressCli, "zone": port.(firewall.ZoneFirewall).Zone()})
		if err != nil {
			panic(err)
		}

		return

	} else {
		objectName = reuse
		return
	}
}

func (rt *SRXTemplates) MakeServiceObjectCli(intent *policy.Intent, sg *service.Service, rule name.NamingRuleType, additionName string) (objectName, cli string) {
	// rt.WithFormatter(name.SIMPLE_NETWORK, name.NewFormatter("OBJ_{{SIMPLE}}", "_", nil))
	rt.WithFormatter(name.SIMPLE_SERVICE, name.NewFormatter("{{SIMPLE}}", "_", nil))

	input := name.NewServiceNamingInput(intent, sg)
	input.WithRule(rule)
	input.WithAddition(additionName)

	objectName, reuse, err := rt.NameService(input)
	if err != nil {
		panic(err)
	}

	if objectName == "" && reuse == "" {
		panic("unknown error")
	}

	baseCli := fmt.Sprintf("set applications application %s", objectName)
	// clis := []string{}
	if objectName != "" {
		s := sg.MustOneServiceEntry()
		var out string
		if s.Protocol() == service.ICMP || s.Protocol() == service.ICMP6 {
			s.WithStrFunc(func() string {
				var strList []string
				// strList := []string{strings.ToLower(s.Protocol().String())}
				p := strings.ToLower(s.Protocol().String())

				switch s.(type) {
				case *service.L3Protocol:
					strList = append(strList, fmt.Sprintf("%s protocol %s", baseCli, p))
					// strList = []string{"icmp"}
				case *service.ICMPProto:
					if s.(*service.ICMPProto).IcmpType != service.ICMP_DEFAULT_TYPE {
						strList = append(strList, fmt.Sprintf("%s icmp-type %d", baseCli, s.(*service.ICMPProto).IcmpType))
						// strList = append(strList, fmt.Sprintf("%d", s.(*service.ICMPProto).IcmpType))
						if s.(*service.ICMPProto).IcmpCode != service.ICMP_DEFAULT_CODE {
							strList = append(strList, fmt.Sprintf("%s icmp-code %d", baseCli, s.(*service.ICMPProto).IcmpCode))
						}
					}
				}
				return strings.Join(strList, "\n")
			})

			out = s.String()
		} else if s.Protocol() == service.TCP || s.Protocol() == service.UDP {
			s.WithStrFunc(func() string {

				strList := []string{fmt.Sprintf("%s protocol %s", baseCli, strings.ToLower(s.Protocol().String()))}
				// p := strings.ToLower(s.Protocol().String())
				// strList = append(strList, fmt.Sprintf("%s protocol %s", baseCli, p))
				// strList := []string{p}

				l4SrcPort := s.(*service.L4Service).SrcPort()
				l4DstPort := s.(*service.L4Service).DstPort()
				if l4SrcPort == nil {
					// strList = append(strList, "source 0 65535")
				} else {
					if len(l4SrcPort.L) != 1 {
						panic(fmt.Sprintf("current not support multiple src port range, %+v", l4SrcPort.L))
					}
					if l4SrcPort.L[0].Low().Cmp(l4SrcPort.L[0].High()) == 0 {
						strList = append(strList, fmt.Sprintf("%s source-port %d", baseCli, l4SrcPort.L[0].Low()))
					} else {
						strList = append(strList, fmt.Sprintf("%s source-port %d-%d", baseCli, l4SrcPort.L[0].Low(), l4SrcPort.L[0].High()))
					}
				}

				if l4DstPort == nil {
					// strList = append(strList, "source 0 65535")
				} else {
					if len(l4DstPort.L) != 1 {
						panic(fmt.Sprintf("current not support multiple dst port range, %+v", l4DstPort.L))
					}
					if l4DstPort.L[0].Low().Cmp(l4DstPort.L[0].High()) == 0 {
						strList = append(strList, fmt.Sprintf("%s destination-port %d", baseCli, l4DstPort.L[0].Low()))
					} else {
						strList = append(strList, fmt.Sprintf("%s destination-port %d-%d", baseCli, l4DstPort.L[0].Low(), l4DstPort.L[0].High()))
					}
				}

				return strings.Join(strList, "\n")

			})
			out = s.String()
		} else {
			var strList []string
			if s.Protocol() == service.IP {
				strList = append(strList, "%s protocol ip", baseCli)
				// strList = []string{"ip"}
			} else {
				strList = append(strList, fmt.Sprintf("%s protocol %s", baseCli, s.Protocol().String()))
			}
			// return strings.Join(strList, "\n")
			out = strings.Join(strList, "\n")

		}

		cli = out

		return
	} else {
		objectName = reuse
		return
	}
}

// SRX_OBJECT_NETWORK_STATIC: "object network {{ objectName}}\n  {{ natType }} {{ natObject }} {{ service }}",

// ciscosrx(config)# object network obj-192.168.100.210
// ciscosrx(config-network-object)# nat (inside,outside) static ?
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
// ciscosrx(config-network-object)# nat (inside,outside) static 1.1.1.1 se
// ciscosrx(config-network-object)# nat (inside,outside) static 1.1.1.1 service ?
//
// network-object mode commands/options:
// sctp  SCTP to be used as transport protocol
// tcp   TCP to be used as transport protocol
// udp   UDP to be used as transport protocol
//
// func (rt *SRXTemplates) MakeObjectStaticNatCli(n string, from, out api.Port, intent *policy.Intent, ref firewall.ObjectReferenceMethod) string {

type SRXDnatTargetServiceValidator struct{}

func (dp SRXDnatTargetServiceValidator) Validate(data map[string]interface{}) validator.Result {
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

type SRXDnatTargetIsExistValidator struct{}

func (dv SRXDnatTargetIsExistValidator) Validate(data map[string]interface{}) validator.Result {
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

type SRXDnatMppaedAddressValidator struct{}

func (dv SRXDnatMppaedAddressValidator) Validate(data map[string]interface{}) validator.Result {
	intent := data["intent"].(*policy.Intent)
	dst := intent.Dst()

	if !(dst.AddressType() == network.HOST || dst.AddressType() == network.SUBNET) {
		return validator.NewValidateResult(false, fmt.Sprint("dnat only support host and subnet, dst: ", dst))
	}

	return validator.NewValidateResult(true, "")
}

package f5

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/l2service/adapter/lb"
	F5 "github.com/influxdata/telegraf/controller/pkg/nodemap/adapter/lb/f5"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/utils/flexrange"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/tools"
)

type F5Node struct {
	node.DeviceNode
	NveInterfaces []lb.Interface
	//objectSet *ASAObjectSet
	//policySet *PolicySet
	//nats      *Nats
	//matrix    *Matrix
}

func (f5 *F5Node) Host() string {
	return f5.CmdIp()
}

func (f5 *F5Node) TypeName() string {
	return "F5"
}

func (f5 *F5Node) LBType() terminalmode.DeviceType {
	return terminalmode.F5
}

func (f5 *F5Node) NodeType() api.NodeType {
	return api.LB
}

func (f5 *F5Node) WithNveInterfaces(intf lb.Interface) {
	if len(f5.NveInterfaces) == 0 {
		f5.NveInterfaces = []lb.Interface{}
	}
	f5.NveInterfaces = append(f5.NveInterfaces, intf)
}

func (f5Node *F5Node) ExtraInit(adapter api.Adapter, deviceConfig *config.DeviceConfig) {
	f5Node.WithNodeType(api.LB)
	f5Adapter := adapter.(*F5.F5Adapter)
	f5Node.makeNveInterfaces(*deviceConfig)

	if len(f5Adapter.Partitions) == 0 || len(f5Adapter.RouteDomains) == 0 {
		f5Adapter.Self(true)
	}

	nodes, e := f5Adapter.GetNodes(true)
	if e != nil {
		fmt.Println(fmt.Sprintf("virtuals异常： %#v", e))
	}
	f5Adapter.Nodes = nodes
	fmt.Println("====ExtraInit： nodes初始化完成====")

	pools, e := f5Adapter.GetPools(true)
	if e != nil {
		fmt.Println(fmt.Sprintf("virtuals异常： %#v", e))
	}
	f5Adapter.Pools = pools
	fmt.Println("====ExtraInit： pools初始化完成====")

	snatPools, e := f5Adapter.GetSnatPools(true)
	if e != nil {
		fmt.Println(fmt.Sprintf("virtuals异常： %#v", e))
	}
	f5Adapter.SnatPools = snatPools
	fmt.Println("====ExtraInit： snatPools初始化完成====")

	snats, e := f5Adapter.GetSnats(true)
	if e != nil {
		fmt.Println(fmt.Sprintf("virtuals异常： %#v", e))
	}
	f5Adapter.Snats = snats
	fmt.Println("====ExtraInit： snats初始化完成====")

	virtuals, e := f5Adapter.GetVirtuals(f5Adapter.RouteDomains, true)
	if e != nil {
		fmt.Println(fmt.Sprintf("virtuals异常： %#v", e))
	}
	f5Adapter.Virtuals = virtuals
	fmt.Println("====ExtraInit： virtuals初始化完成====")

}

func (f5Node *F5Node) makeNveInterfaces(conf config.DeviceConfig) {
	vsRanges := conf.VsRange
	vrfMap := map[string][]config.VsInfo{}
	for _, vsInfo := range vsRanges {
		vrfMap[vsInfo.Vrf] = append(vrfMap[vsInfo.Vrf], *vsInfo)
	}

	index := 0
	for vrf, value := range vrfMap {
		ipList := map[network.IPFamily][]string{}
		for _, rg := range value {
			//net, _ := network.NewNetworkFromString(rg.Network)
			net, _ := network.NewNetworkGroupFromString(rg.Network)

			var rg *network.IPRange
			if net.HasIPv4() {
				drInfo := net.IPv4().DataRange()
				l := drInfo.List()
				ip1 := network.NewIPFromInt(tools.CopyInt(l[0].(flexrange.EntryInt).Low()), network.IPv4)
				ip2 := network.NewIPFromInt(tools.CopyInt(l[0].(flexrange.EntryInt).High()), network.IPv4)
				rg = network.NewIPRangeFromInt(ip1.Int(), ip2.Int(), network.IPv4)
				for _, cidr := range rg.CIDRs() {
					ipList[network.IPv4] = append(ipList[network.IPv4], cidr.String())
				}
			}

			if net.HasIPv6() {
				drInfo := net.IPv6().DataRange()
				l := drInfo.List()
				ip1 := network.NewIPFromInt(tools.CopyInt(l[0].(flexrange.EntryInt).Low()), network.IPv6)
				ip2 := network.NewIPFromInt(tools.CopyInt(l[0].(flexrange.EntryInt).High()), network.IPv6)
				rg = network.NewIPRangeFromInt(ip1.Int(), ip2.Int(), network.IPv6)
				for _, cidr := range rg.CIDRs() {
					ipList[network.IPv6] = append(ipList[network.IPv6], cidr.String())
				}
			}
		}

		ipv4s := []interface{}{}
		ipv4s = append(ipv4s, ipList[network.IPv4])
		ipv6s := []interface{}{}
		ipv6s = append(ipv6s, ipList[network.IPv6])
		intf := lb.Interface{
			Name: fmt.Sprintf("nve-%d", index),
			Vrf:  vrf,
			Ipv4: ipv4s,
			Ipv6: ipv6s,
		}

		for _, ipv4 := range ipv4s {
			rTables := f5Node.Ipv4RouteTable(vrf)
			ips := ipv4.([]string)
			for _, ip := range ips {
				ip, _ := network.ParseIPNet(ip)
				nextHop := &network.NextHop{}
				nextHop.AddHop(intf.Name, "", true, false, nil)
				rTables.PushRoute(ip, nextHop)
			}
		}

		for _, ipv6 := range ipv6s {
			rTables := f5Node.Ipv6RouteTable(vrf)
			ips := ipv6.([]string)
			for _, ip := range ips {
				ip, _ := network.ParseIPNet(ip)
				nextHop := &network.NextHop{}
				nextHop.AddHop(intf.Name, ip.String(), true, false, nil)
				rTables.PushRoute(ip, nextHop)
			}
		}

		f5Node.WithNveInterfaces(intf)
		index++
	}
}

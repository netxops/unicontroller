package dptech

import (
	"reflect"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/registry"
)

var _ firewall.FirewallPort = &DptechPort{}

type DptechPort struct {
	node.NodePort
}

func (dp *DptechPort) TypeName() string {
	return "DptechPort"
}

func (dp *DptechPort) WithZone(name string) *DptechPort {
	dp.NodePort.ZoneName = name
	return dp
}

func (dp *DptechPort) Zone() string {
	return dp.NodePort.ZoneName
}

func (dp *DptechPort) WithMainIpv4(ip string) *DptechPort {
	dp.NodePort.PrimaryIpv4 = ip
	return dp
}

func (dp *DptechPort) WithMainIpv6(ip string) *DptechPort {
	dp.NodePort.PrimaryIpv6 = ip
	return dp
}

func (dp *DptechPort) MainIpv4() string {
	// 如果 PrimaryIpv4 已设置，直接返回
	if dp.NodePort.PrimaryIpv4 != "" {
		return dp.NodePort.PrimaryIpv4
	}
	// 否则从 Ipv4List 中获取第一个 IP 地址
	ipv4List := dp.Ipv4List()
	if len(ipv4List) > 0 {
		// 从 "192.168.1.1/24" 格式中提取 IP 地址部分
		ip := ipv4List[0]
		if idx := strings.Index(ip, "/"); idx > 0 {
			return ip[:idx]
		}
		return ip
	}
	return ""
}

func (dp *DptechPort) MainIpv6() string {
	// 如果 PrimaryIpv6 已设置，直接返回
	if dp.NodePort.PrimaryIpv6 != "" {
		return dp.NodePort.PrimaryIpv6
	}
	// 否则从 Ipv6List 中获取第一个 IP 地址
	ipv6List := dp.Ipv6List()
	if len(ipv6List) > 0 {
		// 从 "2001:db8::1/64" 格式中提取 IP 地址部分
		ip := ipv6List[0]
		if idx := strings.Index(ip, "/"); idx > 0 {
			return ip[:idx]
		}
		return ip
	}
	return ""
}

func NewDptechPort(name, tenant string, ip_list map[network.IPFamily][]string, members []api.Member) *DptechPort {
	p := node.NewPort(name, tenant, ip_list, members)
	return &DptechPort{
		NodePort: *p,
	}
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*api.Port)(nil)).Elem(), "DptechPort", reflect.TypeOf(DptechPort{}))
}

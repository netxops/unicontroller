package secpath

import (
	"reflect"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/registry"
)

var _ api.Port = &SecPathPort{}
var _ firewall.FirewallPort = &SecPathPort{}

type SecPathPort struct {
	node.NodePort
}

func (secpath *SecPathPort) TypeName() string {
	return "SecPathPort"
}

func (secPath *SecPathPort) WithZone(name string) *SecPathPort {
	secPath.NodePort.ZoneName = name
	return secPath
}

func (secPath *SecPathPort) Zone() string {
	return secPath.NodePort.ZoneName
}

func (secPath *SecPathPort) WithMainIpv4(ip string) *SecPathPort {
	secPath.NodePort.PrimaryIpv4 = ip
	return secPath
}

func (secPath *SecPathPort) WithMainIpv6(ip string) *SecPathPort {
	secPath.NodePort.PrimaryIpv6 = ip
	return secPath
}

func (secPath *SecPathPort) MainIpv4() string {
	// 如果 PrimaryIpv4 已设置，直接返回
	if secPath.NodePort.PrimaryIpv4 != "" {
		return secPath.NodePort.PrimaryIpv4
	}
	// 否则从 Ipv4List 中获取第一个 IP 地址
	ipv4List := secPath.Ipv4List()
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

func (secPath *SecPathPort) MainIpv6() string {
	// 如果 PrimaryIpv6 已设置，直接返回
	if secPath.NodePort.PrimaryIpv6 != "" {
		return secPath.NodePort.PrimaryIpv6
	}
	// 否则从 Ipv6List 中获取第一个 IP 地址
	ipv6List := secPath.Ipv6List()
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

func NewSecPathPort(name, tenant string, ip_list map[network.IPFamily][]string, members []api.Member) *SecPathPort {
	p := node.NewPort(name, tenant, ip_list, members)
	return &SecPathPort{
		NodePort: *p,
	}
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*api.Port)(nil)).Elem(), "SecPathPort", reflect.TypeOf(SecPathPort{}))
}

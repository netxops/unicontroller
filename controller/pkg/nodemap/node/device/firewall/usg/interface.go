package usg

import (
	"reflect"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/registry"
)

type UsgPort struct {
	node.NodePort
}

func (up *UsgPort) TypeName() string {
	return "USgPort"
}

func (up *UsgPort) WithZone(name string) *UsgPort {
	up.NodePort.ZoneName = name
	return up
}

func (up *UsgPort) Zone() string {
	return up.NodePort.ZoneName
}

func (up *UsgPort) MainIpv4() string {
	// 如果 PrimaryIpv4 已设置，直接返回
	if up.NodePort.PrimaryIpv4 != "" {
		return up.NodePort.PrimaryIpv4
	}
	// 否则从 Ipv4List 中获取第一个 IP 地址
	ipv4List := up.Ipv4List()
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

func (up *UsgPort) MainIpv6() string {
	// 如果 PrimaryIpv6 已设置，直接返回
	if up.NodePort.PrimaryIpv6 != "" {
		return up.NodePort.PrimaryIpv6
	}
	// 否则从 Ipv6List 中获取第一个 IP 地址
	ipv6List := up.Ipv6List()
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

func NewUsgPort(name, tenant string, ip_list map[network.IPFamily][]string, members []api.Member) *UsgPort {
	p := node.NewPort(name, tenant, ip_list, members)

	return &UsgPort{
		NodePort: *p,
	}
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*api.Port)(nil)).Elem(), "USgPort", reflect.TypeOf(UsgPort{}))
}

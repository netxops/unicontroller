package asa

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
)

var _ firewall.ZoneFirewall = &ASAPort{}

type ASAPort struct {
	node.NodePort
	// NodePort.PrimaryIpv4 string
	// NodePort.PrimaryIpv6 string
	// NodePort.InputAcl    string
	// NodePort.OutputAcl   string
	// SecurityLevel    string
}

func (ap *ASAPort) TypeName() string {
	return "ASAPort"
}

func (ap *ASAPort) Zone() string {
	return ap.NodePort.ZoneName
}

func (ap *ASAPort) WithZone(name string) *ASAPort {
	ap.NodePort.ZoneName = name
	return ap
}

func (ap *ASAPort) WithInAcl(name string) *ASAPort {
	ap.NodePort.InputAcl = name
	return ap
}

func (ap *ASAPort) WithOutAcl(name string) *ASAPort {
	ap.NodePort.OutputAcl = name
	return ap
}

func (ap *ASAPort) WithLevel(level string) *ASAPort {
	ap.NodePort.SecurityLevel = level
	return ap
}

func (ap *ASAPort) WithMainIpv4(ip string) *ASAPort {
	ap.NodePort.PrimaryIpv4 = ip
	return ap
}

func (ap *ASAPort) WithMainIpv6(ip string) *ASAPort {
	ap.NodePort.PrimaryIpv6 = ip
	return ap
}

func (ap *ASAPort) MainIpv4() string {
	return ap.NodePort.PrimaryIpv4
}

func (ap *ASAPort) MainIpv6() string {
	return ap.NodePort.PrimaryIpv6
}

func (ap *ASAPort) InAcl() string {
	return ap.NodePort.InputAcl
}

func (ap *ASAPort) OutAcl() string {
	return ap.NodePort.OutputAcl
}

func (ap *ASAPort) Level() string {
	return ap.SecurityLevel
}

func NewASAPort(name, tenant string, ip_list map[network.IPFamily][]string, members []api.Member) *ASAPort {
	p := node.NewPort(name, tenant, ip_list, members)
	return &ASAPort{
		NodePort: *p,
	}
}

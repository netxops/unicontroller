package forti

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
)

var _ firewall.ZoneFirewall = &FortigatePort{}

type FortigatePort struct {
	node.NodePort
	// NodePort.PrimaryIpv4 string
	// NodePort.PrimaryIpv6 string
	// NodePort.InputAcl    string
	// NodePort.OutputAcl   string
	// SecurityLevel    string
}

func (fgp *FortigatePort) TypeName() string {
	return "FortigatePort"
}

func (fgp *FortigatePort) Zone() string {
	return fgp.NodePort.ZoneName
}

func (fgp *FortigatePort) WithZone(name string) *FortigatePort {
	fgp.NodePort.ZoneName = name
	return fgp
}

func (fgp *FortigatePort) WithInAcl(name string) *FortigatePort {
	fgp.NodePort.InputAcl = name
	return fgp
}

func (fgp *FortigatePort) WithOutAcl(name string) *FortigatePort {
	fgp.NodePort.OutputAcl = name
	return fgp
}

func (fgp *FortigatePort) WithLevel(level string) *FortigatePort {
	fgp.NodePort.SecurityLevel = level
	return fgp
}

func (fgp *FortigatePort) WithMainIpv4(ip string) *FortigatePort {
	fgp.NodePort.PrimaryIpv4 = ip
	return fgp
}

func (fgp *FortigatePort) WithMainIpv6(ip string) *FortigatePort {
	fgp.NodePort.PrimaryIpv6 = ip
	return fgp
}

func (fgp *FortigatePort) MainIpv4() string {
	return fgp.NodePort.PrimaryIpv4
}

func (fgp *FortigatePort) MainIpv6() string {
	return fgp.NodePort.PrimaryIpv6
}

func (fgp *FortigatePort) InAcl() string {
	return fgp.NodePort.InputAcl
}

func (fgp *FortigatePort) OutAcl() string {
	return fgp.NodePort.OutputAcl
}

func (fgp *FortigatePort) Level() string {
	return fgp.SecurityLevel
}

func NewFortigatePort(name, tenant string, ip_list map[network.IPFamily][]string, members []api.Member) *FortigatePort {
	p := node.NewPort(name, tenant, ip_list, members)
	return &FortigatePort{
		NodePort: *p,
	}
}

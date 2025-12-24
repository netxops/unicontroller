package srx

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/netxops/utils/network"
)

type SRXPort struct {
	node.NodePort
}

func (srx *SRXPort) TypeName() string {
	return "SRXPort"
}

func (srx *SRXPort) WithZone(name string) *SRXPort {
	srx.NodePort.ZoneName = name
	return srx
}

func (srx *SRXPort) Zone() string {
	return srx.NodePort.ZoneName
}

func NewSRXPort(name, tenant string, ip_list map[network.IPFamily][]string, members []api.Member) *SRXPort {
	p := node.NewPort(name, tenant, ip_list, members)
	return &SRXPort{
		NodePort: *p,
	}
}

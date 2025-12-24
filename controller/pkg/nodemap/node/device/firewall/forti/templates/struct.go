package templates

import (
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/netxops/utils/network"
)

type NetworkObj struct {
	Name             string
	Type             network.AddressType
	AddressType      network.IPFamily
	Address          string
	Mask             string
	IPv6PrefixLen    int
	StartIPv4Address string
	EndIPv4Address   string
	StartIPv6Address string
	EndIPv6Address   string
	Interface        string
}

type ServiceObj struct {
	Name          string
	Protocol      string
	IpRange       string
	StartSrcPort  *int
	EndSrcPort    *int
	StartDestPort *int
	EndDestPort   *int
	//Group         *ServiceGroup
}

type Vip struct {
	Name            string
	from            api.Port
	to              api.Port
	VipType         network.IPFamily
	NetworkType     firewall.NatType
	Interface       api.Port
	ExtIpAddress    string
	MappedIpAddress string
	Protocol        string
	PortForward     string
	ExtPort         string
	MappedPort      string
}

type Pool struct {
	Name         string
	Type         string
	ExtIpAddress string
}

type Policy struct {
	PolicyId     *int64
	Name         string
	InInterface  api.Port
	OutInterface api.Port
	Src          []string
	Dest         []string
	Services     []*ServiceObj
	Action       string
	UseNat       bool
	UsePool      bool
	IpPool       *Pool
}

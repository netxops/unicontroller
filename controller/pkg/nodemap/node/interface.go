package node

import (
	"encoding/json"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"

	//"github.com/netxops/unify/constant"
	//"github.com/netxops/unify/global"
	"strings"

	"github.com/netxops/utils/network"
	"github.com/netxops/utils/tools"
)

// import "github.com/netxops/unify/nodemap/PortConnector"
// type NodePort struct {
// PortName      string
// Alias         []string
// IpList        map[network.IPFamily][]string
// Tenant        string
// FhrpMembers   []*api.Member
// PortVrf       string
// RemoteVrf     []string
// SnmpIfIndex   int
// ParentNode    api.Node
// PortConnector api.Connector
// Status        api.PortStatus
// }
//

type NodePortIpList struct {
	//global.GVA_MODEL `mapstructure:",squash"`
	Ip         string
	IpType     network.IPFamily
	NodePortID int
}

type NodePort struct {
	id             string                        `json:"id"`
	PortName       string                        `json:"port_name"`
	Alias          api.StringList                `json:"alias"`
	IpList         map[network.IPFamily][]string `json:"ip_list"`
	IpListRaw      string                        `json:"ip_list_raw"`
	Tenant         string                        `json:"tenant"`
	FhrpMembers    []api.Member                  `json:"fhrp_members"`
	FhrpMembersRaw string                        `json:"fhrp_members_raw"`
	PortVrf        string                        `json:"port_vrf"`
	RemoteVrf      api.StringList                `json:"remote_vrf"`
	SnmpIfIndex    int                           `json:"snmp_if_index"`
	NodeID         int                           `json:"node_id"`
	ParentNode     api.Node                      `json:"-"`
	Connector      string                        `json:"connector"`
	ConnectorRaw   string                        `json:"connector_raw"`
	PrimaryIpv4    string                        `json:"primary_ipv4"`
	PrimaryIpv6    string                        `json:"primary_ipv6"`
	InputAcl       string                        `json:"input_acl"`
	OutputAcl      string                        `json:"output_acl"`
	SecurityLevel  string                        `json:"security_level"`
	ZoneName       string                        `json:"zone_name"`
	Description    string                        `json:"description"`
	Status         api.PortStatus                `json:"status"`
	AreaIPv4       string                        `json:"area_ipv4"`
	AreaIPv6       string                        `json:"area_ipv6"`
	StubAreaIPv4   bool                          `json:"stub_area_ipv4"`
	StubAreaIPv6   bool                          `json:"stub_area_ipv6"`
}

func (p *NodePort) TypeName() string {
	return "NodePort"
}

func (NodePort) TableName() string {
	return "node_port"
}

func NewPort(name, tenant string, ip_list map[network.IPFamily][]string, members []api.Member) *NodePort {
	ipList := map[network.IPFamily][]string{}
	for k, v := range ip_list {
		ipList[k] = []string{}
		for _, vv := range v {
			ipList[k] = append(ipList[k], vv)
		}
	}

	return &NodePort{
		PortName:    name,
		Tenant:      tenant,
		IpList:      ipList,
		FhrpMembers: members,
		RemoteVrf:   []string{},
	}
}

// MarshalJSON implements the json.Marshaler interface
func (p NodePort) MarshalJSON() ([]byte, error) {
	type Alias NodePort
	return json.Marshal(&struct {
		Alias
		ID string `json:"id"`
		// IpList      string `json:"ip_list"`
		// FhrpMembers string `json:"fhrp_members"`
		// ParentNode string `json:"parent_node,omitempty"`
	}{
		Alias: Alias(p),
		ID:    p.id,
		// IpList:      p.IpListRaw,
		// FhrpMembers: p.FhrpMembersRaw,
		// ParentNode: fmt.Sprintf("%v", p.ParentNode),
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (p *NodePort) UnmarshalJSON(data []byte) error {
	type Alias NodePort
	aux := &struct {
		*Alias
		ID string `json:"id"`
		// IpList      string `json:"ip_list"`
		// FhrpMembers string `json:"fhrp_members"`
	}{
		Alias: (*Alias)(p),
		ID:    p.id,
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// p.IpListRaw = aux.IpList
	// p.FhrpMembersRaw = aux.FhrpMembers
	p.id = aux.ID

	// Parse IpList from IpListRaw
	// if err := json.Unmarshal([]byte(p.IpListRaw), &p.IpList); err != nil {
	// 	return err
	// }

	// // Parse FhrpMembers from FhrpMembersRaw
	// if err := json.Unmarshal([]byte(p.FhrpMembersRaw), &p.FhrpMembers); err != nil {
	// 	return err
	// }

	return nil
}

func (p *NodePort) Name() string {
	return p.PortName
}

func (p *NodePort) ID() string {
	return p.id
}

func (p *NodePort) Node() api.Node {
	return p.ParentNode
}

func (p *NodePort) Members() []api.Member {
	return p.FhrpMembers
}

func (p *NodePort) AliasName() []string {
	return p.Alias
}

func (p *NodePort) PeerVrf() []string {
	return p.RemoteVrf
}

func (p *NodePort) Vrf() string {
	return p.PortVrf
}

// func (p *NodePort) Connector() api.Connector {
// 	return p.PortConnector
// }

func (p *NodePort) ConnectorID() string {
	return p.Connector
}

func (p *NodePort) HitByName(name string) bool {
	if strings.ToLower(p.PortName) == strings.ToLower(name) {
		return true
	}

	if tools.ContainsWithoutCase(p.Alias, name) {
		return true
	}

	if strings.ToLower(name) == strings.ToLower(p.FlattenName()) {
		return true
	}

	return false
}

func (p *NodePort) WithID(id string) api.Port {
	p.id = id
	return p
}

func (p *NodePort) WithAliasName(name string) api.Port {
	if strings.ToLower(name) == strings.ToLower(p.PortName) {
		return p
	}
	if tools.ContainsWithoutCase(p.Alias, name) {
		return p
	}

	p.Alias = append(p.Alias, name)
	return p
}

func (p *NodePort) WithIfIndex(SnmpIfIndex int) api.Port {
	p.SnmpIfIndex = SnmpIfIndex
	return p
}

func (p *NodePort) WithDescription(description string) api.Port {
	p.Description = description
	return p
}

func (p *NodePort) FlattenPath() []string {
	if p.ParentNode == nil {
		return []string{p.PortName}
	}

	path := p.ParentNode.FlattenPath()
	path = append(path, p.PortName)

	return path
}

func (p *NodePort) FlattenName() string {
	return strings.Join(p.FlattenPath(), "|")
}

func (p *NodePort) GetIpList() map[network.IPFamily][]string {
	m := map[network.IPFamily][]string{}

	for k, ips := range p.IpList {
		m[k] = []string{}
		for _, ip := range ips {
			m[k] = append(m[k], ip)
		}
	}

	return m
}

func (p *NodePort) WithPeerVrf(name string) api.Port {
	if tools.Contains(p.RemoteVrf, name) == false {
		p.RemoteVrf = append(p.RemoteVrf, name)
	}

	return p
}

func (p *NodePort) WithVrf(PortVrf string) api.Port {
	p.PortVrf = PortVrf
	return p
}

func (p *NodePort) MatchVrfOrPeerVrf(name string) bool {
	if p.PortVrf == name || tools.Contains(p.RemoteVrf, name) {
		return true
	}
	return false
}

func (p *NodePort) WithNode(node api.Node) api.Port {
	p.ParentNode = node
	return p
}

func (p *NodePort) HitByIp(target, PortVrf string) bool {
	if (PortVrf == p.PortVrf || tools.Contains(p.RemoteVrf, PortVrf)) == false {
		return false
	}

	targetIp, _ := network.ParseIPNet(target)
	for _, family := range []network.IPFamily{network.IPv4, network.IPv6} {
		for _, _ip := range p.IpList[family] {
			interfaceIp, _ := network.ParseIPNet(_ip)
			if targetIp.Prefix() == interfaceIp.Prefix() && targetIp.IP.Equal(interfaceIp.IP) {
				return true
			}
		}
	}

	return false
}

func (p *NodePort) HitByIpWithoutPrefix(target, PortVrf string) bool {
	if (PortVrf == p.PortVrf || tools.Contains(p.RemoteVrf, PortVrf)) == false {
		return false
	}

	targetIp, _ := network.ParseIPNet(target)
	for _, family := range []network.IPFamily{network.IPv4, network.IPv6} {
		for _, _ip := range p.IpList[family] {
			interfaceIp, _ := network.ParseIPNet(_ip)
			if interfaceIp.MatchIPNet(targetIp) {
				return true
			}
		}
	}

	return false

}

func (p *NodePort) FullMatchByIp(ip, PortVrf string) bool {
	if (PortVrf == p.PortVrf || tools.Contains(p.RemoteVrf, PortVrf)) == false {
		return false
	}
	targetIp, _ := network.ParseIPNet(ip)
	for _, family := range []network.IPFamily{network.IPv4, network.IPv6} {
		for _, _ip := range p.IpList[family] {
			interfaceIp, _ := network.ParseIPNet(_ip)
			if interfaceIp.IP.Equal(targetIp.IP) {
				return true
			}
		}
	}

	for _, member := range p.FhrpMembers {
		if member.Hit(ip) {
			return true
		}
	}

	return false
}

func (p *NodePort) IfIndex() int {
	return p.SnmpIfIndex
}

func (p *NodePort) AddIpv4(ip string) {
	ipv4List := p.IpList[network.IPv4]
	if !tools.ContainsWithoutCase(ipv4List, ip) {
		p.IpList[network.IPv4] = append(p.IpList[network.IPv4], ip)
	}
}

func (p *NodePort) Ipv4List() []string {
	return p.IpList[network.IPv4]
}

func (p *NodePort) vNetworkGroup(af network.IPFamily) *network.NetworkGroup {
	ng := network.NewNetworkGroup()
	// key := tools.Conditional(af == network.IPv4, "ipv4", "ipv6").(string)

	for _, s := range p.IpList[af] {
		ipnet, err := network.ParseIPNet(s)
		if err != nil {
			panic(err)
		}

		ip, err := network.NewNetworkGroupFromString(ipnet.IP.String())
		if err != nil {
			panic(err)
		}

		ng.AddGroup(ip)
	}
	return ng
}

func (p *NodePort) V4NetworkGroup() *network.NetworkGroup {
	return p.vNetworkGroup(network.IPv4)
}

func (p *NodePort) V6NetworkGroup() *network.NetworkGroup {
	return p.vNetworkGroup(network.IPv6)
}

func (p *NodePort) Ipv6List() []string {
	return p.IpList[network.IPv6]
}

func (p *NodePort) AddIpv6(ip string) {
	ipv6List := p.IpList[network.IPv6]
	if !tools.ContainsWithoutCase(ipv6List, ip) {
		p.IpList[network.IPv6] = append(p.IpList[network.IPv6], ip)
	}
}

// func (p *NodePort) HitByNetwork(net *network.IPNet) bool {
// for _, family := range []string{"ipv4", "ipv6"} {
// for _, _ip := range p.IpList[family] {
// interfaceIp, _ := network.ParseIPNet(_ip)
// if interfaceIp.MatchIPNet(net) {
// return true
// }
// }
// }
//
// return false
// }
func (p *NodePort) HitByIfIndex(SnmpIfIndex int) bool {
	if p.SnmpIfIndex == SnmpIfIndex {
		return true
	}

	return false
}
func (p *NodePort) HitByNetwork(net network.AbbrNet) bool {
	for _, family := range []network.IPFamily{network.IPv4, network.IPv6} {
		for _, _ip := range p.IpList[family] {
			interfaceIp, _ := network.NewNetworkFromString(_ip)
			if interfaceIp.Match(net) {
				return true
			}
		}
	}

	return false
}

// func (p *NodePort) WithConnector(c api.Connector) {
// 	p.PortConnector = c
// }

func (p *NodePort) WithConnectorID(id string) {
	p.Connector = id
}

func (p *NodePort) WithStatus(status string) api.Port {
	s := api.NewPortStatusFromString(status)
	p.Status = s
	return p
}

func (p *NodePort) NetworkGroup() *network.NetworkGroup {
	ng := network.NewNetworkGroup()

	for _, family := range []network.IPFamily{network.IPv4, network.IPv6} {
		for _, _ip := range p.IpList[family] {
			interfaceIp, _ := network.NewNetworkFromString(_ip)
			ng.Add(interfaceIp)
		}
	}

	return ng
}

// WithArea 设置指定 IP 地址族的 area
func (p *NodePort) WithArea(areaName string, ipFamily network.IPFamily) api.Port {
	if ipFamily == network.IPv4 {
		p.AreaIPv4 = areaName
	} else {
		p.AreaIPv6 = areaName
	}
	return p
}

// Area 获取指定 IP 地址族的 area
func (p *NodePort) Area(ipFamily network.IPFamily) string {
	if ipFamily == network.IPv4 {
		return p.AreaIPv4
	}
	return p.AreaIPv6
}

// WithStubArea 设置指定 IP 地址族的 stub area 标记
func (p *NodePort) WithStubArea(isStubArea bool, ipFamily network.IPFamily) api.Port {
	if ipFamily == network.IPv4 {
		p.StubAreaIPv4 = isStubArea
	} else {
		p.StubAreaIPv6 = isStubArea
	}
	return p
}

// IsStubArea 获取指定 IP 地址族的 stub area 标记
func (p *NodePort) IsStubArea(ipFamily network.IPFamily) bool {
	if ipFamily == network.IPv4 {
		return p.StubAreaIPv4
	}
	return p.StubAreaIPv6
}

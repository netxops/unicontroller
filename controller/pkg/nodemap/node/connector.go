package node

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/registry"
	"github.com/netxops/utils/tools"
	"github.com/netxops/utils/validator"
)

type NodeConnector struct {
	Name               string                   `json:"name"`
	mode               api.Mode                 `json:"mode"`
	IPv4               api.StringList           `json:"ipv4"`
	IPv6               api.StringList           `json:"ipv6"`
	portRefs           []string                 `json:"port_refs"` // 改为存储 port references
	PortRawData        api.ByteList             `json:"port_raw_data"`
	baseValidateChain  *validator.ValidateChain `json:"-"`
	logicValidateChain *validator.ValidateChain `json:"-"`
	FhrpGroup          []api.FhrpGroup          `json:"fhrp_group"`
	portIterator       api.PortIterator         `json:"-"` // 添加 PortIterator
}

// type NodeConnector struct {
// 	Name               string                   `json:"name"`
// 	mode               api.Mode                 `json:"mode"`
// 	IPv4               api.StringList           `json:"ipv4"`
// 	IPv6               api.StringList           `json:"ipv6"`
// 	portList           []api.Port               `json:"port_list"`
// 	PortRawData        api.ByteList             `json:"port_raw_data"`
// 	baseValidateChain  *validator.ValidateChain `json:"-"`
// 	logicValidateChain *validator.ValidateChain `json:"-"`
// 	FhrpGroup          []api.FhrpGroup          `json:"fhrp_group"`
// }

// func (NodeConnector) WappterUuid() string {
// 	// 参见unify constant中的 NODE_CONNECTOR_ID string = "29cd0472-ec7c-11eb-b5b2-e38c614a68b1"
// 	return "29cd0472-ec7c-11eb-b5b2-e38c614a68b1"
// }

//
//
// func (c *NodeConnector) BeforeCreate(tx *gorm.DB) error {
// global.GVA_Register.MakeWarpper(id, s)
//
// return nil
// }

// MarshalJSON implements the json.Marshaler interface
// nodeConnectorJSON 用于序列化和反序列化
type nodeConnectorJSON struct {
	Name      string            `json:"name"`
	Mode      api.Mode          `json:"mode"`
	IPv4      api.StringList    `json:"ipv4"`
	IPv6      api.StringList    `json:"ipv6"`
	PortRefs  []string          `json:"portRefs"`
	FhrpGroup []json.RawMessage `json:"fhrpGroup"`
}

// MarshalJSON 实现 JSON 序列化
func (c *NodeConnector) MarshalJSON() ([]byte, error) {
	fhrpGroup, err := registry.InterfacesToRawMessages(c.FhrpGroup)
	if err != nil {
		return nil, err
	}

	return json.Marshal(&nodeConnectorJSON{
		Name:      c.Name,
		Mode:      c.mode,
		IPv4:      c.IPv4,
		IPv6:      c.IPv6,
		PortRefs:  c.portRefs,
		FhrpGroup: fhrpGroup,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (c *NodeConnector) UnmarshalJSON(data []byte) error {
	var ncj nodeConnectorJSON
	if err := json.Unmarshal(data, &ncj); err != nil {
		return err
	}

	c.Name = ncj.Name
	c.mode = ncj.Mode
	c.IPv4 = ncj.IPv4
	c.IPv6 = ncj.IPv6
	c.portRefs = ncj.PortRefs

	fhrpGroup, err := registry.RawMessagesToInterfaces[api.FhrpGroup](ncj.FhrpGroup)
	if err != nil {
		return err
	}
	c.FhrpGroup = fhrpGroup

	return nil
}

func NewConnector(name string, mode api.Mode) api.Connector {
	baseChain := validator.ValidateChain{}
	baseChain.Add(&NetworkListRuleValidator{})
	baseChain.Add(&NameDuplicationValidator{})

	logicChain := validator.ValidateChain{}
	logicChain.Add(&IpAddressConflictValidator{})
	return &NodeConnector{
		Name:               name,
		mode:               mode,
		baseValidateChain:  &baseChain,
		logicValidateChain: &logicChain,
	}
}

func (c *NodeConnector) TypeName() string {
	return "NodeConnector"
}

func (c *NodeConnector) Mode() api.Mode {
	return c.mode
}

func (c *NodeConnector) ID() string {
	return c.Name
}

func (c *NodeConnector) IPv4List() api.StringList {
	return c.IPv4
}

func (c *NodeConnector) IPv6List() api.StringList {
	return c.IPv6
}

func (c *NodeConnector) PortList() []api.Port {
	if c.portIterator == nil {
		return nil
	}
	var ports []api.Port
	for _, ref := range c.portRefs {
		port := c.portIterator.GetPort(ref)
		if port != nil {
			ports = append(ports, port)
		}
	}
	return ports
}

func (c *NodeConnector) Verify(port api.Port) validator.Result {
	data := map[string]interface{}{
		"connector": c,
		"port":      port,
	}

	result := c.baseValidateChain.Validate(data)
	if result.Status() {
		return c.logicValidateChain.Validate(data)
	}

	return result
}

func (c *NodeConnector) WithPortIterator(iterator api.PortIterator) {
	c.portIterator = iterator
}

func (c *NodeConnector) GetOrCreateFhrpGroup(groupIp string, mode api.FhrpMode) api.FhrpGroup {
	for _, vg := range c.FhrpGroup {
		if strings.ToLower(vg.GroupIp()) == strings.ToLower(groupIp) {
			return vg
		}
	}

	vg := NewFhrpGroup(groupIp, mode)

	c.FhrpGroup = append(c.FhrpGroup, vg)
	return vg
}

func (c *NodeConnector) PortCount() int {
	return len(c.portRefs)
}

func (c *NodeConnector) Port(name string) api.Port {
	for _, p := range c.PortList() {
		if p.HitByName(name) {
			return p
		}
	}

	return nil
}

// func (c *NodeConnector) Attach(port api.Port) {
// 	result := c.Verify(port)
// 	if result.Status() {
// 		c.portList = append(c.portList, port)
// 	}

// 	// c.networkList = append(c.networkList, port.GetIpList())
// 	for ipType, ipList := range port.GetIpList() {
// 		if ipType == network.IPv4 {
// 			c.IPv4 = append(c.IPv4, ipList...)
// 		}

// 		if ipType == network.IPv6 {
// 			c.IPv6 = append(c.IPv6, ipList...)
// 		}
// 	}
// }

func (c *NodeConnector) Attach(port api.Port) {
	result := c.Verify(port)
	if tools.ContainsT(c.portRefs, port.ID()) {
		return
	}
	if result.Status() {
		// 使用端口的 ID 而不是直接存储端口对象
		c.portRefs = append(c.portRefs, port.ID())

		// 更新 IPv4 和 IPv6 列表
		for ipType, ipList := range port.GetIpList() {
			if ipType == network.IPv4 {
				c.IPv4 = append(c.IPv4, ipList...)
			}

			if ipType == network.IPv6 {
				c.IPv6 = append(c.IPv6, ipList...)
			}
		}
		port.WithConnectorID(c.ID())
	}
}

func (c *NodeConnector) SelectPortListByNetwork(net network.AbbrNet, vrf string) []api.Port {
	portList := []api.Port{}

	for _, port := range c.PortList() {
		if !port.MatchVrfOrPeerVrf(vrf) {
			continue
		}

		if port.HitByNetwork(net) {
			portList = append(portList, port)
		}
	}

	return portList
}

func (c *NodeConnector) HitByNetwork(net network.AbbrNet, vrf string) bool {
	for _, port := range c.PortList() {
		ips := port.GetIpList()
		for _, t := range []network.IPFamily{network.IPv4, network.IPv6} {
			for _, ip := range ips[t] {
				portNetwork, _ := network.NewNetworkFromString(ip)
				if portNetwork.Match(net) {
					return true
				}
			}
		}
	}

	return false
}

func (c *NodeConnector) HitByIp(ipWithPrefix, vrf string) bool {
	targetIp, err := network.ParseIPNet(ipWithPrefix)
	if err != nil {
		panic(err)
	}

	for _, port := range c.PortList() {
		if port.MatchVrfOrPeerVrf(vrf) == false {
			return false
			// panic(fmt.Sprintf("SelectNodeByIp: %v %s %s, match vrf failed", port, ipWithPrefix, vrf))
		}

		ips := port.GetIpList()
		for _, t := range []network.IPFamily{network.IPv4, network.IPv6} {
			for _, ip := range ips[t] {
				portNetwork, err := network.ParseIPNet(ip)
				if err != nil {
					panic(err)
				}

				if portNetwork.MatchIPNet(targetIp) && targetIp.MatchIPNet(portNetwork) {
					return true
				}

			}
		}
	}
	return false
}

func (c *NodeConnector) SelectNodeByIp(ip, vrf string) (api.Node, api.Port) {
	if c == nil {
		return nil, nil
	}

	targetIp, err := network.ParseIPNet(ip)
	if err != nil {
		panic(err)
	}

	for _, port := range c.PortList() {
		if port.MatchVrfOrPeerVrf(vrf) == false {
			panic(fmt.Sprintf("SelectNodeByIp: %v %s %s, match vrf failed", port, ip, vrf))
		}
		ips := port.GetIpList()
		for _, t := range []network.IPFamily{network.IPv4, network.IPv6} {
			for _, ip := range ips[t] {
				portNetwork, err := network.ParseIPNet(ip)
				if err != nil {
					panic(err)
				}

				if targetIp.IP.Equal(portNetwork.IP) {
					return port.Node(), port
				}
			}
		}

		for _, member := range port.Members() {
			if member.Hit(ip) {
				return port.Node(), port
			}
		}
	}

	return nil, nil
}

func (c *NodeConnector) AddFhrpGroupMember(member api.Member) {
	vg := c.GetOrCreateFhrpGroup(member.Ip(), member.FhrpMode())
	vg.AddMember(member)
}

func init() {
	registry.GlobalInterfaceRegistry.RegisterType(reflect.TypeOf((*api.Connector)(nil)).Elem(), "NodeConnector", reflect.TypeOf(NodeConnector{}))
}

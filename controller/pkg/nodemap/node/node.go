package node

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/model"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/registry"
	"github.com/netxops/utils/tools"
	"github.com/netxops/utils/validator"
)

var _ api.Node = &DeviceNode{}
var _ api.Vrf = &NodeVrf{}

type NodeVrf struct {
	name      string
	ipv4Table *network.AddressTable
	ipv6Table *network.AddressTable
}

func (NodeVrf) WappterUuid() string {
	// 参见github.com/netxops/unify/constant 的 NODE_VRF_ID string = "b8b3b9c8-ec7d-11eb-a247-db4a1496cc86"
	return "b8b3b9c8-ec7d-11eb-a247-db4a1496cc86"
}

func (nv *NodeVrf) TypeName() string {
	return "NodeVrf"
}

func (nv *NodeVrf) Name() string {
	return nv.name
}

func (nv *NodeVrf) Ipv4Table() *network.AddressTable {
	return nv.ipv4Table
}

func (nv *NodeVrf) Ipv6Table() *network.AddressTable {
	return nv.ipv6Table
}

// 用于JSON序列化的辅助结构
type nodeVrfJSON struct {
	Name      string                `json:"name"`
	Ipv4Table *network.AddressTable `json:"ipv4Table"`
	Ipv6Table *network.AddressTable `json:"ipv6Table"`
}

// MarshalJSON 实现 JSON 序列化
func (nv *NodeVrf) MarshalJSON() ([]byte, error) {
	return json.Marshal(&nodeVrfJSON{
		Name:      nv.name,
		Ipv4Table: nv.ipv4Table,
		Ipv6Table: nv.ipv6Table,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (nv *NodeVrf) UnmarshalJSON(data []byte) error {
	var nvj nodeVrfJSON
	if err := json.Unmarshal(data, &nvj); err != nil {
		return err
	}

	nv.name = nvj.Name
	nv.ipv4Table = nvj.Ipv4Table
	nv.ipv6Table = nvj.Ipv6Table

	return nil
}

// type DeviceNode struct {
// 	id           string
// 	name         string
// 	vrfs         []api.Vrf
// 	portList     []api.Port
// 	NodeMapName  string
// 	cmdIp        string
// 	nodeType     api.NodeType
// 	DeviceConfig *config.DeviceConfig
// }

// 修改 DeviceNode
type DeviceNode struct {
	id           string
	name         string
	vrfs         []api.Vrf
	portRefs     []string         // 存储 Port 的引用（例如 ID 或名称）
	portIterator api.PortIterator // 新增字段
	NodeMapName  string
	cmdIp        string
	nodeType     api.NodeType
	DeviceConfig *config.DeviceConfig
}

func NewDeviceNode(id, name string, nodeType api.NodeType) *DeviceNode {
	return &DeviceNode{
		id:       id,
		name:     name,
		nodeType: nodeType,
		vrfs:     []api.Vrf{},
		portRefs: []string{},
	}
}

// 修改 deviceNodeJSON 结构
type deviceNodeJSON struct {
	ID           string               `json:"id"`
	Name         string               `json:"name"`
	Vrfs         []json.RawMessage    `json:"vrfs"`
	PortRefs     []string             `json:"portRefs"` // 改为 PortRefs
	NodeMapName  string               `json:"nodeMapName"`
	CmdIp        string               `json:"cmdIp"`
	NodeType     api.NodeType         `json:"nodeType"`
	DeviceConfig *config.DeviceConfig `json:"deviceConfig"`
}

// MarshalJSON 实现 JSON 序列化
func (n *DeviceNode) MarshalJSON() ([]byte, error) {
	vrfs, err := registry.InterfacesToRawMessages(n.vrfs)
	if err != nil {
		return nil, err
	}
	return json.Marshal(deviceNodeJSON{
		ID:           n.id,
		Name:         n.name,
		Vrfs:         vrfs,
		PortRefs:     n.portRefs, // 直接使用 portRefs
		NodeMapName:  n.NodeMapName,
		CmdIp:        n.cmdIp,
		NodeType:     n.nodeType,
		DeviceConfig: n.DeviceConfig,
	})
}

// UnmarshalJSON 实现 JSON 反序列化
func (n *DeviceNode) UnmarshalJSON(data []byte) error {
	var dnj deviceNodeJSON
	if err := json.Unmarshal(data, &dnj); err != nil {
		return err
	}

	n.id = dnj.ID
	n.name = dnj.Name
	n.NodeMapName = dnj.NodeMapName
	n.cmdIp = dnj.CmdIp
	n.nodeType = dnj.NodeType
	n.DeviceConfig = dnj.DeviceConfig
	n.portRefs = dnj.PortRefs // 直接赋值 portRefs

	var err error
	n.vrfs, err = registry.RawMessagesToInterfaces[api.Vrf](dnj.Vrfs)
	if err != nil {
		return err
	}

	return nil
}

func (n *DeviceNode) TypeName() string {
	return "DeviceNode"
}

func (n *DeviceNode) WithNodeType(t api.NodeType) {
	n.nodeType = t
}

func (n *DeviceNode) NodeType() api.NodeType {
	return n.nodeType
}

func (n *DeviceNode) WithCmdIp(ip string) {
	n.cmdIp = ip
}

func (n *DeviceNode) CmdIp() string {
	return n.cmdIp
}

func (n *DeviceNode) WithName(name string) api.Node {
	n.name = name
	return n
}

func (n *DeviceNode) WithID(id string) api.Node {
	n.id = id
	return n
}

func (n *DeviceNode) PortRefs() []string {
	return n.portRefs
}

func (n *DeviceNode) SetDeviceConfig(deviceConfig *config.DeviceConfig) {
	n.DeviceConfig = deviceConfig
}

func (n *DeviceNode) GetDeviceConfig() *config.DeviceConfig {
	return n.DeviceConfig
}

func (n *DeviceNode) ID() string {
	return n.id
}

func (n *DeviceNode) Name() string {
	return n.name
}

func (n *DeviceNode) Vrfs() []api.Vrf {
	return n.vrfs
}

func (n *DeviceNode) PortList() []api.Port {
	if n.portIterator == nil {
		return []api.Port{}
	}

	ports := make([]api.Port, 0, len(n.portRefs))

	for _, ref := range n.portRefs {
		port := n.portIterator.GetPort(ref)
		if port == nil {
			// 调试：如果通过ID找不到，尝试通过名称查找（如果ref看起来像名称）
			// 注意：这里不应该修改逻辑，只是调试
			continue
		}
		ports = append(ports, port)
	}
	return ports
}

func (n *DeviceNode) GetOrCreateVrf(name string) api.Vrf {
	for _, v := range n.vrfs {
		if v.Name() == name {
			return v
		}
	}
	v := &NodeVrf{
		name: name,
	}
	n.vrfs = append(n.vrfs, v)
	return v
}

func (n *DeviceNode) GetVrf(name string) api.Vrf {
	for _, v := range n.vrfs {
		if v.Name() == name {
			return v
		}
	}

	return nil
}

func (n *DeviceNode) ExtraInit(adapter api.Adapter, deviceConfig *config.DeviceConfig) {
	n.WithNodeType(api.ROUTER)
}

func (n *DeviceNode) SetIpv4RouteTable(vrfName string, table *network.AddressTable) {
	if table.Type() != network.IPv4 {
		panic(fmt.Sprintf("route table type: %s", table.Type()))
	}

	vrf := n.GetVrf(vrfName)
	if vrf != nil {
		vrf.(*NodeVrf).ipv4Table = table
	}
}

func (n *DeviceNode) SetIpv6RouteTable(vrfName string, table *network.AddressTable) {
	if table.Type() != network.IPv6 {
		panic(fmt.Sprintf("route table type: %s", table.Type()))
	}

	vrf := n.GetVrf(vrfName)
	if vrf != nil {
		vrf.(*NodeVrf).ipv6Table = table
	}
}

func (n *DeviceNode) GetPortByNameOrAlias(name string) api.Port {
	for _, p := range n.PortList() {
		if strings.ToLower(p.Name()) == strings.ToLower(name) || tools.ContainsWithoutCase(p.AliasName(), name) {
			return p
		}
	}

	return nil
}

func (n *DeviceNode) GetPortByID(id string) api.Port {
	for _, p := range n.PortList() {
		if p.ID() == id {
			return p
		}
	}

	return nil
}

func (n *DeviceNode) GetPortByIfIndex(ifIndex int) api.Port {
	for _, p := range n.PortList() {
		if p.HitByIfIndex(ifIndex) {
			return p
		}
	}

	return nil
}

// func (node *DeviceNode) AddPort(port api.Port, connection []*config.ConnectionInfo) {
// 	data := map[string]interface{}{
// 		"port":       port,
// 		"connection": connection,
// 	}
// 	result := InterfaceConnectionValidator{}.Validate(data)

// 	if result.Status() == false {
// 		panic(result.Msg())
// 	}

// 	if connection != nil {
// 		for _, cn := range connection {
// 			if cn.Interface == port.Name() {
// 				for _, vrf := range port.PeerVrf() {
// 					port.WithPeerVrf(vrf)

// 				}
// 			}
// 		}
// 	}

// 	node.portList = append(node.portList, port)
// 	node.GetOrCreateVrf(port.Vrf())

// 	// port.WithNode(node)
// }

func (node *DeviceNode) AddPort(port api.Port, connection []*config.ConnectionInfo) {
	data := map[string]interface{}{
		"port":       port,
		"connection": connection,
	}
	result := InterfaceConnectionValidator{}.Validate(data)

	if !result.Status() {
		panic(result.Msg())
	}

	if len(connection) > 0 {
		for _, cn := range connection {
			if cn.Interface == port.Name() {
				for _, vrf := range port.PeerVrf() {
					port.WithPeerVrf(vrf)
				}
			}
		}
	}

	portRef := port.ID()
	for _, ref := range node.portRefs {
		if ref == portRef {
			return
		}
	}

	// 添加新的端口引用
	node.portRefs = append(node.portRefs, portRef)
	node.GetOrCreateVrf(port.Vrf())
	port.WithNode(node)
}

func (node *DeviceNode) FlattenPath() []string {
	path := []string{}
	if node.NodeMapName != "" {
		path = append(path, node.NodeMapName)
	}
	path = append(path, node.Name())

	return path
}

func (node *DeviceNode) FlattenName() string {
	return strings.Join(node.FlattenPath(), "|")
}

func (node *DeviceNode) WithNodeMap(name string) api.Node {
	node.NodeMapName = name
	return node
}

func (n *DeviceNode) WithPortIterator(iterator api.PortIterator) api.Node {
	n.portIterator = iterator
	return n
}

func (node *DeviceNode) Ipv4RouteTable(vrfName string) *network.AddressTable {
	vrf := node.GetVrf(vrfName)
	if vrf == nil {
		return nil
	}

	return vrf.Ipv4Table()
}

func (node *DeviceNode) Ipv6RouteTable(vrfName string) *network.AddressTable {
	vrf := node.GetVrf(vrfName)
	if vrf == nil {
		return nil
	}

	return vrf.Ipv6Table()
}

// func (node *DeviceNode) Ipv6RouteCheck(netList network.NetworkList, inPort, vrf string) (bool, *tools.Table, []string) {
// 	return node.IpRouteCheck(netList, inPort, vrf, network.IPv6)
// }

// func (node *DeviceNode) Ipv4RouteCheck(netList network.NetworkList, inPort, vrf string) (bool, *tools.Table, []string) {
// 	return node.IpRouteCheck(netList, inPort, vrf, network.IPv4)
// }

func (node *DeviceNode) Ipv6RouteCheck(netList network.NetworkList, inPort, vrf string) (bool, *tools.Table, []string, error) {
	return node.IpRouteCheck(netList, inPort, vrf, network.IPv6)
}

// IpRouteCheckInternal 内部路由检查方法，返回 RouteCheckResult（公开方法供 traverse 包使用）
func (node *DeviceNode) IpRouteCheckInternal(netList network.NetworkList, inPort, vrf string, af network.IPFamily) *model.RouteCheckResult {
	result := &model.RouteCheckResult{
		Ok:                false,
		HopTable:          nil,
		PortList:          nil,
		Warning:           nil,
		RouteMatchDetails: make(map[string]interface{}),
	}

	var routeTable *network.AddressTable

	if af == network.IPv4 {
		routeTable = node.Ipv4RouteTable(vrf)
	} else {
		routeTable = node.Ipv6RouteTable(vrf)
	}

	if routeTable == nil {
		return result
	}

	rmr := routeTable.MatchNetList(netList, true, false)
	// 如果没有完全匹配，则返回 false
	if rmr.Unmatch != nil && rmr.Unmatch.Len() > 0 {
		return result
	}

	// 检测多路由匹配
	if rmr.Match.Len() > 1 {
		same, _ := rmr.IsSameIp()
		if !same {
			// 提取所有匹配的路由详情
			matchTable, _ := rmr.Table()
			var matchedRoutes []map[string]interface{}

			if matchTable != nil {
				// 提取路由详情 - DistinctList 是 []interface{}，可以直接 range
				interfaces := matchTable.Column("interface").List()
				ips := matchTable.Column("ip").List()
				connected := matchTable.Column("connected").List()

				// 调试：打印匹配表的详细信息
				fmt.Printf("[DEBUG IpRouteCheckInternal] 多路由匹配详情:\n")
				fmt.Printf("  matchTable.Rows 数量: %d\n", len(matchTable.Rows))
				fmt.Printf("  interfaces 数量: %d, 值: %v\n", len(interfaces), interfaces)
				fmt.Printf("  ips 数量: %d, 值: %v\n", len(ips), ips)
				fmt.Printf("  connected 数量: %d, 值: %v\n", len(connected), connected)

				// 打印完整的匹配表结构以便调试
				if len(matchTable.Rows) > 0 {
					fmt.Printf("  matchTable 完整内容:\n")
					for idx, row := range matchTable.Rows {
						fmt.Printf("    行 %d: %v\n", idx, row)
					}
				}

				// 使用 map 来去重，key 为 "interface:ip:connected" 的组合
				seenRoutes := make(map[string]bool)

				// 获取行数
				rowCount := len(matchTable.Rows)
				for i := 0; i < rowCount && i < len(interfaces) && i < len(ips) && i < len(connected); i++ {
					// 调试：打印每一行的详细信息
					fmt.Printf("[DEBUG IpRouteCheckInternal] 处理路由 %d: interface=%v, ip=%v, connected=%v\n",
						i+1, interfaces[i], ips[i], connected[i])

					// 对于直连路由，如果IP是0.0.0.0或空，尝试从节点获取接口的实际IP地址
					actualIP := ips[i]
					if connected[i].(bool) {
						ipStr, ok := ips[i].(string)
						if ok && (ipStr == "" || ipStr == "0.0.0.0" || ipStr == "::") {
							// 尝试从节点获取接口的IP地址
							ifName, ok := interfaces[i].(string)
							if ok && ifName != "" {
								if port := node.GetPortByNameOrAlias(ifName); port != nil {
									// 获取接口的IP地址
									if af == network.IPv4 {
										ipv4List := port.Ipv4List()
										if len(ipv4List) > 0 {
											// 使用第一个IPv4地址
											actualIP = ipv4List[0]
											fmt.Printf("[DEBUG IpRouteCheckInternal] 直连路由，从接口 %s 获取IP: %s\n", ifName, actualIP)
										}
									} else {
										ipv6List := port.Ipv6List()
										if len(ipv6List) > 0 {
											// 使用第一个IPv6地址
											actualIP = ipv6List[0]
											fmt.Printf("[DEBUG IpRouteCheckInternal] 直连路由，从接口 %s 获取IPv6: %s\n", ifName, actualIP)
										}
									}
								}
							}
						}
					}

					// 创建唯一标识符（使用实际IP）
					routeKey := fmt.Sprintf("%s:%v:%v", interfaces[i], actualIP, connected[i])

					// 只有当这个路由组合还没有出现过时才添加
					if !seenRoutes[routeKey] {
						routeInfo := map[string]interface{}{
							"interface": interfaces[i],
							"ip":        actualIP, // 使用实际IP而不是0.0.0.0
							"connected": connected[i],
						}
						matchedRoutes = append(matchedRoutes, routeInfo)
						seenRoutes[routeKey] = true
						fmt.Printf("[DEBUG IpRouteCheckInternal] 添加唯一路由: %s\n", routeKey)
					} else {
						fmt.Printf("[DEBUG IpRouteCheckInternal] 跳过重复路由: %s\n", routeKey)
					}
				}
			}

			// 创建警告信息
			result.Warning = &model.WarningInfo{
				Type:      model.WarningMultiRouteMatch,
				Message:   fmt.Sprintf("目标网络匹配到多条不同路由: 节点=%s, 入接口=%s, VRF=%s", node.Name(), inPort, vrf),
				Timestamp: time.Now(),
				Details: map[string]interface{}{
					"matched_routes":      matchedRoutes,
					"route_count":         len(matchedRoutes), // 使用去重后的实际路由数量
					"raw_route_count":     rmr.Match.Len(),    // 原始匹配的路由表条目数量（去重前）
					"destination_network": netList.String(),
					"in_port":             inPort,
					"vrf":                 vrf,
					"node":                node.Name(),
				},
			}
			result.RouteMatchDetails = result.Warning.Details
			return result
		}
	}

	match, _ := rmr.Table()
	if match == nil {
		return result
	}

	outInterfaces := match.Column("interface").List().Distinct()
	if len(outInterfaces) == 0 {
		result.Warning = &model.WarningInfo{
			Type:      model.WarningIncompleteRoute,
			Message:   fmt.Sprintf("路由表项不完整: 节点=%s, 入接口=%s, VRF=%s, 目标网络=%s, 路由表项=%v", node.Name(), inPort, vrf, netList.String(), match.Rows),
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"in_port":             inPort,
				"vrf":                 vrf,
				"destination_network": netList.String(),
				"node":                node.Name(),
			},
		}
		return result
	}

	var outPortList []string
	for _, p := range outInterfaces {
		if p.(string) == inPort {
			// 创建警告信息：入接口在出接口列表中
			result.Warning = &model.WarningInfo{
				Type:      model.WarningMissRoute,
				Message:   fmt.Sprintf("入接口在出接口列表中: 节点=%s, 入接口=%s, 出接口列表=%v", node.Name(), inPort, outInterfaces),
				Timestamp: time.Now(),
				Details: map[string]interface{}{
					"in_port":             inPort,
					"out_interfaces":      outInterfaces,
					"node":                node.Name(),
					"vrf":                 vrf,
					"destination_network": netList.String(),
				},
			}
			return result
		}
		outPortList = append(outPortList, p.(string))
	}

	result.Ok = true
	result.HopTable = match // tools.Table 实现了 interface{}，可以直接赋值
	result.PortList = outPortList
	return result
}

// IpRouteCheck 实现 api.Node 接口，保持向后兼容
func (node *DeviceNode) IpRouteCheck(netList network.NetworkList, inPort, vrf string, af network.IPFamily) (bool, *tools.Table, []string, error) {
	result := node.IpRouteCheckInternal(netList, inPort, vrf, af)
	if result.Warning != nil {
		return false, nil, nil, fmt.Errorf(result.Warning.Message)
	}
	// 类型断言 HopTable 为 *tools.Table
	var hopTable *tools.Table
	if result.HopTable != nil {
		if ht, ok := result.HopTable.(*tools.Table); ok {
			hopTable = ht
		}
	}
	return result.Ok, hopTable, result.PortList, nil
}

func (node *DeviceNode) Ipv4RouteCheck(netList network.NetworkList, inPort, vrf string) (bool, *tools.Table, []string, error) {
	return node.IpRouteCheck(netList, inPort, vrf, network.IPv4)
}

// func (node *DeviceNode) IpRouteCheck(netList network.NetworkList, inPort, vrf string, af network.IPFamily) (bool, *tools.Table, []string) {
// 	var routeTable *network.AddressTable

// 	if af == network.IPv4 {
// 		routeTable = node.Ipv4RouteTable(vrf)
// 	} else {
// 		routeTable = node.Ipv6RouteTable(vrf)
// 	}

// 	if routeTable == nil {
// 		return false, nil, nil
// 	}

// 	rmr := routeTable.MatchNetList(netList, true, false)
// 	// 如果没有完全匹配，则返回 false
// 	if rmr.Unmatch != nil && rmr.Unmatch.Len() > 0 {
// 		return false, nil, nil
// 	}

// 	// 这里需要重写，以适配多路径的情况
// 	// ok, hop := rmr.IsSameIp()
// 	if rmr.Match.Len() > 1 {
// 		same, _ := rmr.IsSameIp()
// 		if !same {
// 			fmt.Println(rmr)
// 			panic("current not support multiple match route.")
// 		}
// 	}

// 	match, _ := rmr.Table()

// 	outInterfaces := match.Column("interface").List().Distinct()

// 	var outPortList []string
// 	for _, p := range outInterfaces {
// 		if p.(string) == inPort {
// 			// fmt.Println(netList.List)
// 			panic(fmt.Sprintf("node: %s, inPort %s in %+v", node.Name(), inPort, outInterfaces))
// 		}
// 		outPortList = append(outPortList, p.(string))
// 	}

// 	return true, match, outPortList
// }

type InterfaceConnectionValidator struct{}

func (icv InterfaceConnectionValidator) Validate(data map[string]interface{}) validator.Result {
	port := data["port"].(api.Port)
	c := data["connection"]
	if c == nil {
		return validator.NewValidateResult(true, "")
	}

	connection := c.([]*config.ConnectionInfo)
	for _, cn := range connection {
		if cn.Interface == port.Name() {
			if cn.Vrf == port.Vrf() {
				return validator.NewValidateResult(true, "")
			} else {
				return validator.NewValidateResult(false, fmt.Sprintf("interface %s's vrf %s is not same with connection %+v", port.Name(), port.Vrf(), connection))
			}
		}
	}

	return validator.NewValidateResult(true, "")
}

type VrfExistValidator struct{}

func (v *VrfExistValidator) Validate(data map[string]interface{}) validator.Result {
	node := data["node"].(*DeviceNode)
	virtuals := data["virtuals"].([]*config.VsInfo)
	for _, info := range virtuals {
		vrf := info.Vrf
		if node.GetVrf(vrf) == nil {
			return validator.NewValidateResult(false, fmt.Sprintf("vrf %s is not exist", vrf))
		}
	}

	return validator.NewValidateResult(true, "")
}

type NetworkInRouteValidator struct{}

func (nv *NetworkInRouteValidator) Validate(data map[string]interface{}) validator.Result {
	node := data["node"].(*DeviceNode)
	virtuals := data["virtuals"].([]*config.VsInfo)

	for _, info := range virtuals {
		var routeTable *network.AddressTable
		if info.Type == "IPv4" {
			routeTable = node.Ipv4RouteTable(info.Vrf)
		} else {
			routeTable = node.Ipv6RouteTable(info.Vrf)
		}

		net, _ := network.NewIPNet(info.Network)
		rmr := routeTable.Match(net, false, true)

		if rmr.Match != nil && rmr.Match.Len() > 0 {
			return validator.NewValidateResult(false, fmt.Sprintf("network %s is overlaped owith route table", info.Network))
		}
	}
	return validator.NewValidateResult(true, "")
}

type NetworkTypeValidator struct{}

func (nv *NetworkTypeValidator) Validate(data map[string]interface{}) validator.Result {
	// node := data["node"].(*DeviceNode)
	virtuals := data["virtuals"].([]*config.VsInfo)
	for _, info := range virtuals {
		net, err := network.ParseIPNet(info.Network)
		if err != nil {
			return validator.NewValidateResult(false, fmt.Sprintf("%v", err))
		}
		if net.Type().String() != info.Type {
			return validator.NewValidateResult(false, "network type error")
		}
	}

	return validator.NewValidateResult(true, "")
}

func init() {
	vrfType := reflect.TypeOf((*api.Vrf)(nil)).Elem()
	registry.GlobalInterfaceRegistry.RegisterType(vrfType, "NodeVrf", reflect.TypeOf(NodeVrf{}))
	// 注册其他 Vrf 实现...

	portType := reflect.TypeOf((*api.Port)(nil)).Elem()
	registry.GlobalInterfaceRegistry.RegisterType(portType, "NodePort", reflect.TypeOf(NodePort{}))
	// 注册其他 Port 实现...

	nodeType := reflect.TypeOf((*api.Node)(nil)).Elem()
	registry.GlobalInterfaceRegistry.RegisterType(nodeType, "DeviceNode", reflect.TypeOf(DeviceNode{}))
}

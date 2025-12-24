package nodemap

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/routing/graph"
	"github.com/influxdata/telegraf/controller/pkg/routing/model"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/tools"
)

// NodeMapTopologyAdapter 将NodeMap适配为routing.Topology
type NodeMapTopologyAdapter struct {
	nodeMap *NodeMap
}

var _ graph.Topology = (*NodeMapTopologyAdapter)(nil)

// NewNodeMapTopologyAdapter 创建NodeMap拓扑适配器
func NewNodeMapTopologyAdapter(nodeMap *NodeMap) *NodeMapTopologyAdapter {
	return &NodeMapTopologyAdapter{
		nodeMap: nodeMap,
	}
}

// AddNode 添加节点
func (nmta *NodeMapTopologyAdapter) AddNode(node model.Node) error {
	// NodeMap的节点已经存在，这里不需要添加
	return nil
}

// GetNode 获取节点
func (nmta *NodeMapTopologyAdapter) GetNode(nodeID string) (model.Node, error) {
	// 先尝试通过ID查找
	node := nmta.nodeMap.GetNodeById(nodeID)
	if node == nil {
		// 尝试通过名称查找
		node = nmta.nodeMap.GetNode(nodeID)
	}
	if node == nil {
		return nil, fmt.Errorf("节点不存在: %s", nodeID)
	}
	return NewNodeAdapter(node), nil
}

// ListNodes 列出所有节点
func (nmta *NodeMapTopologyAdapter) ListNodes() []model.Node {
	nodes := make([]model.Node, 0, len(nmta.nodeMap.Nodes))
	for _, node := range nmta.nodeMap.Nodes {
		nodes = append(nodes, NewNodeAdapter(node))
	}
	return nodes
}

// GetPort 获取端口
func (nmta *NodeMapTopologyAdapter) GetPort(portID string) (model.Port, error) {
	port := nmta.nodeMap.GetPort(portID)
	if port == nil {
		return nil, fmt.Errorf("端口不存在: %s", portID)
	}
	return NewPortAdapter(port), nil
}

// ListPorts 列出所有端口
func (nmta *NodeMapTopologyAdapter) ListPorts() []model.Port {
	ports := make([]model.Port, 0, len(nmta.nodeMap.Ports))
	for _, port := range nmta.nodeMap.Ports {
		ports = append(ports, NewPortAdapter(port))
	}
	return ports
}

// GetConnector 获取连接器
func (nmta *NodeMapTopologyAdapter) GetConnector(connectorID string) (model.Connector, error) {
	connector := nmta.nodeMap.CxMananger.GetConnectorByID(connectorID)
	if connector == nil {
		return nil, fmt.Errorf("连接器不存在: %s", connectorID)
	}
	return NewConnectorAdapter(connector), nil
}

// GetConnectorByNetwork 通过网络获取连接器
func (nmta *NodeMapTopologyAdapter) GetConnectorByNetwork(net network.AbbrNet, vrf string) (model.Connector, error) {
	connector := nmta.nodeMap.CxMananger.GetConnectorByNetwork(net, vrf)
	if connector == nil {
		return nil, fmt.Errorf("连接器不存在: network=%s, vrf=%s", net.String(), vrf)
	}
	return NewConnectorAdapter(connector), nil
}

// GetConnectorByIP 通过IP获取连接器
func (nmta *NodeMapTopologyAdapter) GetConnectorByIP(ip, vrf string) (model.Connector, error) {
	connector := nmta.nodeMap.CxMananger.GetConnectorByIp(ip, vrf)
	if connector == nil {
		return nil, fmt.Errorf("连接器不存在: ip=%s, vrf=%s", ip, vrf)
	}
	return NewConnectorAdapter(connector), nil
}

// LocateSourceNode 定位源节点
func (nmta *NodeMapTopologyAdapter) LocateSourceNode(
	src network.NetworkList,
	options *graph.LocateOptions) (model.Node, model.Port, error) {

	// 创建目标网络列表（用于LocateNode）
	var dstNetworkList *network.NetworkList
	// 这里需要从options中获取，暂时使用空列表
	dstNetworkList = &network.NetworkList{}

	// 调用nodemap的LocateNode
	ok, node, portName := nmta.nodeMap.Locator().Locate(
		&src, dstNetworkList, options.Node, options.VRF, options.Gateway, options.Area)

	if !ok {
		return nil, nil, fmt.Errorf("无法定位源节点: %s", portName)
	}

	port := node.GetPortByNameOrAlias(portName)
	if port == nil {
		return nil, nil, fmt.Errorf("无法获取端口: %s", portName)
	}

	return NewNodeAdapter(node), NewPortAdapter(port), nil
}

// GetPortsByArea 获取区域端口
func (nmta *NodeMapTopologyAdapter) GetPortsByArea(area string, ipFamily network.IPFamily) []model.Port {
	ports := nmta.nodeMap.GetPortsByArea(area, ipFamily)
	result := make([]model.Port, 0, len(ports))
	for _, port := range ports {
		result = append(result, NewPortAdapter(port))
	}
	return result
}

// IsOutsidePort 判断是否为Outside端口
func (nmta *NodeMapTopologyAdapter) IsOutsidePort(nodeID, portID string, ipFamily network.IPFamily) (bool, string) {
	return nmta.nodeMap.IsOutsidePort(nodeID, portID, ipFamily)
}

// IsStubPort 判断是否为Stub端口
func (nmta *NodeMapTopologyAdapter) IsStubPort(nodeID, portID string, ipFamily network.IPFamily) bool {
	node := nmta.nodeMap.GetNode(nodeID)
	if node == nil {
		return false
	}
	port := node.GetPortByNameOrAlias(portID)
	if port == nil {
		return false
	}
	return nmta.nodeMap.IsStubPort(node, port, ipFamily)
}

// NodeAdapter 将nodemap.Node适配为routing.Node
type NodeAdapter struct {
	node api.Node
}

var _ model.Node = (*NodeAdapter)(nil)

// NewNodeAdapter 创建节点适配器
func NewNodeAdapter(node api.Node) *NodeAdapter {
	return &NodeAdapter{node: node}
}

// ID 获取节点ID
func (na *NodeAdapter) ID() string {
	return na.node.ID()
}

// Name 获取节点名称
func (na *NodeAdapter) Name() string {
	return na.node.Name()
}

// Type 获取节点类型
func (na *NodeAdapter) Type() model.NodeType {
	switch na.node.NodeType() {
	case api.FIREWALL:
		return model.NodeTypeFirewall
	case api.LB:
		return model.NodeTypeLB
	case api.ROUTER:
		return model.NodeTypeRouter
	default:
		return model.NodeTypeRouter
	}
}

// GetRouteTable 获取路由表
func (na *NodeAdapter) GetRouteTable(vrf string, ipFamily network.IPFamily) (*model.RouteTable, error) {
	var table *network.AddressTable
	if ipFamily == network.IPv4 {
		table = na.node.Ipv4RouteTable(vrf)
	} else {
		table = na.node.Ipv6RouteTable(vrf)
	}

	if table == nil {
		return nil, fmt.Errorf("路由表不存在: vrf=%s, ipFamily=%s", vrf, ipFamily)
	}

	return model.NewRouteTableFromAddressTable(vrf, ipFamily, table), nil
}

// SetRouteTable 设置路由表
func (na *NodeAdapter) SetRouteTable(vrf string, ipFamily network.IPFamily, table *model.RouteTable) error {
	if ipFamily == network.IPv4 {
		na.node.SetIpv4RouteTable(vrf, table.GetAddressTable())
	} else {
		na.node.SetIpv6RouteTable(vrf, table.GetAddressTable())
	}
	return nil
}

// QueryRoute 查询路由
func (na *NodeAdapter) QueryRoute(
	dst network.NetworkList,
	inPort, vrf string,
	ipFamily network.IPFamily) (*model.RouteResult, error) {

	// 调用nodemap的IpRouteCheck
	ok, hopTable, outPorts, err := na.node.IpRouteCheck(dst, inPort, vrf, ipFamily)
	if err != nil {
		return nil, err
	}
	if !ok {
		return &model.RouteResult{Matched: false}, nil
	}

	// 转换为routing.RouteResult
	return convertToRouteResult(hopTable, outPorts), nil
}

// GetPort 获取端口
func (na *NodeAdapter) GetPort(portID string) (model.Port, error) {
	port := na.node.GetPortByID(portID)
	if port == nil {
		return nil, fmt.Errorf("端口不存在: %s", portID)
	}
	return NewPortAdapter(port), nil
}

// GetPortByName 通过名称获取端口
func (na *NodeAdapter) GetPortByName(name string) (model.Port, error) {
	port := na.node.GetPortByNameOrAlias(name)
	if port == nil {
		return nil, fmt.Errorf("端口不存在: %s", name)
	}
	return NewPortAdapter(port), nil
}

// ListPorts 列出所有端口
func (na *NodeAdapter) ListPorts() []model.Port {
	ports := na.node.PortList()
	result := make([]model.Port, 0, len(ports))
	for _, port := range ports {
		result = append(result, NewPortAdapter(port))
	}
	return result
}

// PortAdapter 将nodemap.Port适配为routing.Port
type PortAdapter struct {
	port api.Port
}

var _ model.Port = (*PortAdapter)(nil)

// NewPortAdapter 创建端口适配器
func NewPortAdapter(port api.Port) *PortAdapter {
	return &PortAdapter{port: port}
}

// ID 获取端口ID
func (pa *PortAdapter) ID() string {
	return pa.port.ID()
}

// Name 获取端口名称
func (pa *PortAdapter) Name() string {
	return pa.port.Name()
}

// VRF 获取VRF
func (pa *PortAdapter) VRF() string {
	return pa.port.Vrf()
}

// Node 获取节点
func (pa *PortAdapter) Node() model.Node {
	return NewNodeAdapter(pa.port.Node())
}

// IPAddresses 获取IP地址列表
func (pa *PortAdapter) IPAddresses(ipFamily network.IPFamily) []string {
	return pa.port.GetIpList()[ipFamily]
}

// ConnectorID 获取连接器ID
func (pa *PortAdapter) ConnectorID() string {
	return pa.port.ConnectorID()
}

// ConnectorAdapter 将nodemap.Connector适配为routing.Connector
type ConnectorAdapter struct {
	connector api.Connector
}

var _ model.Connector = (*ConnectorAdapter)(nil)

// NewConnectorAdapter 创建连接器适配器
func NewConnectorAdapter(connector api.Connector) *ConnectorAdapter {
	return &ConnectorAdapter{connector: connector}
}

// ID 获取连接器ID
func (ca *ConnectorAdapter) ID() string {
	return ca.connector.ID()
}

// SelectNodeByIP 通过IP选择节点
func (ca *ConnectorAdapter) SelectNodeByIP(ip, vrf string) (model.Node, model.Port, error) {
	node, port := ca.connector.SelectNodeByIp(ip, vrf)
	if node == nil {
		return nil, nil, fmt.Errorf("未找到节点: ip=%s, vrf=%s", ip, vrf)
	}
	return NewNodeAdapter(node), NewPortAdapter(port), nil
}

// SelectPortsByNetwork 通过网络选择端口
func (ca *ConnectorAdapter) SelectPortsByNetwork(net network.AbbrNet, vrf string) []model.Port {
	ports := ca.connector.SelectPortListByNetwork(net, vrf)
	result := make([]model.Port, 0, len(ports))
	for _, port := range ports {
		result = append(result, NewPortAdapter(port))
	}
	return result
}

// HitByNetwork 检查是否匹配网络
func (ca *ConnectorAdapter) HitByNetwork(net network.AbbrNet, vrf string) bool {
	return ca.connector.HitByNetwork(net, vrf)
}

// HitByIp 检查是否匹配IP
func (ca *ConnectorAdapter) HitByIp(ip, vrf string) bool {
	return ca.connector.HitByIp(ip, vrf)
}

// convertToRouteResult 将hopTable转换为RouteResult
func convertToRouteResult(hopTable *tools.Table, outPorts []string) *model.RouteResult {
	if hopTable == nil {
		return &model.RouteResult{Matched: false}
	}

	var nextHops []*model.NextHopInfo
	connectedList := hopTable.Column("connected").List().Distinct()
	isConnected := false

	if len(connectedList) > 0 {
		isConnected = connectedList[0].(bool)
	}

	for it := hopTable.Iterator(); it.HasNext(); {
		_, hopMap := it.Next()
		interfaceName := hopMap["interface"].(string)
		nextHopIP := hopMap["ip"].(string)
		connected := hopMap["connected"].(bool)

		nextHops = append(nextHops, model.NewNextHopInfo(interfaceName, nextHopIP, connected))
	}

	isECMP := len(nextHops) > 1

	return &model.RouteResult{
		Matched:     true,
		OutPorts:    outPorts,
		NextHops:    nextHops,
		IsConnected: isConnected,
		IsECMP:      isECMP,
	}
}

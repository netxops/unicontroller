package graph

import (
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/routing/model"
	"github.com/netxops/utils/network"
)

// Topology 网络拓扑接口
type Topology interface {
	// Node管理
	AddNode(node model.Node) error
	GetNode(nodeID string) (model.Node, error)
	ListNodes() []model.Node

	// 端口管理
	GetPort(portID string) (model.Port, error)
	ListPorts() []model.Port

	// 连接器管理
	GetConnector(connectorID string) (model.Connector, error)
	GetConnectorByNetwork(net network.AbbrNet, vrf string) (model.Connector, error)
	GetConnectorByIP(ip, vrf string) (model.Connector, error)

	// 节点定位
	LocateSourceNode(src network.NetworkList, options *LocateOptions) (model.Node, model.Port, error)

	// 区域和Stub管理
	GetPortsByArea(area string, ipFamily network.IPFamily) []model.Port
	IsOutsidePort(nodeID, portID string, ipFamily network.IPFamily) (bool, string)
	IsStubPort(nodeID, portID string, ipFamily network.IPFamily) bool
}

// LocateOptions 定位选项
type LocateOptions struct {
	VRF     string
	Gateway string
	Area    string
	Node    string
}

// BaseTopology 基础拓扑实现
type BaseTopology struct {
	nodes      map[string]model.Node
	ports      map[string]model.Port
	connectors map[string]model.Connector
}

// NewBaseTopology 创建基础拓扑
func NewBaseTopology() *BaseTopology {
	return &BaseTopology{
		nodes:      make(map[string]model.Node),
		ports:      make(map[string]model.Port),
		connectors: make(map[string]model.Connector),
	}
}

// AddNode 添加节点
func (bt *BaseTopology) AddNode(node model.Node) error {
	if node == nil {
		return fmt.Errorf("节点不能为空")
	}
	bt.nodes[node.ID()] = node
	return nil
}

// GetNode 获取节点
func (bt *BaseTopology) GetNode(nodeID string) (model.Node, error) {
	if node, exists := bt.nodes[nodeID]; exists {
		return node, nil
	}
	return nil, fmt.Errorf("节点不存在: %s", nodeID)
}

// ListNodes 列出所有节点
func (bt *BaseTopology) ListNodes() []model.Node {
	nodes := make([]model.Node, 0, len(bt.nodes))
	for _, node := range bt.nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// GetPort 获取端口
func (bt *BaseTopology) GetPort(portID string) (model.Port, error) {
	if port, exists := bt.ports[portID]; exists {
		return port, nil
	}
	return nil, fmt.Errorf("端口不存在: %s", portID)
}

// ListPorts 列出所有端口
func (bt *BaseTopology) ListPorts() []model.Port {
	ports := make([]model.Port, 0, len(bt.ports))
	for _, port := range bt.ports {
		ports = append(ports, port)
	}
	return ports
}

// GetConnector 获取连接器
func (bt *BaseTopology) GetConnector(connectorID string) (model.Connector, error) {
	if connector, exists := bt.connectors[connectorID]; exists {
		return connector, nil
	}
	return nil, fmt.Errorf("连接器不存在: %s", connectorID)
}

// GetConnectorByNetwork 通过网络获取连接器
func (bt *BaseTopology) GetConnectorByNetwork(net network.AbbrNet, vrf string) (model.Connector, error) {
	// 默认实现，需要子类实现
	return nil, fmt.Errorf("未实现")
}

// GetConnectorByIP 通过IP获取连接器
func (bt *BaseTopology) GetConnectorByIP(ip, vrf string) (model.Connector, error) {
	// 默认实现，需要子类实现
	return nil, fmt.Errorf("未实现")
}

// LocateSourceNode 定位源节点
func (bt *BaseTopology) LocateSourceNode(src network.NetworkList, options *LocateOptions) (model.Node, model.Port, error) {
	// 默认实现，需要子类实现
	return nil, nil, fmt.Errorf("未实现")
}

// GetPortsByArea 获取区域端口
func (bt *BaseTopology) GetPortsByArea(area string, ipFamily network.IPFamily) []model.Port {
	// 默认实现，需要子类实现
	return []model.Port{}
}

// IsOutsidePort 判断是否为Outside端口
func (bt *BaseTopology) IsOutsidePort(nodeID, portID string, ipFamily network.IPFamily) (bool, string) {
	// 默认实现，需要子类实现
	return false, ""
}

// IsStubPort 判断是否为Stub端口
func (bt *BaseTopology) IsStubPort(nodeID, portID string, ipFamily network.IPFamily) bool {
	// 默认实现，需要子类实现
	return false
}

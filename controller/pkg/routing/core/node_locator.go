package core

import (
	"github.com/influxdata/telegraf/controller/pkg/routing/graph"
	"github.com/influxdata/telegraf/controller/pkg/routing/model"
	"github.com/netxops/utils/network"
)

// NodeLocator 节点定位器
type NodeLocator struct {
	topology graph.Topology
}

// NewNodeLocator 创建节点定位器
func NewNodeLocator(topology graph.Topology) *NodeLocator {
	return &NodeLocator{
		topology: topology,
	}
}

// LocateSourceNode 定位源节点
func (nl *NodeLocator) LocateSourceNode(
	src network.NetworkList,
	options *graph.LocateOptions) (model.Node, model.Port, error) {

	return nl.topology.LocateSourceNode(src, options)
}

// LocateStubNode 定位Stub节点
func (nl *NodeLocator) LocateStubNode(
	netList *network.NetworkList,
	vrf string,
	ipType network.IPFamily) (bool, model.Node, model.Port) {

	// 默认实现，需要子类实现
	return false, nil, nil
}

// LocateOutsideNode 定位Outside节点
func (nl *NodeLocator) LocateOutsideNode(
	vrf string,
	ipType network.IPFamily) []model.Node {

	// 默认实现，需要子类实现
	return []model.Node{}
}

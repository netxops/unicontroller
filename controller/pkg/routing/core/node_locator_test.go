package core

import (
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/routing/graph"
	"github.com/netxops/utils/network"
)

// TestNewNodeLocator 测试创建节点定位器
func TestNewNodeLocator(t *testing.T) {
	topology := graph.NewBaseTopology()
	nl := NewNodeLocator(topology)

	if nl == nil {
		t.Fatal("NodeLocator不应该为空")
	}

	if nl.topology == nil {
		t.Error("topology不应该为nil")
	}
}

// TestNodeLocator_LocateSourceNode 测试定位源节点
func TestNodeLocator_LocateSourceNode(t *testing.T) {
	topology := graph.NewBaseTopology()
	nl := NewNodeLocator(topology)

	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	options := &graph.LocateOptions{
		VRF:     "default",
		Gateway: "",
		Area:    "",
		Node:    "",
	}

	// BaseTopology 的 LocateSourceNode 返回未实现错误
	node, port, err := nl.LocateSourceNode(*dst, options)
	if err == nil {
		t.Error("BaseTopology应该返回未实现错误")
	}

	if node != nil {
		t.Error("未实现时节点应该为nil")
	}

	if port != nil {
		t.Error("未实现时端口应该为nil")
	}
}

// TestNodeLocator_LocateStubNode 测试定位Stub节点
func TestNodeLocator_LocateStubNode(t *testing.T) {
	topology := graph.NewBaseTopology()
	nl := NewNodeLocator(topology)

	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	// LocateStubNode 默认实现返回 false, nil, nil
	found, node, port := nl.LocateStubNode(dst, "default", network.IPv4)

	if found {
		t.Error("默认实现应该返回false")
	}

	if node != nil {
		t.Error("默认实现节点应该为nil")
	}

	if port != nil {
		t.Error("默认实现端口应该为nil")
	}
}

// TestNodeLocator_LocateOutsideNode 测试定位Outside节点
func TestNodeLocator_LocateOutsideNode(t *testing.T) {
	topology := graph.NewBaseTopology()
	nl := NewNodeLocator(topology)

	// LocateOutsideNode 默认实现返回空列表
	nodes := nl.LocateOutsideNode("default", network.IPv4)

	if nodes == nil {
		t.Error("结果不应该为nil")
	}

	if len(nodes) != 0 {
		t.Errorf("期望节点数量为0，实际为%d", len(nodes))
	}
}

// TestNodeLocator_LocateOutsideNode_DifferentVRF 测试不同VRF的Outside节点
func TestNodeLocator_LocateOutsideNode_DifferentVRF(t *testing.T) {
	topology := graph.NewBaseTopology()
	nl := NewNodeLocator(topology)

	// 测试不同VRF
	vrf1Nodes := nl.LocateOutsideNode("vrf1", network.IPv4)
	vrf2Nodes := nl.LocateOutsideNode("vrf2", network.IPv4)

	if len(vrf1Nodes) != 0 {
		t.Errorf("vrf1期望节点数量为0，实际为%d", len(vrf1Nodes))
	}

	if len(vrf2Nodes) != 0 {
		t.Errorf("vrf2期望节点数量为0，实际为%d", len(vrf2Nodes))
	}
}

// TestNodeLocator_LocateOutsideNode_IPv6 测试IPv6的Outside节点
func TestNodeLocator_LocateOutsideNode_IPv6(t *testing.T) {
	topology := graph.NewBaseTopology()
	nl := NewNodeLocator(topology)

	// 测试IPv6
	nodes := nl.LocateOutsideNode("default", network.IPv6)

	if nodes == nil {
		t.Error("结果不应该为nil")
	}

	if len(nodes) != 0 {
		t.Errorf("期望节点数量为0，实际为%d", len(nodes))
	}
}

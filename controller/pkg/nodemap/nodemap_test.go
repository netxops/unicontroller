package nodemap

import (
	"encoding/json"
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/netxops/utils/network"
	"github.com/stretchr/testify/assert"
)

func TestNodeMapSerialization(t *testing.T) {
	// 创建测试用的端口
	port1 := node.NewPort("Port1", "Tenant1", map[network.IPFamily][]string{
		network.IPv4: {"192.168.1.1/24"},
	}, nil)
	port1.WithID("1")

	port2 := node.NewPort("Port2", "Tenant1", map[network.IPFamily][]string{
		network.IPv4: {"192.168.2.1/24"},
	}, nil)
	port2.WithID("2")

	// 创建测试用的节点
	node1 := node.NewDeviceNode("node1", "Node1", api.ROUTER)
	node2 := node.NewDeviceNode("node2", "Node2", api.ROUTER)

	// 创建一个测试用的 NodeMap
	nm := &NodeMap{
		Name:  "TestNodeMap",
		Ports: []api.Port{port1, port2},
		Nodes: []api.Node{node1, node2},
		Ipv4Areas: []*config.AreaInfo{
			{
				Name:      "Area1",
				NodeName:  "Node1",
				Interface: "Port1",
			},
		},
		Ipv6Areas: []*config.AreaInfo{
			{
				Name:      "Area2",
				NodeName:  "Node2",
				Interface: "Port2",
			},
		},
		Ipv4Stubs: []*StubInfo{
			{
				Node: node.NewDeviceNode("stubnode1", "StubNode1", api.ROUTER),
				Port: node.NewPort("StubPort1", "Tenant1", nil, nil).WithID("stubport1"),
			},
		},
		Ipv6Stubs: []*StubInfo{
			{
				Node: node.NewDeviceNode("stubnode2", "StubNode2", api.ROUTER),
				Port: node.NewPort("StubPort2", "Tenant1", nil, nil).WithID("stubport2"),
			},
		},
		CxMananger: &ConnectorManager{},
		TNodeMapID: new(uint),
		taskId:     1,
	}

	// 添加端口到节点
	node1.AddPort(port1, nil)
	node2.AddPort(port2, nil)

	// 设置 PortIterator
	for _, n := range nm.Nodes {
		n.WithPortIterator(nm)
	}

	// 序列化
	data, err := json.Marshal(nm)
	assert.NoError(t, err)

	// 反序列化
	var deserializedNM NodeMap
	err = json.Unmarshal(data, &deserializedNM)
	assert.NoError(t, err)

	// 验证反序列化后的数据
	assert.Equal(t, nm.Name, deserializedNM.Name)
	assert.Equal(t, len(nm.Ports), len(deserializedNM.Ports))
	assert.Equal(t, len(nm.Nodes), len(deserializedNM.Nodes))
	assert.Equal(t, len(nm.Ipv4Areas), len(deserializedNM.Ipv4Areas))
	assert.Equal(t, len(nm.Ipv6Areas), len(deserializedNM.Ipv6Areas))
	assert.Equal(t, len(nm.Ipv4Stubs), len(deserializedNM.Ipv4Stubs))
	assert.Equal(t, len(nm.Ipv6Stubs), len(deserializedNM.Ipv6Stubs))
	assert.NotNil(t, deserializedNM.CxMananger)
	assert.Equal(t, nm.taskId, deserializedNM.taskId)

	// 验证 Ports
	assert.Equal(t, nm.Ports[0].(*node.NodePort).Name(), deserializedNM.Ports[0].(*node.NodePort).Name())
	assert.Equal(t, nm.Ports[1].(*node.NodePort).Name(), deserializedNM.Ports[1].(*node.NodePort).Name())

	// 验证 Nodes
	assert.Equal(t, nm.Nodes[0].(*node.DeviceNode).Name(), deserializedNM.Nodes[0].(*node.DeviceNode).Name())
	assert.Equal(t, nm.Nodes[1].(*node.DeviceNode).Name(), deserializedNM.Nodes[1].(*node.DeviceNode).Name())
	assert.Equal(t, nm.Nodes[0].(*node.DeviceNode).ID(), deserializedNM.Nodes[0].(*node.DeviceNode).ID())
	assert.Equal(t, nm.Nodes[1].(*node.DeviceNode).ID(), deserializedNM.Nodes[1].(*node.DeviceNode).ID())

	// 验证 Node 的 portRefs
	assert.Equal(t, nm.Nodes[0].(*node.DeviceNode).PortRefs(), deserializedNM.Nodes[0].(*node.DeviceNode).PortRefs())
	assert.Equal(t, nm.Nodes[1].(*node.DeviceNode).PortRefs(), deserializedNM.Nodes[1].(*node.DeviceNode).PortRefs())

	// 验证 Ipv4Areas
	assert.Equal(t, nm.Ipv4Areas[0].Name, deserializedNM.Ipv4Areas[0].Name)
	assert.Equal(t, nm.Ipv4Areas[0].NodeName, deserializedNM.Ipv4Areas[0].NodeName)
	assert.Equal(t, nm.Ipv4Areas[0].Interface, deserializedNM.Ipv4Areas[0].Interface)

	// 验证 Ipv6Areas
	assert.Equal(t, nm.Ipv6Areas[0].Name, deserializedNM.Ipv6Areas[0].Name)
	assert.Equal(t, nm.Ipv6Areas[0].NodeName, deserializedNM.Ipv6Areas[0].NodeName)
	assert.Equal(t, nm.Ipv6Areas[0].Interface, deserializedNM.Ipv6Areas[0].Interface)

	// 验证 Ipv4Stubs
	assert.Equal(t, nm.Ipv4Stubs[0].Node.(*node.DeviceNode).Name(), deserializedNM.Ipv4Stubs[0].Node.(*node.DeviceNode).Name())
	assert.Equal(t, nm.Ipv4Stubs[0].Port.(*node.NodePort).Name(), deserializedNM.Ipv4Stubs[0].Port.(*node.NodePort).Name())

	// 验证 Ipv6Stubs
	assert.Equal(t, nm.Ipv6Stubs[0].Node.(*node.DeviceNode).Name(), deserializedNM.Ipv6Stubs[0].Node.(*node.DeviceNode).Name())
	assert.Equal(t, nm.Ipv6Stubs[0].Port.(*node.NodePort).Name(), deserializedNM.Ipv6Stubs[0].Port.(*node.NodePort).Name())

	// 验证 PortIterator 功能
	for i, n := range deserializedNM.Nodes {
		deviceNode := n.(*node.DeviceNode)
		assert.NotNil(t, deviceNode.PortList())
		assert.Equal(t, len(deviceNode.PortRefs()), len(deviceNode.PortList()))
		for _, portRef := range deviceNode.PortRefs() {
			port := deviceNode.GetPortByID(portRef)
			assert.NotNil(t, port)
			assert.Equal(t, nm.Ports[i].(*node.NodePort).Name(), port.Name())
			assert.Equal(t, nm.Ports[i].(*node.NodePort).ID(), port.ID())
		}
	}
}

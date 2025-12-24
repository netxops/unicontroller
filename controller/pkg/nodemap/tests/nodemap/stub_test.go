package nodemap_test

import (
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/tests/fixtures"
	"github.com/netxops/utils/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocateStubNode(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	node1 := fixtures.NewTestNode("node1", api.ROUTER)
	port1 := fixtures.NewTestPort("port1", "vrf1", nil)
	// 确保端口有正确的VRF设置
	port1.WithVrf("vrf1")

	node1.AddPort(port1, nil)
	nm.Ports = append(nm.Ports, port1)

	// 确保节点有portIterator
	node1.WithPortIterator(nm)

	nm.AddNode(node1, nil)

	// 再次确保portIterator
	node1.WithPortIterator(nm)

	// 创建并设置路由表（LocateStubNode需要路由表）
	routeTable := network.NewAddressTable(network.IPv4)
	// 添加一个路由，使192.168.1.10能够匹配到port1
	net, err := network.ParseIPNet("192.168.1.0/24")
	require.NoError(t, err)

	nextHop := &network.NextHop{}
	nextHop.AddHop("port1", "192.168.1.1", false, false, nil)

	err = routeTable.PushRoute(net, nextHop)
	require.NoError(t, err)

	// 设置路由表到节点
	node1.GetOrCreateVrf("vrf1")
	node1.SetIpv4RouteTable("vrf1", routeTable)

	// 设置 Stub 接口
	nm.SetStubInterface("node1", "port1", network.IPv4)

	// 测试定位 Stub 节点
	srcNetList := fixtures.NewTestIPv4NetworkList("192.168.1.10")
	ok, node, port := nm.LocateStubNode(srcNetList, "vrf1", network.IPv4)

	require.True(t, ok, "Should locate stub node")
	require.NotNil(t, node)
	require.NotNil(t, port)
	assert.Equal(t, "node1", node.Name())
	assert.Equal(t, "port1", port.Name())
}

func TestSetStubInterface(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	node1 := fixtures.NewTestNode("node1", api.ROUTER)
	port1 := fixtures.NewTestPort("port1", "vrf1", nil)
	// 确保端口有正确的VRF设置
	port1.WithVrf("vrf1")

	node1.AddPort(port1, nil)
	nm.Ports = append(nm.Ports, port1)

	// 确保节点有portIterator
	node1.WithPortIterator(nm)

	nm.AddNode(node1, nil)

	// 再次确保portIterator
	node1.WithPortIterator(nm)

	// 设置 Stub 接口
	nm.SetStubInterface("node1", "port1", network.IPv4)

	// 验证 Stub 接口已设置
	assert.Equal(t, 1, len(nm.Ipv4Stubs))
	if len(nm.Ipv4Stubs) > 0 {
		assert.Equal(t, "node1", nm.Ipv4Stubs[0].Node.Name())
		assert.Equal(t, "port1", nm.Ipv4Stubs[0].Port.Name())
	}
}

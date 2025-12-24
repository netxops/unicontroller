package nodemap_test

import (
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/tests/fixtures"
	"github.com/netxops/utils/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocateNodeByNetwork(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	node1 := fixtures.NewTestNode("node1", api.ROUTER)

	port1 := fixtures.NewTestPort("port1", "vrf1", map[network.IPFamily][]string{
		network.IPv4: {"192.168.1.1/24"},
	})
	// 确保端口有正确的VRF设置（NewPort只设置Tenant，需要显式设置PortVrf）
	port1.WithVrf("vrf1")

	// 先添加端口到节点，再添加节点到NodeMap
	// 这样AddNode会自动将端口添加到Connector
	node1.AddPort(port1, nil)
	nm.Ports = append(nm.Ports, port1)

	// 确保节点有portIterator
	node1.WithPortIterator(nm)

	// 添加节点到NodeMap（这会自动处理Connector）
	nm.AddNode(node1, nil)

	// 再次确保portIterator（AddNode可能会重置）
	node1.WithPortIterator(nm)

	// 测试通过网络定位节点
	// 192.168.1.10 应该在 192.168.1.1/24 网段内，应该能匹配到port1
	srcNetList := fixtures.NewTestIPv4NetworkList("192.168.1.10")
	ok, node, portName := nm.Locator().Locate(srcNetList, nil, "", "vrf1", "", "")

	require.True(t, ok, "Should locate node via network")
	assert.NotNil(t, node)
	assert.Equal(t, "node1", node.Name())
	assert.Equal(t, "port1", portName)
}

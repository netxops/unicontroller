package firewall_test

import (
	"encoding/json"
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/asa"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/tests/fixtures"
	"github.com/netxops/utils/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestASANode 创建测试用的 ASA 节点（简化版）
func newTestASANode() *asa.ASANode {
	asaNode := &asa.ASANode{
		DeviceNode: &node.DeviceNode{
			NodeMapName: "test-nodemap",
		},
	}
	asaNode.WithName("test-asa")
	asaNode.WithNodeType(api.FIREWALL)
	return asaNode
}

// simplePortIterator 简单的 PortIterator 实现，用于测试
type simplePortIterator struct {
	ports map[string]api.Port
}

func (s *simplePortIterator) GetPort(ref string) api.Port {
	return s.ports[ref]
}

func (s *simplePortIterator) GetAllPorts() []api.Port {
	result := make([]api.Port, 0, len(s.ports))
	for _, port := range s.ports {
		result = append(result, port)
	}
	return result
}

func newSimplePortIterator(ports map[string]api.Port) api.PortIterator {
	return &simplePortIterator{ports: ports}
}

// TestASANodeCreation 测试 ASA 节点创建
func TestASANodeCreation(t *testing.T) {
	// 创建 ASA 节点
	asaNode := newTestASANode()

	// 验证节点基本信息
	assert.Equal(t, "ASANode", asaNode.TypeName(), "节点类型名称应该匹配")
	assert.Equal(t, "test-asa", asaNode.Name(), "节点名称应该匹配")
	assert.Equal(t, api.FIREWALL, asaNode.NodeType(), "节点类型应该匹配")

	// 验证实现了 FirewallNode 接口
	var _ firewall.FirewallNode = asaNode
}

// TestASANodeInterface 测试 ASA 节点接口实现
func TestASANodeInterface(t *testing.T) {
	asaNode := newTestASANode()

	// 验证实现了 FirewallNode 接口
	var _ firewall.FirewallNode = asaNode

	// 验证实现了 Node 接口
	var _ api.Node = asaNode
}

// TestASAPortCreation 测试 ASA 端口创建
func TestASAPortCreation(t *testing.T) {
	// 创建 ASA 端口
	ipList := map[network.IPFamily][]string{
		network.IPv4: {"192.168.1.1/24"},
		network.IPv6: {"2001:db8::1/64"},
	}

	port := asa.NewASAPort("outside", "default", ipList, []api.Member{})

	// 验证端口基本信息
	assert.Equal(t, "ASAPort", port.TypeName(), "端口类型名称应该匹配")
	assert.Equal(t, "outside", port.Name(), "端口名称应该匹配")

	// 验证 IP 地址
	ipListFromPort := port.GetIpList()
	assert.Contains(t, ipListFromPort[network.IPv4], "192.168.1.1/24", "应该包含 IPv4 地址")
	assert.Contains(t, ipListFromPort[network.IPv6], "2001:db8::1/64", "应该包含 IPv6 地址")

	// 验证实现了 ZoneFirewall 接口
	var _ firewall.ZoneFirewall = port
}

// TestASAPortZone 测试 ASA 端口 Zone 功能
func TestASAPortZone(t *testing.T) {
	ipList := map[network.IPFamily][]string{
		network.IPv4: {"192.168.1.1/24"},
	}

	port := asa.NewASAPort("outside", "default", ipList, []api.Member{})

	// 设置 Zone
	port.WithZone("OUTSIDE")
	assert.Equal(t, "OUTSIDE", port.Zone(), "Zone 应该匹配")

	// 设置安全级别
	port.WithLevel("0")
	assert.Equal(t, "0", port.Level(), "安全级别应该匹配")

	// 设置 ACL
	port.WithInAcl("OUTSIDE_IN")
	port.WithOutAcl("OUTSIDE_OUT")
	assert.Equal(t, "OUTSIDE_IN", port.InAcl(), "输入 ACL 应该匹配")
	assert.Equal(t, "OUTSIDE_OUT", port.OutAcl(), "输出 ACL 应该匹配")
}

// TestASAPortMainIp 测试 ASA 端口主 IP 地址
func TestASAPortMainIp(t *testing.T) {
	ipList := map[network.IPFamily][]string{
		network.IPv4: {"192.168.1.1/24"},
		network.IPv6: {"2001:db8::1/64"},
	}

	port := asa.NewASAPort("outside", "default", ipList, []api.Member{})

	// 设置主 IPv4
	port.WithMainIpv4("192.168.1.1/24")
	assert.Equal(t, "192.168.1.1/24", port.MainIpv4(), "主 IPv4 应该匹配")

	// 设置主 IPv6
	port.WithMainIpv6("2001:db8::1/64")
	assert.Equal(t, "2001:db8::1/64", port.MainIpv6(), "主 IPv6 应该匹配")
}

// TestASANodeSerialization 测试 ASA 节点序列化/反序列化
func TestASANodeSerialization(t *testing.T) {
	asaNode := newTestASANode()

	// 序列化
	jsonData, err := json.Marshal(asaNode)
	require.NoError(t, err, "序列化应该成功")
	require.NotEmpty(t, jsonData, "序列化数据不应为空")

	// 反序列化
	var deserializedNode asa.ASANode
	err = json.Unmarshal(jsonData, &deserializedNode)
	require.NoError(t, err, "反序列化应该成功")

	// 验证反序列化后的节点
	assert.Equal(t, asaNode.TypeName(), deserializedNode.TypeName(), "节点类型应该匹配")
}

// TestASANodeExtraInit 测试 ASA 节点额外初始化
// 注意：这个测试需要完整的适配器配置，暂时跳过
// ExtraInit 需要适配器正确配置，在实际使用中通过工厂方法创建节点时会自动调用
func TestASANodeExtraInit(t *testing.T) {
	t.Skip("跳过 ExtraInit 测试，需要完整的适配器配置")
}

// TestASANodeMultiplePorts 测试 ASA 节点多个端口
func TestASANodeMultiplePorts(t *testing.T) {
	asaNode := newTestASANode()

	// 创建多个端口
	port1 := asa.NewASAPort("outside", "default", map[network.IPFamily][]string{
		network.IPv4: {"203.0.113.1/24"},
	}, []api.Member{})
	port1.WithZone("OUTSIDE")
	port1.WithLevel("0")
	port1.WithID("port1-id")
	port1.WithNode(asaNode)

	port2 := asa.NewASAPort("inside", "default", map[network.IPFamily][]string{
		network.IPv4: {"192.168.1.1/24"},
	}, []api.Member{})
	port2.WithZone("INSIDE")
	port2.WithLevel("100")
	port2.WithID("port2-id")
	port2.WithNode(asaNode)

	// 创建简单的 PortIterator（用于测试）
	// 注意：在实际使用中，PortIterator 通常由 NodeMap 提供
	// 这里我们创建一个简单的实现用于测试
	simpleIterator := newSimplePortIterator(map[string]api.Port{
		"port1-id": port1,
		"port2-id": port2,
	})

	// 设置 PortIterator
	asaNode.WithPortIterator(simpleIterator)

	// 添加端口到节点
	asaNode.AddPort(port1, nil)
	asaNode.AddPort(port2, nil)

	// 验证端口列表
	ports := asaNode.PortList()
	require.Len(t, ports, 2, "应该有 2 个端口")

	// 验证端口信息
	portNames := make(map[string]bool)
	for _, p := range ports {
		portNames[p.Name()] = true
	}
	assert.True(t, portNames["outside"], "应该包含 outside 端口")
	assert.True(t, portNames["inside"], "应该包含 inside 端口")
}

// TestASANodeVRF 测试 ASA 节点 VRF 功能
func TestASANodeVRF(t *testing.T) {
	asaNode := newTestASANode()

	// 创建 VRF
	vrf := asaNode.GetOrCreateVrf("default")
	require.NotNil(t, vrf, "应该创建 VRF")
	assert.Equal(t, "default", vrf.Name(), "VRF 名称应该匹配")

	// 获取已存在的 VRF
	vrf2 := asaNode.GetOrCreateVrf("default")
	assert.Equal(t, vrf, vrf2, "应该返回同一个 VRF 对象")

	// 创建不同的 VRF
	vrf3 := asaNode.GetOrCreateVrf("vrf1")
	require.NotNil(t, vrf3, "应该创建新的 VRF")
	assert.Equal(t, "vrf1", vrf3.Name(), "VRF 名称应该匹配")
	assert.NotEqual(t, vrf, vrf3, "应该是不同的 VRF 对象")
}

// TestASANodeRouteTable 测试 ASA 节点路由表
func TestASANodeRouteTable(t *testing.T) {
	asaNode := newTestASANode()

	// 首先创建 VRF（路由表需要 VRF）
	vrf := asaNode.GetOrCreateVrf("default")
	require.NotNil(t, vrf, "应该创建 VRF")

	// 创建路由表
	routeTable := network.NewAddressTable(network.IPv4)
	require.NotNil(t, routeTable, "应该创建路由表")

	// 设置路由表
	asaNode.SetIpv4RouteTable("default", routeTable)

	// 获取路由表
	retrievedTable := asaNode.Ipv4RouteTable("default")
	require.NotNil(t, retrievedTable, "应该获取路由表")
	assert.Equal(t, routeTable, retrievedTable, "路由表应该匹配")
}

// TestASANodeComplexScenario 测试 ASA 节点复杂场景
func TestASANodeComplexScenario(t *testing.T) {
	// 创建 ASA 节点
	asaNode := newTestASANode()

	// 创建多个端口
	ports := []*asa.ASAPort{
		asa.NewASAPort("outside", "default", map[network.IPFamily][]string{
			network.IPv4: {"203.0.113.1/24"},
		}, []api.Member{}),
		asa.NewASAPort("inside", "default", map[network.IPFamily][]string{
			network.IPv4: {"192.168.1.1/24"},
		}, []api.Member{}),
		asa.NewASAPort("dmz", "default", map[network.IPFamily][]string{
			network.IPv4: {"172.16.1.1/24"},
		}, []api.Member{}),
	}

	// 配置端口
	ports[0].WithZone("OUTSIDE").WithLevel("0").WithInAcl("OUTSIDE_IN").WithID("port1-id").WithNode(asaNode)
	ports[1].WithZone("INSIDE").WithLevel("100").WithInAcl("INSIDE_IN").WithID("port2-id").WithNode(asaNode)
	ports[2].WithZone("DMZ").WithLevel("50").WithInAcl("DMZ_IN").WithID("port3-id").WithNode(asaNode)

	// 创建 PortIterator
	portMap := make(map[string]api.Port)
	for _, port := range ports {
		portMap[port.ID()] = port
	}
	simpleIterator := newSimplePortIterator(portMap)
	asaNode.WithPortIterator(simpleIterator)

	// 添加端口到节点
	for _, port := range ports {
		asaNode.AddPort(port, nil)
	}

	// 验证节点状态
	assert.Equal(t, 3, len(asaNode.PortList()), "应该有 3 个端口")

	// 验证每个端口
	portList := asaNode.PortList()
	zoneMap := make(map[string]string)
	for _, p := range portList {
		if asaPort, ok := p.(*asa.ASAPort); ok {
			zoneMap[asaPort.Name()] = asaPort.Zone()
		}
	}

	assert.Equal(t, "OUTSIDE", zoneMap["outside"], "outside 端口 Zone 应该匹配")
	assert.Equal(t, "INSIDE", zoneMap["inside"], "inside 端口 Zone 应该匹配")
	assert.Equal(t, "DMZ", zoneMap["dmz"], "dmz 端口 Zone 应该匹配")
}

// TestASANodeType 测试 ASA 节点设备类型
func TestASANodeType(t *testing.T) {
	asaNode := newTestASANode()

	// 验证设备类型
	deviceType := asaNode.Type()
	assert.NotNil(t, deviceType, "设备类型应该存在")
}

// TestASAPortWithNode 测试 ASA 端口与节点关联
func TestASAPortWithNode(t *testing.T) {
	asaNode := newTestASANode()

	ipList := map[network.IPFamily][]string{
		network.IPv4: {"192.168.1.1/24"},
	}

	port := asa.NewASAPort("outside", "default", ipList, []api.Member{})

	// 关联端口到节点
	port.WithNode(asaNode)

	// 验证关联
	assert.Equal(t, asaNode, port.Node(), "端口应该关联到节点")
}

// TestASANodePortIterator 测试 ASA 节点端口迭代器
func TestASANodePortIterator(t *testing.T) {
	asaNode := newTestASANode()

	// 创建端口
	port1 := asa.NewASAPort("outside", "default", map[network.IPFamily][]string{
		network.IPv4: {"203.0.113.1/24"},
	}, []api.Member{})
	port1.WithID("port1-id")
	port1.WithNode(asaNode)

	port2 := asa.NewASAPort("inside", "default", map[network.IPFamily][]string{
		network.IPv4: {"192.168.1.1/24"},
	}, []api.Member{})
	port2.WithID("port2-id")
	port2.WithNode(asaNode)

	// 创建 PortIterator
	simpleIterator := newSimplePortIterator(map[string]api.Port{
		"port1-id": port1,
		"port2-id": port2,
	})
	asaNode.WithPortIterator(simpleIterator)

	// 添加端口
	asaNode.AddPort(port1, nil)
	asaNode.AddPort(port2, nil)

	// 验证端口列表
	ports := asaNode.PortList()
	require.Len(t, ports, 2, "应该有 2 个端口")

	// 验证可以通过 ID 获取端口
	foundPort1 := asaNode.GetPortByID("port1-id")
	require.NotNil(t, foundPort1, "应该找到 port1")
	assert.Equal(t, "outside", foundPort1.Name(), "端口名称应该匹配")

	foundPort2 := asaNode.GetPortByID("port2-id")
	require.NotNil(t, foundPort2, "应该找到 port2")
	assert.Equal(t, "inside", foundPort2.Name(), "端口名称应该匹配")
}

// ========== NodeMap 集成测试 ==========

// TestASANodeAddToNodeMap 测试将 ASA 节点添加到 NodeMap
func TestASANodeAddToNodeMap(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	// 创建 ASA 节点
	asaNode := newTestASANode()
	asaNode.WithName("asa-firewall")

	// 创建端口
	port1 := asa.NewASAPort("outside", "default", map[network.IPFamily][]string{
		network.IPv4: {"203.0.113.1/24"},
	}, []api.Member{})
	port1.WithVrf("default")
	port1.WithID("port1-id")
	port1.WithNode(asaNode)

	port2 := asa.NewASAPort("inside", "default", map[network.IPFamily][]string{
		network.IPv4: {"192.168.1.1/24"},
	}, []api.Member{})
	port2.WithVrf("default")
	port2.WithID("port2-id")
	port2.WithNode(asaNode)

	// 将端口添加到 NodeMap 的全局端口列表
	nm.Ports = append(nm.Ports, port1, port2)

	// 添加端口到节点
	asaNode.AddPort(port1, nil)
	asaNode.AddPort(port2, nil)

	// 设置 PortIterator
	asaNode.WithPortIterator(nm)

	// 将节点添加到 NodeMap
	nm.AddNode(asaNode, nil)

	// 确保节点有 PortIterator（AddNode 可能会重置）
	asaNode.WithPortIterator(nm)

	// 验证节点已添加到 NodeMap
	require.Len(t, nm.Nodes, 1, "NodeMap 应该包含 1 个节点")
	assert.Equal(t, "asa-firewall", nm.Nodes[0].Name(), "节点名称应该匹配")

	// 验证节点可以通过名称获取
	retrievedNode := nm.GetNode("asa-firewall")
	require.NotNil(t, retrievedNode, "应该找到节点")
	assert.Equal(t, "asa-firewall", retrievedNode.Name(), "节点名称应该匹配")
}

// TestASANodeConnectorIntegration 测试 ASA 节点与 Connector 的集成
func TestASANodeConnectorIntegration(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	// 创建 ASA 节点
	asaNode := newTestASANode()
	asaNode.WithName("asa-firewall")

	// 创建端口
	port1 := asa.NewASAPort("outside", "default", map[network.IPFamily][]string{
		network.IPv4: {"203.0.113.1/24"},
	}, []api.Member{})
	port1.WithVrf("default")
	port1.WithID("port1-id")
	port1.WithNode(asaNode)

	// 将端口添加到 NodeMap 的全局端口列表
	nm.Ports = append(nm.Ports, port1)

	// 添加端口到节点
	asaNode.AddPort(port1, nil)

	// 设置 PortIterator
	asaNode.WithPortIterator(nm)

	// 将节点添加到 NodeMap（会自动创建 Connector）
	nm.AddNode(asaNode, nil)
	asaNode.WithPortIterator(nm)

	// 验证 Connector 已创建
	connectors := nm.CxMananger.ConnectorList
	require.Greater(t, len(connectors), 0, "应该至少创建一个 Connector")

	// 验证端口已附加到 Connector
	connector := nm.CxMananger.GetConnectorByIp("203.0.113.1/24", "default")
	require.NotNil(t, connector, "应该找到 Connector")
	connector.WithPortIterator(nm)

	ports := connector.PortList()
	require.Len(t, ports, 1, "Connector 应该包含 1 个端口")
	assert.Equal(t, "outside", ports[0].Name(), "端口名称应该匹配")

	// 验证端口的 ConnectorID 已设置
	assert.Equal(t, connector.ID(), port1.ConnectorID(), "端口的 ConnectorID 应该匹配")
}

// TestASANodeSelectPortListByNetwork 测试通过 NodeMap 根据网络选择端口
func TestASANodeSelectPortListByNetwork(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	// 创建 ASA 节点
	asaNode := newTestASANode()
	asaNode.WithName("asa-firewall")

	// 创建端口
	port1 := asa.NewASAPort("outside", "default", map[network.IPFamily][]string{
		network.IPv4: {"203.0.113.1/24"},
	}, []api.Member{})
	port1.WithVrf("default")
	port1.WithID("port1-id")
	port1.WithNode(asaNode)

	port2 := asa.NewASAPort("inside", "default", map[network.IPFamily][]string{
		network.IPv4: {"192.168.1.1/24"},
	}, []api.Member{})
	port2.WithVrf("default")
	port2.WithID("port2-id")
	port2.WithNode(asaNode)

	// 将端口添加到 NodeMap 的全局端口列表
	nm.Ports = append(nm.Ports, port1, port2)

	// 添加端口到节点
	asaNode.AddPort(port1, nil)
	asaNode.AddPort(port2, nil)

	// 设置 PortIterator
	asaNode.WithPortIterator(nm)

	// 将节点添加到 NodeMap
	nm.AddNode(asaNode, nil)
	asaNode.WithPortIterator(nm)

	// 测试通过网络选择端口
	net1, err := network.NewNetworkFromString("203.0.113.10/32")
	require.NoError(t, err)

	ports1 := nm.SelectPortListByNetwork(net1, "default")
	require.Len(t, ports1, 1, "应该找到 1 个端口")
	assert.Equal(t, "outside", ports1[0].Name(), "应该匹配 outside 端口")

	net2, err := network.NewNetworkFromString("192.168.1.10/32")
	require.NoError(t, err)

	ports2 := nm.SelectPortListByNetwork(net2, "default")
	require.Len(t, ports2, 1, "应该找到 1 个端口")
	assert.Equal(t, "inside", ports2[0].Name(), "应该匹配 inside 端口")
}

// TestASANodeLocateNode 测试通过 NodeMap 定位 ASA 节点
func TestASANodeLocateNode(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	// 创建 ASA 节点
	asaNode := newTestASANode()
	asaNode.WithName("asa-firewall")

	// 创建端口
	port1 := asa.NewASAPort("outside", "default", map[network.IPFamily][]string{
		network.IPv4: {"203.0.113.1/24"},
	}, []api.Member{})
	port1.WithVrf("default")
	port1.WithID("port1-id")
	port1.WithNode(asaNode)

	// 将端口添加到 NodeMap 的全局端口列表
	nm.Ports = append(nm.Ports, port1)

	// 添加端口到节点
	asaNode.AddPort(port1, nil)

	// 设置 PortIterator
	asaNode.WithPortIterator(nm)

	// 将节点添加到 NodeMap
	nm.AddNode(asaNode, nil)
	asaNode.WithPortIterator(nm)

	// 测试通过网络定位节点（不再使用 AddressList）
	srcNetList := fixtures.NewTestIPv4NetworkList("203.0.113.10")
	ok, node, portName := nm.Locator().Locate(srcNetList, nil, "", "default", "", "")

	require.True(t, ok, "应该定位到节点")
	require.NotNil(t, node, "节点不应为 nil")
	assert.Equal(t, "asa-firewall", node.Name(), "节点名称应该匹配")
	assert.Equal(t, "outside", portName, "端口名称应该匹配")
}

// TestASANodeMultipleNodes 测试多个 ASA 节点在 NodeMap 中的交互
func TestASANodeMultipleNodes(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	// 创建第一个 ASA 节点
	asaNode1 := newTestASANode()
	asaNode1.WithName("asa-firewall-1")

	port1 := asa.NewASAPort("outside", "default", map[network.IPFamily][]string{
		network.IPv4: {"203.0.113.1/24"},
	}, []api.Member{})
	port1.WithVrf("default")
	port1.WithID("port1-id")
	port1.WithNode(asaNode1)

	nm.Ports = append(nm.Ports, port1)
	asaNode1.AddPort(port1, nil)
	asaNode1.WithPortIterator(nm)
	nm.AddNode(asaNode1, nil)
	asaNode1.WithPortIterator(nm)

	// 创建第二个 ASA 节点
	asaNode2 := newTestASANode()
	asaNode2.WithName("asa-firewall-2")

	port2 := asa.NewASAPort("inside", "default", map[network.IPFamily][]string{
		network.IPv4: {"192.168.1.1/24"},
	}, []api.Member{})
	port2.WithVrf("default")
	port2.WithID("port2-id")
	port2.WithNode(asaNode2)

	nm.Ports = append(nm.Ports, port2)
	asaNode2.AddPort(port2, nil)
	asaNode2.WithPortIterator(nm)
	nm.AddNode(asaNode2, nil)
	asaNode2.WithPortIterator(nm)

	// 验证两个节点都已添加
	require.Len(t, nm.Nodes, 2, "NodeMap 应该包含 2 个节点")

	// 验证可以通过名称获取节点
	node1 := nm.GetNode("asa-firewall-1")
	require.NotNil(t, node1, "应该找到第一个节点")

	node2 := nm.GetNode("asa-firewall-2")
	require.NotNil(t, node2, "应该找到第二个节点")

	// 验证每个节点都有独立的 Connector
	connector1 := nm.CxMananger.GetConnectorByIp("203.0.113.1/24", "default")
	require.NotNil(t, connector1, "应该找到第一个节点的 Connector")
	connector1.WithPortIterator(nm)

	connector2 := nm.CxMananger.GetConnectorByIp("192.168.1.1/24", "default")
	require.NotNil(t, connector2, "应该找到第二个节点的 Connector")
	connector2.WithPortIterator(nm)

	// 验证 Connector 不同（因为 IP 不同）
	assert.NotEqual(t, connector1.ID(), connector2.ID(), "两个 Connector 应该不同")
}

// TestASANodeWithRouterNode 测试 ASA 节点与路由器节点的交互
func TestASANodeWithRouterNode(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	// 创建路由器节点
	routerNode := fixtures.NewTestNode("router1", api.ROUTER)

	routerPort := fixtures.NewTestPort("eth0", "default", map[network.IPFamily][]string{
		network.IPv4: {"10.0.0.1/24"},
	})
	routerPort.WithVrf("default")
	routerPort.WithID("router-port-id")
	routerPort.WithNode(routerNode)

	nm.Ports = append(nm.Ports, routerPort)
	routerNode.AddPort(routerPort, nil)
	routerNode.WithPortIterator(nm)
	nm.AddNode(routerNode, nil)
	routerNode.WithPortIterator(nm)

	// 创建 ASA 节点
	asaNode := newTestASANode()
	asaNode.WithName("asa-firewall")

	asaPort := asa.NewASAPort("outside", "default", map[network.IPFamily][]string{
		network.IPv4: {"203.0.113.1/24"},
	}, []api.Member{})
	asaPort.WithVrf("default")
	asaPort.WithID("asa-port-id")
	asaPort.WithNode(asaNode)

	nm.Ports = append(nm.Ports, asaPort)
	asaNode.AddPort(asaPort, nil)
	asaNode.WithPortIterator(nm)
	nm.AddNode(asaNode, nil)
	asaNode.WithPortIterator(nm)

	// 验证两个节点都已添加
	require.Len(t, nm.Nodes, 2, "NodeMap 应该包含 2 个节点")

	// 验证节点类型
	assert.Equal(t, api.ROUTER, routerNode.NodeType(), "路由器节点类型应该匹配")
	assert.Equal(t, api.FIREWALL, asaNode.NodeType(), "ASA 节点类型应该匹配")

	// 验证可以通过网络查找端口
	net1, _ := network.NewNetworkFromString("10.0.0.10/32")
	ports1 := nm.SelectPortListByNetwork(net1, "default")
	require.Len(t, ports1, 1, "应该找到路由器端口")
	assert.Equal(t, "eth0", ports1[0].Name(), "应该匹配路由器端口")

	net2, _ := network.NewNetworkFromString("203.0.113.10/32")
	ports2 := nm.SelectPortListByNetwork(net2, "default")
	require.Len(t, ports2, 1, "应该找到 ASA 端口")
	assert.Equal(t, "outside", ports2[0].Name(), "应该匹配 ASA 端口")
}

// TestASANodeConnectorByNetwork 测试通过 NodeMap 根据网络获取 Connector
func TestASANodeConnectorByNetwork(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	// 创建 ASA 节点
	asaNode := newTestASANode()
	asaNode.WithName("asa-firewall")

	// 创建端口
	port1 := asa.NewASAPort("outside", "default", map[network.IPFamily][]string{
		network.IPv4: {"203.0.113.1/24"},
	}, []api.Member{})
	port1.WithVrf("default")
	port1.WithID("port1-id")
	port1.WithNode(asaNode)

	nm.Ports = append(nm.Ports, port1)
	asaNode.AddPort(port1, nil)
	asaNode.WithPortIterator(nm)
	nm.AddNode(asaNode, nil)
	asaNode.WithPortIterator(nm)

	// 通过网络获取 Connector
	net, err := network.NewNetworkFromString("203.0.113.10/32")
	require.NoError(t, err)

	connector := nm.CxMananger.GetConnectorByNetwork(net, "default")
	require.NotNil(t, connector, "应该找到 Connector")
	connector.WithPortIterator(nm)

	// 验证 Connector 包含正确的端口
	ports := connector.PortList()
	require.Len(t, ports, 1, "Connector 应该包含 1 个端口")
	assert.Equal(t, "outside", ports[0].Name(), "端口名称应该匹配")
}

// TestASANodeConnectorByIp 测试通过 NodeMap 根据 IP 获取 Connector
func TestASANodeConnectorByIp(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	// 创建 ASA 节点
	asaNode := newTestASANode()
	asaNode.WithName("asa-firewall")

	// 创建端口
	port1 := asa.NewASAPort("outside", "default", map[network.IPFamily][]string{
		network.IPv4: {"203.0.113.1/24"},
	}, []api.Member{})
	port1.WithVrf("default")
	port1.WithID("port1-id")
	port1.WithNode(asaNode)

	nm.Ports = append(nm.Ports, port1)
	asaNode.AddPort(port1, nil)
	asaNode.WithPortIterator(nm)
	nm.AddNode(asaNode, nil)
	asaNode.WithPortIterator(nm)

	// 通过 IP 获取 Connector
	connector := nm.CxMananger.GetConnectorByIp("203.0.113.1/24", "default")
	require.NotNil(t, connector, "应该找到 Connector")
	connector.WithPortIterator(nm)

	// 验证 Connector 包含正确的端口
	ports := connector.PortList()
	require.Len(t, ports, 1, "Connector 应该包含 1 个端口")
	assert.Equal(t, "outside", ports[0].Name(), "端口名称应该匹配")
}

// TestASANodeZoneInNodeMap 测试 ASA 节点的 Zone 功能在 NodeMap 中的表现
func TestASANodeZoneInNodeMap(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	// 创建 ASA 节点
	asaNode := newTestASANode()
	asaNode.WithName("asa-firewall")

	// 创建多个 Zone 的端口
	port1 := asa.NewASAPort("outside", "default", map[network.IPFamily][]string{
		network.IPv4: {"203.0.113.1/24"},
	}, []api.Member{})
	port1.WithVrf("default")
	port1.WithZone("OUTSIDE")
	port1.WithLevel("0")
	port1.WithID("port1-id")
	port1.WithNode(asaNode)

	port2 := asa.NewASAPort("inside", "default", map[network.IPFamily][]string{
		network.IPv4: {"192.168.1.1/24"},
	}, []api.Member{})
	port2.WithVrf("default")
	port2.WithZone("INSIDE")
	port2.WithLevel("100")
	port2.WithID("port2-id")
	port2.WithNode(asaNode)

	nm.Ports = append(nm.Ports, port1, port2)
	asaNode.AddPort(port1, nil)
	asaNode.AddPort(port2, nil)
	asaNode.WithPortIterator(nm)
	nm.AddNode(asaNode, nil)
	asaNode.WithPortIterator(nm)

	// 验证端口列表
	ports := asaNode.PortList()
	require.Len(t, ports, 2, "应该有 2 个端口")

	// 验证 Zone 信息
	zoneMap := make(map[string]string)
	for _, p := range ports {
		if asaPort, ok := p.(*asa.ASAPort); ok {
			zoneMap[asaPort.Name()] = asaPort.Zone()
		}
	}

	assert.Equal(t, "OUTSIDE", zoneMap["outside"], "outside 端口 Zone 应该匹配")
	assert.Equal(t, "INSIDE", zoneMap["inside"], "inside 端口 Zone 应该匹配")
}

// TestASANodeComplexIntegration 测试 ASA 节点在 NodeMap 中的复杂集成场景
func TestASANodeComplexIntegration(t *testing.T) {
	nm := fixtures.NewTestNodeMap()

	// 创建 ASA 节点
	asaNode := newTestASANode()
	asaNode.WithName("asa-firewall")

	// 创建多个端口
	ports := []*asa.ASAPort{
		asa.NewASAPort("outside", "default", map[network.IPFamily][]string{
			network.IPv4: {"203.0.113.1/24"},
		}, []api.Member{}),
		asa.NewASAPort("inside", "default", map[network.IPFamily][]string{
			network.IPv4: {"192.168.1.1/24"},
		}, []api.Member{}),
		asa.NewASAPort("dmz", "default", map[network.IPFamily][]string{
			network.IPv4: {"172.16.1.1/24"},
		}, []api.Member{}),
	}

	// 配置端口
	ports[0].WithVrf("default")
	ports[0].WithZone("OUTSIDE")
	ports[0].WithLevel("0")
	ports[0].WithID("port1-id")
	ports[0].WithNode(asaNode)

	ports[1].WithVrf("default")
	ports[1].WithZone("INSIDE")
	ports[1].WithLevel("100")
	ports[1].WithID("port2-id")
	ports[1].WithNode(asaNode)

	ports[2].WithVrf("default")
	ports[2].WithZone("DMZ")
	ports[2].WithLevel("50")
	ports[2].WithID("port3-id")
	ports[2].WithNode(asaNode)

	// 将端口添加到 NodeMap
	for _, port := range ports {
		nm.Ports = append(nm.Ports, port)
		asaNode.AddPort(port, nil)
	}

	// 设置 PortIterator 并添加节点
	asaNode.WithPortIterator(nm)
	nm.AddNode(asaNode, nil)
	asaNode.WithPortIterator(nm)

	// 验证节点已添加
	require.Len(t, nm.Nodes, 1, "NodeMap 应该包含 1 个节点")

	// 验证端口列表
	nodePorts := asaNode.PortList()
	require.Len(t, nodePorts, 3, "应该有 3 个端口")

	// 验证每个端口都有对应的 Connector
	for _, port := range ports {
		connector := nm.CxMananger.GetConnectorByIp(port.GetIpList()[network.IPv4][0], "default")
		require.NotNil(t, connector, "应该找到端口 %s 的 Connector", port.Name())
		connector.WithPortIterator(nm)

		connectorPorts := connector.PortList()
		require.Greater(t, len(connectorPorts), 0, "Connector 应该包含端口")
	}

	// 验证可以通过网络查找端口
	testCases := []struct {
		network  string
		portName string
	}{
		{"203.0.113.10/32", "outside"},
		{"192.168.1.10/32", "inside"},
		{"172.16.1.10/32", "dmz"},
	}

	for _, tc := range testCases {
		net, err := network.NewNetworkFromString(tc.network)
		require.NoError(t, err)

		foundPorts := nm.SelectPortListByNetwork(net, "default")
		require.Greater(t, len(foundPorts), 0, "应该找到端口: %s", tc.network)

		found := false
		for _, p := range foundPorts {
			if p.Name() == tc.portName {
				found = true
				break
			}
		}
		assert.True(t, found, "应该找到端口 %s", tc.portName)
	}
}

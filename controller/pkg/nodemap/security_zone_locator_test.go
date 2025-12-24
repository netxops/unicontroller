package nodemap_test

import (
	"strings"
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/nodemap"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/api"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/config"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/node/device/firewall/asa"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/tests/fixtures"
	"github.com/netxops/utils/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// setupTestSecurityZoneLocator 创建测试用的 SecurityZoneLocator
func setupTestSecurityZoneLocator() (*nodemap.SecurityZoneLocator, *nodemap.NodeMap) {
	logger := zap.NewNop()
	nm := fixtures.NewTestNodeMap()
	locator := nodemap.NewSecurityZoneLocator(nm, logger)
	return locator, nm
}

// setupFirewallNodeWithSecurityZone 创建带 SecurityZoneInfo 的防火墙节点
// routes: key 是网络，value 是 ConfigZoneName（用于匹配接口的 Zone）
// 返回: node, securityZones, ports
func setupFirewallNodeWithSecurityZone(name, vrf string, routes map[string]string) (api.Node, []*config.SecurityZoneInfo, []api.Port) {
	node := fixtures.NewTestNode(name, api.FIREWALL)
	var securityZones []*config.SecurityZoneInfo
	var ports []api.Port

	// 为每个路由创建 SecurityZoneInfo 和对应的端口
	for netStr, configZoneName := range routes {
		zoneInfo := &config.SecurityZoneInfo{
			ConfigZoneName:  configZoneName,
			NodeName:        name,
			NetworkSegments: []string{netStr},
			Vrf:             vrf,
			Priority:        0,
		}
		securityZones = append(securityZones, zoneInfo)

		// 创建对应的端口，并设置 Zone
		portName := configZoneName // 使用 ConfigZoneName 作为端口名（简化测试）
		port := asa.NewASAPort(portName, vrf, map[network.IPFamily][]string{
			network.IPv4: {"192.168.1.1/24"},
		}, []api.Member{})
		port.WithZone(configZoneName)
		port.WithVrf(vrf) // 确保设置 VRF
		port.WithID(portName + "-id")
		port.WithNode(node)
		node.AddPort(port, nil)
		ports = append(ports, port)
	}

	return node, securityZones, ports
}

// addFirewallNodeToNodeMap 将防火墙节点添加到 NodeMap，并正确设置 PortIterator 和 SecurityZoneInfo
func addFirewallNodeToNodeMap(nm *nodemap.NodeMap, node api.Node, securityZones []*config.SecurityZoneInfo, ports []api.Port) {
	// 1. 先将端口添加到 NodeMap.Ports（PortIterator 需要通过这里查找端口）
	nm.Ports = append(nm.Ports, ports...)

	// 2. 设置 PortIterator（这样 PortList() 才能通过 portIterator.GetPort(ref) 找到端口）
	node.WithPortIterator(nm)

	// 3. 添加节点到 NodeMap
	nm.AddNode(node, nil)

	// 4. 再次设置 PortIterator（AddNode 可能会重置）
	node.WithPortIterator(nm)

	// 5. 添加 SecurityZoneInfo 到 NodeMap
	nm.Ipv4SecurityZones = append(nm.Ipv4SecurityZones, securityZones...)
}

// setupFirewallNodeWithDefaultRoute 创建带默认路由 SecurityZoneInfo 的防火墙节点
func setupFirewallNodeWithDefaultRoute(name, vrf, configZoneName string) (api.Node, []*config.SecurityZoneInfo, []api.Port) {
	node := fixtures.NewTestNode(name, api.FIREWALL)
	securityZones := []*config.SecurityZoneInfo{
		{
			ConfigZoneName:  configZoneName,
			NodeName:        name,
			NetworkSegments: []string{"0.0.0.0/0"}, // 默认路由
			Vrf:             vrf,
			Priority:        0,
		},
	}

	// 创建默认路由对应的端口
	defaultPort := asa.NewASAPort(configZoneName, vrf, map[network.IPFamily][]string{
		network.IPv4: {"192.168.1.1/24"},
	}, []api.Member{})
	defaultPort.WithZone(configZoneName)
	defaultPort.WithVrf(vrf) // 确保设置 VRF
	defaultPort.WithID(configZoneName + "-id")
	defaultPort.WithNode(node)
	node.AddPort(defaultPort, nil)

	return node, securityZones, []api.Port{defaultPort}
}

func TestSecurityZoneLocator_CanHandle(t *testing.T) {
	t.Run("有防火墙节点时应该返回true", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()
		nm.AddNode(fixtures.NewTestNode("fw1", api.FIREWALL), nil)
		req := &nodemap.LocateRequest{}
		assert.True(t, locator.CanHandle(req))
	})

	t.Run("没有防火墙节点时应该返回false", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()
		nm.AddNode(fixtures.NewTestNode("router1", api.ROUTER), nil)
		req := &nodemap.LocateRequest{}
		assert.False(t, locator.CanHandle(req))
	})

	t.Run("空NodeMap时应该返回false", func(t *testing.T) {
		locator, _ := setupTestSecurityZoneLocator() // 空 NodeMap
		req := &nodemap.LocateRequest{}
		assert.False(t, locator.CanHandle(req))
	})
}

func TestSecurityZoneLocator_Locate(t *testing.T) {
	t.Run("空源网络列表", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()
		node, zones, ports := setupFirewallNodeWithSecurityZone("fw1", "default", map[string]string{
			"192.168.1.0/24": "zone1",
		})
		addFirewallNodeToNodeMap(nm, node, zones, ports)

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList(), // 空列表
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		assert.False(t, ok)
		assert.Nil(t, matchedNode)
		assert.Contains(t, portName, "source network list is empty")
	})

	t.Run("源网络列表为nil", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()
		node, zones, ports := setupFirewallNodeWithSecurityZone("fw1", "default", map[string]string{
			"192.168.1.0/24": "zone1",
		})
		addFirewallNodeToNodeMap(nm, node, zones, ports)

		req := &nodemap.LocateRequest{
			SrcNetList: nil, // nil 列表
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		assert.False(t, ok)
		assert.Nil(t, matchedNode)
		assert.Contains(t, portName, "source network list is empty")
	})

	t.Run("单防火墙节点-匹配成功", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()

		// 创建防火墙节点，添加 SecurityZoneInfo: 192.168.1.0/24 -> zone1
		node, zones, ports := setupFirewallNodeWithSecurityZone("fw1", "default", map[string]string{
			"192.168.1.0/24": "zone1",
		})
		addFirewallNodeToNodeMap(nm, node, zones, ports)

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("192.168.1.10"),
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		require.True(t, ok, "应该匹配成功")
		assert.NotNil(t, matchedNode)
		assert.Equal(t, "fw1", matchedNode.Name())
		assert.Equal(t, "zone1", portName)
	})

	t.Run("单防火墙节点-最长匹配", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()

		// 创建防火墙节点，添加多个 SecurityZoneInfo（测试最长匹配）
		node, zones, ports := setupFirewallNodeWithSecurityZone("fw1", "default", map[string]string{
			"192.168.0.0/16": "zone0", // 更宽的路由
			"192.168.1.0/24": "zone1", // 更精确的路由（应该匹配这个）
		})
		addFirewallNodeToNodeMap(nm, node, zones, ports)

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("192.168.1.10"),
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		assert.True(t, ok, "应该匹配成功")
		require.NotNil(t, matchedNode)
		assert.Equal(t, "fw1", matchedNode.Name())
		assert.Equal(t, "zone1", portName) // 应该匹配到更具体的 zone1
	})

	t.Run("单防火墙节点-无匹配-使用默认路由", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()

		// 创建防火墙节点，只有默认路由
		node, zones, ports := setupFirewallNodeWithDefaultRoute("fw1", "default", "default_zone")
		addFirewallNodeToNodeMap(nm, node, zones, ports)

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("10.0.0.1"), // 不在任何具体路由中
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		assert.True(t, ok, "应该通过默认路由匹配成功")
		require.NotNil(t, matchedNode)
		assert.Equal(t, "fw1", matchedNode.Name())
		assert.Equal(t, "default_zone", portName)
	})

	t.Run("单防火墙节点-无匹配-无默认路由", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()

		// 创建防火墙节点，没有 SecurityZoneInfo（空列表）
		node := fixtures.NewTestNode("fw1", api.FIREWALL)
		nm.AddNode(node, nil)
		// 不添加任何 SecurityZoneInfo

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("10.0.0.1"),
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		assert.False(t, ok, "应该匹配失败")
		assert.Nil(t, matchedNode)
		assert.Contains(t, portName, "no security zones configured")
	})

	t.Run("单防火墙节点-非防火墙节点-不能使用默认路由", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()

		// 创建非防火墙节点
		node := fixtures.NewTestNode("router1", api.ROUTER)
		nm.AddNode(node, nil)

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("10.0.0.1"),
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		assert.False(t, ok, "非防火墙节点不能使用默认路由")
		assert.Nil(t, matchedNode)
		assert.Contains(t, portName, "is not a firewall")
	})

	t.Run("多防火墙节点-只有一个匹配", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()

		// 创建两个防火墙节点
		fw1, zones1, ports1 := setupFirewallNodeWithSecurityZone("fw1", "default", map[string]string{
			"192.168.1.0/24": "zone1",
		})
		fw2, zones2, ports2 := setupFirewallNodeWithSecurityZone("fw2", "default", map[string]string{
			"10.0.0.0/8": "zone2",
		})
		addFirewallNodeToNodeMap(nm, fw1, zones1, ports1)
		addFirewallNodeToNodeMap(nm, fw2, zones2, ports2)

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("192.168.1.10"),
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		assert.True(t, ok, "应该匹配成功")
		require.NotNil(t, matchedNode)
		assert.Equal(t, "fw1", matchedNode.Name())
		assert.Equal(t, "zone1", portName)
	})

	t.Run("多防火墙节点-多个匹配-路由分歧", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()

		// 创建两个防火墙节点，都有相同的 SecurityZoneInfo（会导致路由分歧）
		fw1, zones1, ports1 := setupFirewallNodeWithSecurityZone("fw1", "default", map[string]string{
			"192.168.1.0/24": "zone1",
		})
		fw2, zones2, ports2 := setupFirewallNodeWithSecurityZone("fw2", "default", map[string]string{
			"192.168.1.0/24": "zone2",
		})
		addFirewallNodeToNodeMap(nm, fw1, zones1, ports1)
		addFirewallNodeToNodeMap(nm, fw2, zones2, ports2)

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("192.168.1.10"),
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		assert.False(t, ok, "路由分歧时应该返回失败")
		assert.Nil(t, matchedNode)
		// 路由分歧时，locate 方法会返回 "route divergence"，但 Locate 方法可能会返回其他消息
		assert.True(t,
			containsAny(portName, []string{"route divergence", "multiple different nodes/zones matched"}),
			"错误消息应该包含路由分歧相关信息，实际: %s", portName)
	})

	t.Run("多防火墙节点-无匹配-不能使用默认路由", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()

		// 创建两个防火墙节点，都有具体的 SecurityZoneInfo（没有默认路由）
		fw1, zones1, ports1 := setupFirewallNodeWithSecurityZone("fw1", "default", map[string]string{
			"192.168.1.0/24": "zone1",
		})
		fw2, zones2, ports2 := setupFirewallNodeWithSecurityZone("fw2", "default", map[string]string{
			"10.0.0.0/8": "zone2",
		})
		addFirewallNodeToNodeMap(nm, fw1, zones1, ports1)
		addFirewallNodeToNodeMap(nm, fw2, zones2, ports2)

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("172.16.0.1"), // 不在任何 SecurityZoneInfo 中
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		assert.False(t, ok, "无匹配且多防火墙时不能使用默认路由")
		assert.Nil(t, matchedNode)
		assert.Contains(t, portName, "no match found via longest prefix match")
	})

	t.Run("排除默认路由-只匹配具体路由", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()

		// 创建防火墙节点，同时有具体 SecurityZoneInfo 和默认路由 SecurityZoneInfo
		node, zones, ports := setupFirewallNodeWithSecurityZone("fw1", "default", map[string]string{
			"192.168.1.0/24": "zone1", // 具体路由
		})
		// 添加默认路由 SecurityZoneInfo
		defaultZone := &config.SecurityZoneInfo{
			ConfigZoneName:  "default_zone",
			NodeName:        "fw1",
			NetworkSegments: []string{"0.0.0.0/0"},
			Vrf:             "default",
			Priority:        0,
		}
		zones = append(zones, defaultZone)
		// 创建默认路由对应的端口
		defaultPort := asa.NewASAPort("default_zone", "default", map[network.IPFamily][]string{
			network.IPv4: {"192.168.1.1/24"},
		}, []api.Member{})
		defaultPort.WithZone("default_zone")
		defaultPort.WithVrf("default") // 确保设置 VRF
		defaultPort.WithID("default_zone-id")
		defaultPort.WithNode(node)
		node.AddPort(defaultPort, nil)
		ports = append(ports, defaultPort)

		addFirewallNodeToNodeMap(nm, node, zones, ports)

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("192.168.1.10"),
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		require.True(t, ok, "应该匹配成功")
		assert.NotNil(t, matchedNode)
		assert.Equal(t, "fw1", matchedNode.Name())
		// 应该匹配到具体路由的接口，而不是默认路由
		assert.Equal(t, "zone1", portName)
	})

	t.Run("VRF匹配", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()

		// 创建防火墙节点，指定 VRF
		node, zones, ports := setupFirewallNodeWithSecurityZone("fw1", "vrf1", map[string]string{
			"192.168.1.0/24": "zone1",
		})
		addFirewallNodeToNodeMap(nm, node, zones, ports)

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("192.168.1.10"),
			DstNetList: nil,
			Vrf:        "vrf1", // 匹配的 VRF
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		assert.True(t, ok, "应该匹配成功")
		require.NotNil(t, matchedNode)
		assert.Equal(t, "fw1", matchedNode.Name())
		assert.Equal(t, "zone1", portName)
	})

	t.Run("VRF不匹配", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()

		// 创建防火墙节点，指定 VRF
		node, zones, ports := setupFirewallNodeWithSecurityZone("fw1", "vrf1", map[string]string{
			"192.168.1.0/24": "zone1",
		})
		addFirewallNodeToNodeMap(nm, node, zones, ports)

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("192.168.1.10"),
			DstNetList: nil,
			Vrf:        "vrf2", // 不匹配的 VRF
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		assert.False(t, ok, "VRF 不匹配应该失败")
		assert.Nil(t, matchedNode)
		// VRF 不匹配时，可能返回 "no valid routes found" 或 "no default route zone found"
		assert.True(t,
			containsAny(portName, []string{"no valid routes found", "no default route zone found", "VRF"}),
			"错误消息应该包含 VRF 不匹配相关信息，实际: %s", portName)
	})

	t.Run("节点未找到", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()

		// 创建 SecurityZoneInfo，但节点不存在于 NodeMap
		zoneInfo := &config.SecurityZoneInfo{
			ConfigZoneName:  "zone1",
			NodeName:        "nonexistent",
			NetworkSegments: []string{"192.168.1.0/24"},
			Vrf:             "default",
			Priority:        0,
		}
		nm.Ipv4SecurityZones = append(nm.Ipv4SecurityZones, zoneInfo)

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("192.168.1.10"),
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		assert.False(t, ok, "节点不存在应该失败")
		assert.Nil(t, matchedNode)
		// 节点未找到时，可能返回 "not found in NodeMap" 或 "NodeMap has no nodes"
		assert.True(t,
			containsAny(portName, []string{"not found in NodeMap", "NodeMap has no nodes", "nonexistent"}),
			"错误消息应该包含节点未找到相关信息，实际: %s", portName)
	})

	t.Run("端口未找到-ConfigZoneName不匹配", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()

		// 创建防火墙节点，但端口的 Zone 与 ConfigZoneName 不匹配
		node := fixtures.NewTestNode("fw1", api.FIREWALL)
		port := asa.NewASAPort("port1", "default", map[network.IPFamily][]string{
			network.IPv4: {"192.168.1.1/24"},
		}, []api.Member{})
		port.WithZone("different_zone") // Zone 与 ConfigZoneName 不匹配
		port.WithVrf("default")         // 确保设置 VRF
		port.WithID("port1-id")
		port.WithNode(node)
		node.AddPort(port, nil)

		zoneInfo := &config.SecurityZoneInfo{
			ConfigZoneName:  "zone1", // ConfigZoneName 与端口的 Zone 不匹配
			NodeName:        "fw1",
			NetworkSegments: []string{"192.168.1.0/24"},
			Vrf:             "default",
			Priority:        0,
		}

		addFirewallNodeToNodeMap(nm, node, []*config.SecurityZoneInfo{zoneInfo}, []api.Port{port})

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("192.168.1.10"),
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		assert.False(t, ok, "端口 Zone 不匹配应该失败")
		assert.Nil(t, matchedNode)
		// 端口未找到时，可能返回 "no firewall port found" 或 "no default route zone found"
		assert.True(t,
			containsAny(portName, []string{"no firewall port found", "no default route zone found", "Zone()"}),
			"错误消息应该包含端口未找到相关信息，实际: %s", portName)
	})

	t.Run("NodeMap为nil", func(t *testing.T) {
		locator, _ := setupTestSecurityZoneLocator()

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("192.168.1.10"),
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nil, // NodeMap 为 nil
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		assert.False(t, ok, "NodeMap 为 nil 应该失败")
		assert.Nil(t, matchedNode)
		// NodeMap 为 nil 时，可能返回 "NodeMap is nil" 或 "NodeMap has no nodes"
		assert.True(t,
			containsAny(portName, []string{"NodeMap is nil", "NodeMap has no nodes"}),
			"错误消息应该包含 NodeMap 相关信息，实际: %s", portName)
	})

	t.Run("无SecurityZone配置", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()

		// 创建防火墙节点，但不添加 SecurityZoneInfo
		node := fixtures.NewTestNode("fw1", api.FIREWALL)
		nm.AddNode(node, nil)

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("192.168.1.10"),
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		assert.False(t, ok, "无 SecurityZone 配置应该失败")
		assert.Nil(t, matchedNode)
		assert.Contains(t, portName, "no security zones configured")
	})

	t.Run("只有默认路由-无有效路由", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()

		// 创建防火墙节点，只有默认路由（在最长匹配阶段会被跳过）
		node, zones, ports := setupFirewallNodeWithDefaultRoute("fw1", "default", "default_zone")
		addFirewallNodeToNodeMap(nm, node, zones, ports)

		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("10.0.0.1"),
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		// 应该通过默认路由匹配成功（单防火墙节点）
		assert.True(t, ok, "应该通过默认路由匹配成功")
		require.NotNil(t, matchedNode)
		assert.Equal(t, "fw1", matchedNode.Name())
		assert.Equal(t, "default_zone", portName)
	})

	t.Run("部分网络未匹配-应该跳过", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()

		// 创建防火墙节点，只有部分网络的 SecurityZoneInfo
		node, zones, ports := setupFirewallNodeWithSecurityZone("fw1", "default", map[string]string{
			"192.168.1.0/24": "zone1",
		})
		addFirewallNodeToNodeMap(nm, node, zones, ports)

		// 请求包含多个网络，其中一个不在 SecurityZoneInfo 中
		req := &nodemap.LocateRequest{
			SrcNetList: fixtures.NewTestIPv4NetworkList("192.168.1.10", "10.0.0.1"), // 第二个不在 SecurityZoneInfo 中
			DstNetList: nil,
			Vrf:        "default",
			IPFamily:   network.IPv4,
			NodeMap:    nm,
			Logger:     zap.NewNop(),
		}

		ok, matchedNode, portName := locator.Locate(req)

		// 因为有未匹配的网络，应该失败（单防火墙时，如果没有默认路由也会失败）
		assert.False(t, ok, "有未匹配的网络应该返回失败")
		assert.Nil(t, matchedNode)
		assert.Contains(t, portName, "no match found")
	})
}

// 注意：getFirewallNodes 是未导出的方法，通过 CanHandle 间接测试
func TestSecurityZoneLocator_getFirewallNodes_Indirect(t *testing.T) {
	t.Run("通过CanHandle测试防火墙节点检测", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()
		nm.AddNode(fixtures.NewTestNode("fw1", api.FIREWALL), nil)
		nm.AddNode(fixtures.NewTestNode("router1", api.ROUTER), nil)
		nm.AddNode(fixtures.NewTestNode("fw2", api.FIREWALL), nil)

		req := &nodemap.LocateRequest{}
		assert.True(t, locator.CanHandle(req), "有防火墙节点时 CanHandle 应该返回 true")
	})

	t.Run("通过CanHandle测试无防火墙节点", func(t *testing.T) {
		locator, nm := setupTestSecurityZoneLocator()
		nm.AddNode(fixtures.NewTestNode("router1", api.ROUTER), nil)
		nm.AddNode(fixtures.NewTestNode("lb1", api.LB), nil)

		req := &nodemap.LocateRequest{}
		assert.False(t, locator.CanHandle(req), "没有防火墙节点时 CanHandle 应该返回 false")
	})
}

// containsAny 检查字符串是否包含任意一个子字符串
func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

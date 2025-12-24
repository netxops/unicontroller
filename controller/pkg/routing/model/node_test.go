package model

import (
	"testing"

	"github.com/netxops/utils/network"
)

func TestRouteTable_AddRoute(t *testing.T) {
	// 创建路由表
	rt := NewRouteTable("default", network.IPv4)

	// 添加路由
	net, err := network.ParseIPNet("10.0.0.0/8")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop := &network.NextHop{}
	nextHop.AddHop("GigabitEthernet0/0", "192.168.1.1", false, false, nil)

	err = rt.AddRoute(net, nextHop)
	if err != nil {
		t.Fatalf("添加路由失败: %v", err)
	}

	// 验证路由表
	if rt.VRF != "default" {
		t.Errorf("期望VRF为default，实际为%s", rt.VRF)
	}

	if rt.IPFamily != network.IPv4 {
		t.Errorf("期望IPFamily为IPv4，实际为%v", rt.IPFamily)
	}
}

func TestRouteTable_QueryRoute(t *testing.T) {
	// 创建路由表
	rt := NewRouteTable("default", network.IPv4)

	// 添加路由
	net, err := network.ParseIPNet("10.0.0.0/8")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop := &network.NextHop{}
	nextHop.AddHop("GigabitEthernet0/0", "192.168.1.1", false, false, nil)

	err = rt.AddRoute(net, nextHop)
	if err != nil {
		t.Fatalf("添加路由失败: %v", err)
	}

	// 查询路由
	// Create NetworkList from a network string
	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建网络失败: %v", err)
	}
	// NetworkList() is a method on Network that returns NetworkList
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	rmr, err := rt.QueryRoute(*dst)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if rmr == nil {
		t.Fatal("路由匹配结果为空")
	}

	if rmr.Match == nil {
		t.Error("匹配结果为空")
	}
}

func TestNewRouteTableFromAddressTable(t *testing.T) {
	// 创建AddressTable
	at := network.NewAddressTable(network.IPv4)

	// 从AddressTable创建RouteTable
	rt := NewRouteTableFromAddressTable("default", network.IPv4, at)

	if rt == nil {
		t.Fatal("RouteTable为空")
	}

	if rt.VRF != "default" {
		t.Errorf("期望VRF为default，实际为%s", rt.VRF)
	}

	if rt.IPFamily != network.IPv4 {
		t.Errorf("期望IPFamily为IPv4，实际为%v", rt.IPFamily)
	}

	// 验证GetAddressTable
	at2 := rt.GetAddressTable()
	if at2 != at {
		t.Error("GetAddressTable返回的AddressTable不正确")
	}
}

// TestRouteTable_MultipleRoutes 测试多个路由
func TestRouteTable_MultipleRoutes(t *testing.T) {
	rt := NewRouteTable("default", network.IPv4)

	// 添加多个路由
	routes := []struct {
		network       string
		interfaceName string
		nextHop       string
	}{
		{"10.0.0.0/8", "GigabitEthernet0/0", "192.168.1.1"},
		{"172.16.0.0/12", "GigabitEthernet0/1", "192.168.2.1"},
		{"192.168.0.0/16", "GigabitEthernet0/2", "192.168.3.1"},
	}

	for _, route := range routes {
		net, err := network.ParseIPNet(route.network)
		if err != nil {
			t.Fatalf("解析网络失败 %s: %v", route.network, err)
		}

		nextHop := &network.NextHop{}
		nextHop.AddHop(route.interfaceName, route.nextHop, false, false, nil)

		err = rt.AddRoute(net, nextHop)
		if err != nil {
			t.Fatalf("添加路由失败 %s: %v", route.network, err)
		}
	}

	// 查询每个路由
	for _, route := range routes {
		// 从网络地址中提取一个IP进行查询
		net, _ := network.ParseIPNet(route.network)
		// 使用网络中的第一个IP
		dstNet, err := network.NewNetworkFromString(net.IP.String() + "/32")
		if err != nil {
			t.Fatalf("创建目标网络失败: %v", err)
		}

		dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
		if err != nil {
			t.Fatalf("创建网络列表失败: %v", err)
		}

		rmr, err := rt.QueryRoute(*dst)
		if err != nil {
			t.Fatalf("查询路由失败 %s: %v", route.network, err)
		}

		if rmr == nil || rmr.Match == nil {
			t.Errorf("路由 %s 应该匹配", route.network)
		}
	}
}

// TestRouteTable_IPv6 测试IPv6路由
func TestRouteTable_IPv6(t *testing.T) {
	rt := NewRouteTable("default", network.IPv6)

	// 添加IPv6路由
	net, err := network.ParseIPNet("2001:db8::/32")
	if err != nil {
		t.Fatalf("解析IPv6网络失败: %v", err)
	}

	nextHop := &network.NextHop{}
	nextHop.AddHop("GigabitEthernet0/0", "2001:db8::1", false, false, nil)

	err = rt.AddRoute(net, nextHop)
	if err != nil {
		t.Fatalf("添加IPv6路由失败: %v", err)
	}

	// 验证路由表
	if rt.IPFamily != network.IPv6 {
		t.Errorf("期望IPFamily为IPv6，实际为%v", rt.IPFamily)
	}

	// 查询IPv6路由
	dstNet, err := network.NewNetworkFromString("2001:db8::1/128")
	if err != nil {
		t.Fatalf("创建IPv6目标网络失败: %v", err)
	}

	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建IPv6网络列表失败: %v", err)
	}

	rmr, err := rt.QueryRoute(*dst)
	if err != nil {
		t.Fatalf("查询IPv6路由失败: %v", err)
	}

	if rmr == nil || rmr.Match == nil {
		t.Error("IPv6路由应该匹配")
	}
}

// TestRouteTable_DifferentVRF 测试不同VRF
func TestRouteTable_DifferentVRF(t *testing.T) {
	// 创建不同VRF的路由表
	vrf1 := NewRouteTable("vrf1", network.IPv4)
	vrf2 := NewRouteTable("vrf2", network.IPv4)

	// 为每个VRF添加相同的网络但不同的下一跳
	net, err := network.ParseIPNet("10.0.0.0/8")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop1 := &network.NextHop{}
	nextHop1.AddHop("GigabitEthernet0/0", "192.168.1.1", false, false, nil)
	err = vrf1.AddRoute(net, nextHop1)
	if err != nil {
		t.Fatalf("添加vrf1路由失败: %v", err)
	}

	nextHop2 := &network.NextHop{}
	nextHop2.AddHop("GigabitEthernet0/1", "192.168.2.1", false, false, nil)
	err = vrf2.AddRoute(net, nextHop2)
	if err != nil {
		t.Fatalf("添加vrf2路由失败: %v", err)
	}

	// 验证VRF不同
	if vrf1.VRF != "vrf1" {
		t.Errorf("期望VRF为vrf1，实际为%s", vrf1.VRF)
	}
	if vrf2.VRF != "vrf2" {
		t.Errorf("期望VRF为vrf2，实际为%s", vrf2.VRF)
	}

	// 验证路由表是独立的
	if vrf1.GetAddressTable() == vrf2.GetAddressTable() {
		t.Error("不同VRF的路由表应该是独立的")
	}
}

// TestRouteTable_RouteOverlap 测试路由覆盖（更具体的路由）
func TestRouteTable_RouteOverlap(t *testing.T) {
	rt := NewRouteTable("default", network.IPv4)

	// 先添加一个大的网络
	net1, err := network.ParseIPNet("10.0.0.0/8")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop1 := &network.NextHop{}
	nextHop1.AddHop("GigabitEthernet0/0", "192.168.1.1", false, false, nil)
	err = rt.AddRoute(net1, nextHop1)
	if err != nil {
		t.Fatalf("添加路由失败: %v", err)
	}

	// 再添加一个更具体的网络（子网）
	net2, err := network.ParseIPNet("10.1.0.0/16")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop2 := &network.NextHop{}
	nextHop2.AddHop("GigabitEthernet0/1", "192.168.2.1", false, false, nil)
	err = rt.AddRoute(net2, nextHop2)
	if err != nil {
		t.Fatalf("添加更具体的路由失败: %v", err)
	}

	// 查询子网中的IP，应该匹配到更具体的路由
	dstNet, err := network.NewNetworkFromString("10.1.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}

	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	rmr, err := rt.QueryRoute(*dst)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if rmr == nil || rmr.Match == nil {
		t.Error("应该匹配到路由")
	}
}

// TestRouteTable_NoMatch 测试未匹配的情况
func TestRouteTable_NoMatch(t *testing.T) {
	rt := NewRouteTable("default", network.IPv4)

	// 添加一个路由
	net, err := network.ParseIPNet("10.0.0.0/8")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop := &network.NextHop{}
	nextHop.AddHop("GigabitEthernet0/0", "192.168.1.1", false, false, nil)
	err = rt.AddRoute(net, nextHop)
	if err != nil {
		t.Fatalf("添加路由失败: %v", err)
	}

	// 查询不在路由表中的网络
	dstNet, err := network.NewNetworkFromString("20.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}

	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	rmr, err := rt.QueryRoute(*dst)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if rmr == nil {
		t.Fatal("路由匹配结果不应该为nil")
	}

	// 应该没有匹配或匹配为空
	// 如果Match为nil，说明没有匹配到路由（这是我们期望的）
	if rmr.Match != nil {
		t.Error("不应该匹配到路由（期望Match为nil）")
	}
}

// TestRouteTable_ConnectedRoute 测试直连路由
func TestRouteTable_ConnectedRoute(t *testing.T) {
	rt := NewRouteTable("default", network.IPv4)

	// 添加直连路由
	net, err := network.ParseIPNet("192.168.1.0/24")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop := &network.NextHop{}
	nextHop.AddHop("GigabitEthernet0/0", "192.168.1.1", true, false, nil) // connected = true

	err = rt.AddRoute(net, nextHop)
	if err != nil {
		t.Fatalf("添加直连路由失败: %v", err)
	}

	// 查询直连网络
	dstNet, err := network.NewNetworkFromString("192.168.1.10/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}

	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	rmr, err := rt.QueryRoute(*dst)
	if err != nil {
		t.Fatalf("查询直连路由失败: %v", err)
	}

	if rmr == nil || rmr.Match == nil {
		t.Error("直连路由应该匹配")
	}
}

// TestRouteTable_MultipleNextHops 测试多个下一跳（ECMP）
func TestRouteTable_MultipleNextHops(t *testing.T) {
	rt := NewRouteTable("default", network.IPv4)

	// 添加带多个下一跳的路由
	net, err := network.ParseIPNet("10.0.0.0/8")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop := &network.NextHop{}
	nextHop.AddHop("GigabitEthernet0/0", "192.168.1.1", false, false, nil)
	nextHop.AddHop("GigabitEthernet0/1", "192.168.1.2", false, false, nil)
	nextHop.AddHop("GigabitEthernet0/2", "192.168.1.3", false, false, nil)

	err = rt.AddRoute(net, nextHop)
	if err != nil {
		t.Fatalf("添加多下一跳路由失败: %v", err)
	}

	// 查询路由
	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}

	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	rmr, err := rt.QueryRoute(*dst)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if rmr == nil || rmr.Match == nil {
		t.Error("应该匹配到路由")
	}
}

// TestRouteTable_ComplexQuery 测试复杂查询（多个目标网络）
func TestRouteTable_ComplexQuery(t *testing.T) {
	rt := NewRouteTable("default", network.IPv4)

	// 添加多个路由
	routes := []struct {
		network       string
		interfaceName string
		nextHop       string
	}{
		{"10.0.0.0/8", "GigabitEthernet0/0", "192.168.1.1"},
		{"172.16.0.0/12", "GigabitEthernet0/1", "192.168.2.1"},
	}

	for _, route := range routes {
		net, err := network.ParseIPNet(route.network)
		if err != nil {
			t.Fatalf("解析网络失败 %s: %v", route.network, err)
		}

		nextHop := &network.NextHop{}
		nextHop.AddHop(route.interfaceName, route.nextHop, false, false, nil)
		err = rt.AddRoute(net, nextHop)
		if err != nil {
			t.Fatalf("添加路由失败 %s: %v", route.network, err)
		}
	}

	// 查询多个目标网络
	dstNets := []string{"10.0.0.1/32", "172.16.0.1/32"}
	var abbrNets []network.AbbrNet

	for _, dstStr := range dstNets {
		dstNet, err := network.NewNetworkFromString(dstStr)
		if err != nil {
			t.Fatalf("创建目标网络失败 %s: %v", dstStr, err)
		}
		abbrNets = append(abbrNets, dstNet)
	}

	dst, err := network.NewNetworkListFromList(abbrNets)
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	rmr, err := rt.QueryRoute(*dst)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if rmr == nil {
		t.Fatal("路由匹配结果不应该为空")
	}
}

package core

import (
	"testing"

	"github.com/influxdata/telegraf/controller/pkg/routing/model"
	"github.com/netxops/utils/network"
)

func TestRouteQuery_QueryRoute(t *testing.T) {
	// 创建路由表
	rt := model.NewRouteTable("default", network.IPv4)

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

	// 创建路由查询器
	rq := NewRouteQuery(rt)

	// 查询路由
	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq.QueryRoute(*dst, "GigabitEthernet0/1", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if result == nil {
		t.Fatal("路由结果为空")
	}

	if !result.Matched {
		t.Error("应该匹配到路由")
	}

	if len(result.NextHops) == 0 {
		t.Error("下一跳列表不应该为空")
	}

	if result.NextHops[0].Interface != "GigabitEthernet0/0" {
		t.Errorf("期望接口为GigabitEthernet0/0，实际为%s", result.NextHops[0].Interface)
	}

	if result.NextHops[0].NextHopIP != "192.168.1.1" {
		t.Errorf("期望下一跳IP为192.168.1.1，实际为%s", result.NextHops[0].NextHopIP)
	}
}

func TestRouteQuery_QueryRoute_ECMP(t *testing.T) {
	// 创建路由表
	rt := model.NewRouteTable("default", network.IPv4)

	// 添加ECMP路由
	net, err := network.ParseIPNet("10.0.0.0/8")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop := &network.NextHop{}
	nextHop.AddHop("GigabitEthernet0/0", "192.168.1.1", false, false, nil)
	nextHop.AddHop("GigabitEthernet0/1", "192.168.1.2", false, false, nil)

	err = rt.AddRoute(net, nextHop)
	if err != nil {
		t.Fatalf("添加路由失败: %v", err)
	}

	// 创建路由查询器
	rq := NewRouteQuery(rt)

	// 查询路由
	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq.QueryRoute(*dst, "GigabitEthernet0/2", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if result == nil {
		t.Fatal("路由结果为空")
	}

	if !result.Matched {
		t.Error("应该匹配到路由")
	}

	if !result.IsECMP {
		t.Error("应该识别为ECMP路由")
	}

	if len(result.NextHops) != 2 {
		t.Errorf("期望下一跳数量为2，实际为%d", len(result.NextHops))
	}
}

func TestRouteQuery_QueryRoute_Loop(t *testing.T) {
	// 创建路由表
	rt := model.NewRouteTable("default", network.IPv4)

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

	// 创建路由查询器
	rq := NewRouteQuery(rt)

	// 查询路由（输入端口和输出端口相同，应该检测到环路）
	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq.QueryRoute(*dst, "GigabitEthernet0/0", "default", network.IPv4)
	if err == nil {
		t.Error("应该检测到路由环路")
	}

	if result != nil && result.Matched {
		t.Error("不应该匹配到路由（环路）")
	}
}

func TestRouteQuery_QueryAllRoutes(t *testing.T) {
	// 创建路由表
	rt := model.NewRouteTable("default", network.IPv4)

	// 添加ECMP路由
	net, err := network.ParseIPNet("10.0.0.0/8")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop := &network.NextHop{}
	nextHop.AddHop("GigabitEthernet0/0", "192.168.1.1", false, false, nil)
	nextHop.AddHop("GigabitEthernet0/1", "192.168.1.2", false, false, nil)

	err = rt.AddRoute(net, nextHop)
	if err != nil {
		t.Fatalf("添加路由失败: %v", err)
	}

	// 创建路由查询器
	rq := NewRouteQuery(rt)

	// 查询所有路由
	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	results, err := rq.QueryAllRoutes(*dst, "GigabitEthernet0/2", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询所有路由失败: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("期望路由数量为2，实际为%d", len(results))
	}

	// 验证每个路由都是单一路径（不是ECMP）
	for i, result := range results {
		if result.IsECMP {
			t.Errorf("路由%d不应该标记为ECMP", i)
		}

		if len(result.NextHops) != 1 {
			t.Errorf("路由%d的下一跳数量应该为1，实际为%d", i, len(result.NextHops))
		}
	}
}

// TestRouteQuery_QueryRoute_NoRouteTable 测试空路由表
func TestRouteQuery_QueryRoute_NoRouteTable(t *testing.T) {
	rq := NewRouteQuery(nil)

	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq.QueryRoute(*dst, "GigabitEthernet0/1", "default", network.IPv4)
	if err == nil {
		t.Error("应该返回错误（路由表为空）")
	}

	if result != nil {
		t.Error("结果应该为nil")
	}
}

// TestRouteQuery_QueryRoute_NoMatch 测试未匹配的路由
func TestRouteQuery_QueryRoute_NoMatch(t *testing.T) {
	rt := model.NewRouteTable("default", network.IPv4)

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

	rq := NewRouteQuery(rt)

	// 查询不在路由表中的网络
	dstNet, err := network.NewNetworkFromString("20.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq.QueryRoute(*dst, "GigabitEthernet0/1", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if result == nil {
		t.Fatal("结果不应该为nil")
	}

	if result.Matched {
		t.Error("不应该匹配到路由")
	}
}

// TestRouteQuery_QueryRoute_Connected 测试直连路由
func TestRouteQuery_QueryRoute_Connected(t *testing.T) {
	rt := model.NewRouteTable("default", network.IPv4)

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

	rq := NewRouteQuery(rt)

	// 查询直连网络
	dstNet, err := network.NewNetworkFromString("192.168.1.10/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq.QueryRoute(*dst, "GigabitEthernet0/1", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询直连路由失败: %v", err)
	}

	if result == nil {
		t.Fatal("结果不应该为nil")
	}

	if !result.Matched {
		t.Error("应该匹配到路由")
	}

	if !result.IsConnected {
		t.Error("应该识别为直连路由")
	}

	if result.IsECMP {
		t.Error("直连路由不应该是ECMP")
	}
}

// TestRouteQuery_QueryRoute_MultipleECMP 测试多个ECMP下一跳
func TestRouteQuery_QueryRoute_MultipleECMP(t *testing.T) {
	rt := model.NewRouteTable("default", network.IPv4)

	// 添加带多个下一跳的路由
	net, err := network.ParseIPNet("10.0.0.0/8")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop := &network.NextHop{}
	nextHop.AddHop("GigabitEthernet0/0", "192.168.1.1", false, false, nil)
	nextHop.AddHop("GigabitEthernet0/1", "192.168.1.2", false, false, nil)
	nextHop.AddHop("GigabitEthernet0/2", "192.168.1.3", false, false, nil)
	nextHop.AddHop("GigabitEthernet0/3", "192.168.1.4", false, false, nil)

	err = rt.AddRoute(net, nextHop)
	if err != nil {
		t.Fatalf("添加多下一跳路由失败: %v", err)
	}

	rq := NewRouteQuery(rt)

	// 查询路由
	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq.QueryRoute(*dst, "GigabitEthernet0/4", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if result == nil {
		t.Fatal("结果不应该为nil")
	}

	if !result.Matched {
		t.Error("应该匹配到路由")
	}

	if !result.IsECMP {
		t.Error("应该识别为ECMP路由")
	}

	if len(result.NextHops) != 4 {
		t.Errorf("期望下一跳数量为4，实际为%d", len(result.NextHops))
	}

	if len(result.OutPorts) != 4 {
		t.Errorf("期望输出端口数量为4，实际为%d", len(result.OutPorts))
	}
}

// TestRouteQuery_QueryAllRoutes_SinglePath 测试单一路径查询所有路由
func TestRouteQuery_QueryAllRoutes_SinglePath(t *testing.T) {
	rt := model.NewRouteTable("default", network.IPv4)

	// 添加单一路径路由
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

	rq := NewRouteQuery(rt)

	// 查询所有路由
	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	results, err := rq.QueryAllRoutes(*dst, "GigabitEthernet0/1", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询所有路由失败: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("期望路由数量为1，实际为%d", len(results))
	}

	if results[0].IsECMP {
		t.Error("单一路径不应该标记为ECMP")
	}
}

// TestRouteQuery_QueryAllRoutes_NoMatch 测试未匹配时查询所有路由
func TestRouteQuery_QueryAllRoutes_NoMatch(t *testing.T) {
	rt := model.NewRouteTable("default", network.IPv4)

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

	rq := NewRouteQuery(rt)

	// 查询不在路由表中的网络
	dstNet, err := network.NewNetworkFromString("20.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	results, err := rq.QueryAllRoutes(*dst, "GigabitEthernet0/1", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询所有路由失败: %v", err)
	}
	if err != nil {
		t.Fatalf("查询所有路由失败: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("期望路由数量为0，实际为%d", len(results))
	}
}

// TestRouteQuery_QueryAllRoutes_MultipleECMP 测试多个ECMP路径查询所有路由
func TestRouteQuery_QueryAllRoutes_MultipleECMP(t *testing.T) {
	rt := model.NewRouteTable("default", network.IPv4)

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
		t.Fatalf("添加路由失败: %v", err)
	}

	rq := NewRouteQuery(rt)

	// 查询所有路由
	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	results, err := rq.QueryAllRoutes(*dst, "GigabitEthernet0/3", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询所有路由失败: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("期望路由数量为3，实际为%d", len(results))
	}

	// 验证每个路由都是单一路径
	for i, result := range results {
		if result.IsECMP {
			t.Errorf("路由%d不应该标记为ECMP", i)
		}

		if len(result.NextHops) != 1 {
			t.Errorf("路由%d的下一跳数量应该为1，实际为%d", i, len(result.NextHops))
		}

		if len(result.OutPorts) != 1 {
			t.Errorf("路由%d的输出端口数量应该为1，实际为%d", i, len(result.OutPorts))
		}
	}
}

// ========== 更详细的边界测试和错误场景测试 ==========

// TestRouteQuery_QueryRoute_EmptyTable 测试空路由表查询
func TestRouteQuery_QueryRoute_EmptyTable(t *testing.T) {
	rt := model.NewRouteTable("default", network.IPv4)
	rq := NewRouteQuery(rt)

	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq.QueryRoute(*dst, "GigabitEthernet0/1", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if result == nil {
		t.Fatal("结果不应该为nil")
	}

	if result.Matched {
		t.Error("空路由表不应该匹配到路由")
	}

	if len(result.NextHops) != 0 {
		t.Errorf("期望下一跳数量为0，实际为%d", len(result.NextHops))
	}
}

// TestRouteQuery_QueryRoute_MultipleVRF 测试不同VRF的路由查询
func TestRouteQuery_QueryRoute_MultipleVRF(t *testing.T) {
	// 创建不同VRF的路由表
	vrf1 := model.NewRouteTable("vrf1", network.IPv4)
	vrf2 := model.NewRouteTable("vrf2", network.IPv4)

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

	// 测试vrf1
	rq1 := NewRouteQuery(vrf1)
	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result1, err := rq1.QueryRoute(*dst, "GigabitEthernet0/2", "vrf1", network.IPv4)
	if err != nil {
		t.Fatalf("查询vrf1路由失败: %v", err)
	}

	if !result1.Matched {
		t.Error("vrf1应该匹配到路由")
	}

	if len(result1.NextHops) == 0 {
		t.Error("vrf1应该有下一跳")
	}

	// 测试vrf2
	rq2 := NewRouteQuery(vrf2)
	result2, err := rq2.QueryRoute(*dst, "GigabitEthernet0/2", "vrf2", network.IPv4)
	if err != nil {
		t.Fatalf("查询vrf2路由失败: %v", err)
	}

	if !result2.Matched {
		t.Error("vrf2应该匹配到路由")
	}

	// 验证两个VRF的下一跳不同
	if result1.NextHops[0].NextHopIP == result2.NextHops[0].NextHopIP {
		t.Error("不同VRF的下一跳应该不同")
	}
}

// TestRouteQuery_QueryRoute_IPv6 测试IPv6路由查询
func TestRouteQuery_QueryRoute_IPv6(t *testing.T) {
	rt := model.NewRouteTable("default", network.IPv6)

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

	rq := NewRouteQuery(rt)

	// 查询IPv6路由
	dstNet, err := network.NewNetworkFromString("2001:db8::1/128")
	if err != nil {
		t.Fatalf("创建IPv6目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建IPv6网络列表失败: %v", err)
	}

	result, err := rq.QueryRoute(*dst, "GigabitEthernet0/1", "default", network.IPv6)
	if err != nil {
		t.Fatalf("查询IPv6路由失败: %v", err)
	}

	if result == nil {
		t.Fatal("结果不应该为nil")
	}

	if !result.Matched {
		t.Error("应该匹配到IPv6路由")
	}

	if len(result.NextHops) == 0 {
		t.Error("应该有IPv6下一跳")
	}

	if result.NextHops[0].NextHopIP != "2001:db8::1" {
		t.Errorf("期望下一跳IP为2001:db8::1，实际为%s", result.NextHops[0].NextHopIP)
	}
}

// TestRouteQuery_QueryRoute_MixedConnected 测试混合直连和非直连路由
func TestRouteQuery_QueryRoute_MixedConnected(t *testing.T) {
	rt := model.NewRouteTable("default", network.IPv4)

	// 添加直连路由
	net1, err := network.ParseIPNet("192.168.1.0/24")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop1 := &network.NextHop{}
	nextHop1.AddHop("GigabitEthernet0/0", "192.168.1.1", true, false, nil) // connected = true
	err = rt.AddRoute(net1, nextHop1)
	if err != nil {
		t.Fatalf("添加直连路由失败: %v", err)
	}

	// 添加非直连路由
	net2, err := network.ParseIPNet("10.0.0.0/8")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop2 := &network.NextHop{}
	nextHop2.AddHop("GigabitEthernet0/1", "192.168.2.1", false, false, nil) // connected = false
	err = rt.AddRoute(net2, nextHop2)
	if err != nil {
		t.Fatalf("添加非直连路由失败: %v", err)
	}

	rq := NewRouteQuery(rt)

	// 查询直连路由
	dstNet1, err := network.NewNetworkFromString("192.168.1.10/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst1, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet1})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result1, err := rq.QueryRoute(*dst1, "GigabitEthernet0/2", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询直连路由失败: %v", err)
	}

	if !result1.IsConnected {
		t.Error("应该识别为直连路由")
	}

	// 查询非直连路由
	dstNet2, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst2, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet2})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result2, err := rq.QueryRoute(*dst2, "GigabitEthernet0/2", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询非直连路由失败: %v", err)
	}

	if result2.IsConnected {
		t.Error("不应该识别为直连路由")
	}
}

// TestRouteQuery_QueryAllRoutes_EmptyResult 测试空结果
func TestRouteQuery_QueryAllRoutes_EmptyResult(t *testing.T) {
	rt := model.NewRouteTable("default", network.IPv4)
	rq := NewRouteQuery(rt)

	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	results, err := rq.QueryAllRoutes(*dst, "GigabitEthernet0/1", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询所有路由失败: %v", err)
	}

	if results == nil {
		t.Fatal("结果不应该为nil")
	}

	if len(results) != 0 {
		t.Errorf("期望路由数量为0，实际为%d", len(results))
	}
}

// TestRouteQuery_QueryRoute_ComplexNetworkList 测试复杂的网络列表查询
func TestRouteQuery_QueryRoute_ComplexNetworkList(t *testing.T) {
	rt := model.NewRouteTable("default", network.IPv4)

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

	rq := NewRouteQuery(rt)

	// 查询多个目标网络
	dstNets := []string{"10.0.0.1/32", "172.16.0.1/32", "192.168.0.1/32"}
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

	result, err := rq.QueryRoute(*dst, "GigabitEthernet0/3", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if result == nil {
		t.Fatal("结果不应该为nil")
	}

	// 应该匹配到至少一个路由
	if !result.Matched {
		t.Error("应该匹配到至少一个路由")
	}
}

// TestRouteQuery_QueryRoute_AllConnected 测试所有下一跳都是直连的情况
func TestRouteQuery_QueryRoute_AllConnected(t *testing.T) {
	rt := model.NewRouteTable("default", network.IPv4)

	net, err := network.ParseIPNet("10.0.0.0/8")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop := &network.NextHop{}
	nextHop.AddHop("GigabitEthernet0/0", "192.168.1.1", true, false, nil) // connected = true
	nextHop.AddHop("GigabitEthernet0/1", "192.168.1.2", true, false, nil) // connected = true

	err = rt.AddRoute(net, nextHop)
	if err != nil {
		t.Fatalf("添加路由失败: %v", err)
	}

	rq := NewRouteQuery(rt)

	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq.QueryRoute(*dst, "GigabitEthernet0/2", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	if !result.IsConnected {
		t.Error("所有下一跳都是直连，应该识别为直连路由")
	}

	if !result.IsECMP {
		t.Error("多个下一跳应该识别为ECMP")
	}
}

// TestRouteQuery_QueryRoute_PartialConnected 测试部分直连的情况
func TestRouteQuery_QueryRoute_PartialConnected(t *testing.T) {
	rt := model.NewRouteTable("default", network.IPv4)

	net, err := network.ParseIPNet("10.0.0.0/8")
	if err != nil {
		t.Fatalf("解析网络失败: %v", err)
	}

	nextHop := &network.NextHop{}
	nextHop.AddHop("GigabitEthernet0/0", "192.168.1.1", true, false, nil)  // connected = true
	nextHop.AddHop("GigabitEthernet0/1", "192.168.1.2", false, false, nil) // connected = false

	err = rt.AddRoute(net, nextHop)
	if err != nil {
		t.Fatalf("添加路由失败: %v", err)
	}

	rq := NewRouteQuery(rt)

	dstNet, err := network.NewNetworkFromString("10.0.0.1/32")
	if err != nil {
		t.Fatalf("创建目标网络失败: %v", err)
	}
	dst, err := network.NewNetworkListFromList([]network.AbbrNet{dstNet})
	if err != nil {
		t.Fatalf("创建网络列表失败: %v", err)
	}

	result, err := rq.QueryRoute(*dst, "GigabitEthernet0/2", "default", network.IPv4)
	if err != nil {
		t.Fatalf("查询路由失败: %v", err)
	}

	// 根据实现，如果第一个下一跳是直连，则IsConnected为true
	// 这里主要测试功能是否正常
	if result == nil {
		t.Fatal("结果不应该为nil")
	}

	if len(result.NextHops) != 2 {
		t.Errorf("期望下一跳数量为2，实际为%d", len(result.NextHops))
	}

	// 验证第一个下一跳是直连的
	if !result.NextHops[0].Connected {
		t.Error("第一个下一跳应该是直连的")
	}
}
